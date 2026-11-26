package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Self-update. innernetcorp.com/registry/dl/latest names the newest published release; the program
// and SHA256SUMS come from that release (the registry forwards to the release host; provider/LATEST on
// GitHub is the fallback). The download must match its line in SHA256SUMS, or nothing changes.
// Development builds never update themselves.

const repo = "shakeelamjid/innernet-protocol"

var (
	// The network's own address forwards to the release files; GitHub is the fallback.
	latestURL       = "https://innernetcorp.com/registry/dl/latest"
	releaseURL      = "https://innernetcorp.com/registry/dl/"
	latestFallback  = "https://raw.githubusercontent.com/" + repo + "/main/provider/LATEST"
	releaseFallback = "https://github.com/" + repo + "/releases/download/"
	reTag           = regexp.MustCompile(`^provider-v(\d+)\.(\d+)\.(\d+)$`)
	reVersion       = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`)
)

func updatesOff() bool {
	return os.Getenv("INNERNET_NO_UPDATE") == "1" || !reVersion.MatchString(version)
}

// newer reports whether tag (provider-vX.Y.Z) is newer than the running version.
func newer(tag, cur string) bool {
	a, b := reTag.FindStringSubmatch(tag), reVersion.FindStringSubmatch(cur)
	if a == nil || b == nil {
		return false
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(a[i])
		y, _ := strconv.Atoi(b[i])
		if x != y {
			return x > y
		}
	}
	return false
}

func assetName() string {
	n := "innernet-provider-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		n += ".exe"
	}
	return n
}

var updateClient = &http.Client{Timeout: 120 * time.Second}

func fetch(url string, limit int64) ([]byte, error) {
	resp, err := updateClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: too large", url)
	}
	return b, nil
}

// latestTag returns the release named in LATEST, or "" if it cannot be read.
func latestTag() string {
	b, err := fetch(latestURL, 64)
	if err != nil {
		if b, err = fetch(latestFallback, 64); err != nil {
			return ""
		}
	}
	t := strings.TrimSpace(string(b))
	if !reTag.MatchString(t) {
		return ""
	}
	return t
}

// download fetches this system's program for tag and checks it against SHA256SUMS.
func download(tag string) ([]byte, error) {
	base := releaseURL
	sums, err := fetch(base+tag+"/SHA256SUMS", 16<<10)
	if err != nil {
		base = releaseFallback
		if sums, err = fetch(base+tag+"/SHA256SUMS", 16<<10); err != nil {
			return nil, fmt.Errorf("release %s is not ready yet (%v)", tag, err)
		}
	}
	want := ""
	sc := bufio.NewScanner(strings.NewReader(string(sums)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == assetName() {
			want = strings.ToLower(f[0])
		}
	}
	if len(want) != 64 {
		return nil, fmt.Errorf("release %s has no %s", tag, assetName())
	}
	bin, err := fetch(base+tag+"/"+assetName(), 64<<20)
	if err != nil {
		return nil, err
	}
	got := sha256.Sum256(bin)
	if hex.EncodeToString(got[:]) != want {
		return nil, errors.New("download does not match SHA256SUMS; nothing was changed")
	}
	return bin, nil
}

// replaceSelf swaps the running program for bin. The old file is kept as .old until the next update.
func replaceSelf(bin []byte) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if p, err := filepath.EvalSymlinks(exe); err == nil {
		exe = p
	}
	return exe, replaceFile(exe, bin)
}

func replaceFile(exe string, bin []byte) error {
	dir := filepath.Dir(exe)
	tmp, err := os.CreateTemp(dir, ".innernet-provider-new-*")
	if err != nil {
		return fmt.Errorf("cannot write next to %s: %v", exe, err)
	}
	if _, err := tmp.Write(bin); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	tmp.Close()
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	old := exe + ".old"
	_ = os.Remove(old)
	// Windows cannot overwrite a running program but can rename it; Unix can do either.
	if err := os.Rename(exe, old); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), exe); err != nil {
		_ = os.Rename(old, exe)
		os.Remove(tmp.Name())
		return err
	}
	if runtime.GOOS != "windows" {
		_ = os.Remove(old)
	}
	return nil
}

// selfUpdate installs the latest release if it is newer. It returns the new tag, or "".
func selfUpdate() (string, error) {
	if updatesOff() {
		return "", nil
	}
	tag := latestTag()
	if tag == "" || !newer(tag, version) {
		return "", nil
	}
	bin, err := download(tag)
	if err != nil {
		return "", err
	}
	if _, err := replaceSelf(bin); err != nil {
		return "", err
	}
	return tag, nil
}

// restartSelf runs the updated program with the same arguments. On Unix the process is replaced in
// place (same process id, so systemd and launchd keep tracking it); on Windows a new process starts
// and this one exits with its result.
func restartSelf() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if p, err := filepath.EvalSymlinks(exe); err == nil {
		exe = p
	}
	env := append(os.Environ(), "INNERNET_UPDATED=1")
	if runtime.GOOS != "windows" {
		err = execSelf(exe, os.Args, env)
		log.Printf("restart after update failed: %v", err)
		return
	}
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr, cmd.Env = os.Stdin, os.Stdout, os.Stderr, env
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		os.Exit(1)
	}
	os.Exit(0)
}

// updateBeforeStart is called first thing by start: a person always sets up with the newest program.
func updateBeforeStart() {
	if updatesOff() || os.Getenv("INNERNET_UPDATED") == "1" {
		return
	}
	tag := latestTag()
	if tag == "" || !newer(tag, version) {
		return
	}
	fmt.Printf("  Updating innernet-provider %s → %s…\n", version, strings.TrimPrefix(tag, "provider-v"))
	bin, err := download(tag)
	if err == nil {
		_, err = replaceSelf(bin)
	}
	if err != nil {
		fmt.Println(dim("  Update skipped: " + err.Error() + ". Continuing with " + version + "."))
		fmt.Println()
		return
	}
	fmt.Println("  " + green(markOK) + " Updated. Restarting…")
	fmt.Println()
	restartSelf()
}

// updateLoop keeps a serving machine current: it checks every 6 hours and restarts into a new release.
// Pieces, keys and settings live in ~/.innernet/provider, so a restart loses nothing.
var updateNow = make(chan struct{}, 1) // the registry relays the operator's "update now"

func updateLoop(stop func()) {
	if updatesOff() {
		return
	}
	select {
	case <-time.After(2 * time.Minute):
	case <-updateNow:
	}
	for {
		tag, err := selfUpdate()
		switch {
		case err != nil:
			log.Printf("update check: %v", err)
		case tag != "":
			log.Printf("updated to %s; restarting", tag)
			stop()
			restartSelf()
		}
		select {
		case <-time.After(6 * time.Hour):
		case <-updateNow:
		}
	}
}

func cmdUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	check := fs.Bool("check", false, "only say whether a newer release exists")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !reVersion.MatchString(version) {
		return fmt.Errorf("this is a development build (%s); install a release to update", version)
	}
	tag := latestTag()
	if tag == "" {
		return errors.New("could not read the latest release (no internet, or GitHub is unreachable)")
	}
	if !newer(tag, version) {
		fmt.Printf("innernet-provider %s is the latest release.\n", version)
		return nil
	}
	if *check {
		fmt.Printf("A newer release is available: %s (you have %s). Run: innernet-provider update\n", tag, version)
		return nil
	}
	fmt.Printf("Updating %s → %s…\n", version, strings.TrimPrefix(tag, "provider-v"))
	bin, err := download(tag)
	if err != nil {
		return err
	}
	exe, err := replaceSelf(bin)
	if err != nil {
		return err
	}
	fmt.Printf("%s Updated %s. A running background service picks it up within 6 hours, or now with:\n", green(markOK), exe)
	fmt.Println("  innernet-provider service uninstall && innernet-provider service install")
	return nil
}
