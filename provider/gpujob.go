package main

import (
	"archive/zip"
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// GPU-1: the client brings a GPU program, the provider the GPU. Programs are JavaScript or
// TypeScript modules that use WebGPU (navigator.gpu), the same sandboxed GPU API browsers give
// web pages. They run in Deno with no permissions at all: no files, no network, no environment,
// no other programs. They read their input from standard input and write their result to standard
// output. Any kind of GPU work fits: AI (ONNX Runtime Web, WebLLM, Transformers.js and others
// run on WebGPU), image and video processing, simulations, maths. Billed per GPU-hour by the second.

var ghAPI = "https://api.github.com"

const (
	maxGPUSeconds = 3600
	maxGPUProgram = 1536 << 10
	maxGPUOutput  = 256 << 10
)

func gpuDir(parts ...string) string {
	return filepath.Join(append([]string{home(), "gpu"}, parts...)...)
}

// ---------- the Deno runtime ----------

var denoOnce struct {
	sync.Mutex
	path string
	err  error
}

// findDeno: INNERNET_DENO, deno on PATH (macOS: brew install deno), or the copy downloaded earlier.
func findDeno() string {
	if p := os.Getenv("INNERNET_DENO"); p != "" {
		return p
	}
	if p, err := exec.LookPath("deno"); err == nil {
		return p
	}
	found := ""
	_ = filepath.Walk(gpuDir("bin"), func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && (info.Name() == "deno" || info.Name() == "deno.exe") {
			found = p
		}
		return nil
	})
	return found
}

func denoAsset() string {
	return map[string]string{
		"darwin/arm64":  "deno-aarch64-apple-darwin.zip",
		"darwin/amd64":  "deno-x86_64-apple-darwin.zip",
		"linux/amd64":   "deno-x86_64-unknown-linux-gnu.zip",
		"linux/arm64":   "deno-aarch64-unknown-linux-gnu.zip",
		"windows/amd64": "deno-x86_64-pc-windows-msvc.zip",
		"windows/arm64": "deno-aarch64-pc-windows-msvc.zip",
	}[runtime.GOOS+"/"+runtime.GOARCH]
}

// installDeno downloads the latest Deno release for this machine, checked against GitHub's digest.
func installDeno() (string, error) {
	var rel struct {
		Tag    string `json:"tag_name"`
		Assets []struct {
			Name   string `json:"name"`
			URL    string `json:"browser_download_url"`
			Digest string `json:"digest"`
		} `json:"assets"`
	}
	b, err := fetch(ghAPI+"/repos/denoland/deno/releases/latest", 4<<20)
	if err != nil || json.Unmarshal(b, &rel) != nil {
		return "", fmt.Errorf("could not read the Deno release list: %v", err)
	}
	want := denoAsset()
	for _, a := range rel.Assets {
		if a.Name != want {
			continue
		}
		sum := strings.TrimPrefix(a.Digest, "sha256:")
		if len(sum) != 64 {
			return "", errors.New("GitHub gives no checksum for Deno; not installing it")
		}
		log.Printf("downloading Deno %s (%s) for GPU programs", rel.Tag, want)
		z, err := fetch(a.URL, 256<<20)
		if err != nil {
			return "", err
		}
		got := sha256.Sum256(z)
		if hex.EncodeToString(got[:]) != sum {
			return "", errors.New("Deno download does not match GitHub's checksum; not installing it")
		}
		if err := unzipTo(z, gpuDir("bin", rel.Tag)); err != nil {
			return "", err
		}
		if p := findDeno(); p != "" {
			return p, nil
		}
		return "", errors.New("deno not found in the download")
	}
	return "", fmt.Errorf("no Deno build for %s/%s; install it yourself (https://deno.com)", runtime.GOOS, runtime.GOARCH)
}

func ensureDeno() (string, error) {
	denoOnce.Lock()
	defer denoOnce.Unlock()
	if denoOnce.path != "" {
		return denoOnce.path, nil
	}
	if p := findDeno(); p != "" {
		denoOnce.path = p
		return p, nil
	}
	p, err := installDeno()
	if err == nil {
		denoOnce.path = p
	}
	return p, err
}

// ---------- running a GPU program ----------

type gpuJob struct {
	Program    string   `json:"program"`        // base64 module source, or:
	ProgramURL string   `json:"program_url"`    // https address of the module, with
	ProgramSHA string   `json:"program_sha256"` // its SHA-256; downloaded once, kept by hash
	Lang       string   `json:"lang"`           // "js" (default) or "ts"
	Input      string   `json:"input"`          // base64, given as standard input
	Args       []string `json:"args"`
	MaxSeconds int      `json:"max_seconds"`
	MaxMemMiB  int      `json:"max_memory_mib"` // JavaScript memory; GPU memory is the device's
	QueueSecs  *int     `json:"queue_seconds"`
}

// runGPUProgram runs the module in Deno with no permissions and WebGPU enabled.
func runGPUProgram(deno string, program, input []byte, lang string, args []string, memMiB int, limit time.Duration) jobResult {
	dir, err := os.MkdirTemp(gpuDir(), "job-")
	if err != nil {
		_ = os.MkdirAll(gpuDir(), 0o700)
		if dir, err = os.MkdirTemp(gpuDir(), "job-"); err != nil {
			return jobResult{Err: err.Error()}
		}
	}
	defer os.RemoveAll(dir)
	main := filepath.Join(dir, "main."+map[bool]string{true: "ts", false: "js"}[lang == "ts"])
	if err := os.WriteFile(main, program, 0o600); err != nil {
		return jobResult{Err: err.Error()}
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, deno, append([]string{"run",
		"--no-prompt", "--no-config", "--no-lock", "--no-remote", "--no-npm", "--cached-only", // nothing from the network
		"--unstable-webgpu", fmt.Sprintf("--v8-flags=--max-old-space-size=%d", memMiB),
		main}, args...)...)
	cmd.Dir = dir
	cmd.Env = []string{"DENO_DIR=" + filepath.Join(dir, "cache"), "HOME=" + dir, "NO_COLOR=1", "DENO_NO_UPDATE_CHECK=1"}
	if runtime.GOOS == "windows" {
		cmd.Env = append(cmd.Env, "SystemRoot="+os.Getenv("SystemRoot"))
	}
	var stdout, stderr limitedBuffer
	stdout.max, stderr.max = maxGPUOutput, 16<<10
	cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewReader(input), &stdout, &stderr
	start := time.Now()
	err = cmd.Run()
	res := jobResult{Output: stdout.Bytes(), Stderr: stderr.Bytes(), Seconds: time.Since(start).Seconds()}
	if cmd.ProcessState != nil {
		res.ExitCode = uint32(max(cmd.ProcessState.ExitCode(), 0))
	}
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		res.Err = fmt.Sprintf("stopped after the %s time limit", limit)
	case stdout.over:
		res.Err = fmt.Sprintf("output is larger than %d KiB", maxGPUOutput>>10)
	case err != nil && res.ExitCode == 0:
		res.Err = err.Error()
	}
	return res
}

func (s *server) gpuJobHandler(w http.ResponseWriter, client string, body []byte) {
	if !s.cfg.GPU {
		s.fail(w, 404, "this provider does not offer GPU time")
		return
	}
	var j gpuJob
	if json.Unmarshal(body, &j) != nil || (j.Program == "") == (j.ProgramURL == "") {
		s.fail(w, 400, "job needs program (base64 JavaScript/TypeScript module) or program_url with program_sha256")
		return
	}
	var program []byte
	var err1 error
	if j.ProgramURL != "" {
		if !okURL(j.ProgramURL) || !reHex64.MatchString(j.ProgramSHA) {
			s.fail(w, 400, "program_url must be https and program_sha256 64 hex")
			return
		}
		p := filepath.Join(s.data, "gpu-programs", j.ProgramSHA)
		if err := downloadVerified(j.ProgramURL, p, j.ProgramSHA, 64<<20, nil); err != nil {
			s.fail(w, 422, "program: "+err.Error())
			return
		}
		program, err1 = os.ReadFile(p)
	} else {
		program, err1 = base64.StdEncoding.DecodeString(j.Program)
	}
	input, err2 := base64.StdEncoding.DecodeString(j.Input)
	if err1 != nil || err2 != nil || len(j.Args) > 32 || (j.ProgramURL == "" && len(program) > maxGPUProgram) {
		s.fail(w, 400, "program and input must be base64; an inline program at most 1.5 MiB (larger: program_url); at most 32 args")
		return
	}
	deno, err := ensureDeno()
	if err != nil {
		s.fail(w, 503, "GPU runtime not ready: "+err.Error())
		return
	}
	if j.MaxSeconds <= 0 || j.MaxSeconds > maxGPUSeconds {
		j.MaxSeconds = 300
	}
	if j.MaxMemMiB <= 0 || j.MaxMemMiB > 8192 {
		j.MaxMemMiB = 1024
	}
	price := s.cfg.Prices["GPU-1"]
	held := micro(fmt.Sprintf("%d/3600", j.MaxSeconds), price)
	if err := s.credits.hold(client, held); err != nil {
		s.fail(w, 402, err.Error())
		return
	}
	wait := 30 * time.Second
	if j.QueueSecs != nil {
		wait = time.Duration(min(max(*j.QueueSecs, 0), 600)) * time.Second
	}
	release, err := s.sched.acquire(context.Background(), demand{Client: client, GPU: 1, MemMiB: j.MaxMemMiB + 256}, wait)
	if err != nil {
		s.credits.settle(client, held, 0)
		if errors.Is(err, errBusy) {
			w.Header().Set("Retry-After", "15")
			s.fail(w, 503, "busy ("+err.Error()+"); try again or use another provider")
		} else {
			s.fail(w, 422, err.Error())
		}
		return
	}
	res := runGPUProgram(deno, program, input, j.Lang, j.Args, j.MaxMemMiB, time.Duration(j.MaxSeconds)*time.Second)
	release()
	ms := int64(max(res.Seconds, 0.001)*1000 + 0.999)
	secs := fmt.Sprintf("%d.%03d", ms/1000, ms%1000)
	cost := micro(fmt.Sprintf("%d/3600000", ms), price)
	bal := s.credits.settle(client, held, cost)
	ph, ih, oh := sha256.Sum256(program), sha256.Sum256(input), sha256.Sum256(res.Output)
	s.stats.add("jobs", 1)
	out := map[string]any{"output": base64.StdEncoding.EncodeToString(res.Output), "exit_code": res.ExitCode,
		"stderr": string(res.Stderr), "seconds": secs,
		"receipt": s.receipt(client, "GPU-1", secs, "GPU-second", cost, bal, map[string]any{
			"program_sha256": hex.EncodeToString(ph[:]), "input_sha256": hex.EncodeToString(ih[:]),
			"output_sha256": hex.EncodeToString(oh[:]), "exit_code": res.ExitCode})}
	if res.Err != "" {
		out["error"] = res.Err
	}
	s.reply(w, 200, out)
}

// prepareGPU fetches Deno in the background when the machine offers GPU time, so the first job is quick.
func (s *server) prepareGPU() {
	if !s.cfg.GPU {
		return
	}
	go func() {
		if _, err := ensureDeno(); err != nil {
			log.Printf("GPU runtime: %v", err)
		}
	}()
}

// ---------- downloads ----------

func unzipTo(b []byte, dir string) error {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		name := filepath.Clean(f.Name)
		if strings.HasPrefix(name, "..") || filepath.IsAbs(name) {
			continue
		}
		p := filepath.Join(dir, name)
		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(p, 0o755)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(out, io.LimitReader(rc, 1<<30))
		rc.Close()
		out.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

var dlClient = &http.Client{Timeout: 0}

// downloadVerified streams url into path, checking SHA-256 and size; the file appears only if it matches.
func downloadVerified(url, path, wantSHA string, maxBytes int64, progress func(int64)) error {
	if fileSHA(path) == wantSHA {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	resp, err := dlClient.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxBytes {
		return fmt.Errorf("file is %d MiB, over the %d MiB limit", resp.ContentLength>>20, maxBytes>>20)
	}
	tmp := path + ".part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	h := sha256.New()
	var n int64
	buf := make([]byte, 1<<20)
	for {
		k, rerr := resp.Body.Read(buf)
		if k > 0 {
			n += int64(k)
			if n > maxBytes {
				f.Close()
				os.Remove(tmp)
				return fmt.Errorf("file is over the %d MiB limit", maxBytes>>20)
			}
			h.Write(buf[:k])
			if _, err := f.Write(buf[:k]); err != nil {
				f.Close()
				os.Remove(tmp)
				return err
			}
			if progress != nil {
				progress(n)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			f.Close()
			os.Remove(tmp)
			return rerr
		}
	}
	f.Close()
	if got := hex.EncodeToString(h.Sum(nil)); got != wantSHA {
		os.Remove(tmp)
		return fmt.Errorf("downloaded file does not match its SHA-256 (got %s…)", got[:12])
	}
	return os.Rename(tmp, path)
}

func fileSHA(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func randHex(n int) string {
	b := make([]byte, n/2)
	_, _ = crand.Read(b)
	return hex.EncodeToString(b)
}
