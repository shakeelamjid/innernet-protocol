package main

// Background service: keep `innernet-provider serve` running across reboots.
//
//   Linux   systemd unit (user unit for a normal user, system unit when run as root)
//   macOS   launchd agent in ~/Library/LaunchAgents
//   Windows scheduled task that starts at log-on and at boot when allowed
//
// Nothing here needs a password or a private key. The service runs the same binary
// with the same INNERNET_HOME, so it uses this machine's provider key and settings.

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	serviceName  = "innernet-provider"
	launchdLabel = "com.innernetcorp.provider"
	winTask      = "INNERnet Provider"
)

// run executes a command; replaced in tests.
var run = func(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

type serviceSpec struct {
	Exe, Home string
	Root      bool
}

func currentSpec() (serviceSpec, error) {
	exe, err := os.Executable()
	if err != nil {
		return serviceSpec{}, err
	}
	if p, err := filepath.EvalSymlinks(exe); err == nil {
		exe = p
	}
	return serviceSpec{Exe: exe, Home: home(), Root: runtime.GOOS != "windows" && os.Geteuid() == 0}, nil
}

func systemdUnit(s serviceSpec) string {
	wanted := "default.target"
	if s.Root {
		wanted = "multi-user.target"
	}
	return fmt.Sprintf(`[Unit]
Description=INNERnet provider (IRM-1): serve storage to clients
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s serve
Environment=INNERNET_HOME=%s
Restart=always
RestartSec=10
NoNewPrivileges=true

[Install]
WantedBy=%s
`, quoteSystemd(s.Exe), s.Home, wanted)
}

func quoteSystemd(p string) string {
	if strings.ContainsAny(p, " \t\"") {
		return `"` + strings.ReplaceAll(p, `"`, `\"`) + `"`
	}
	return p
}

func launchdPlist(s serviceSpec) string {
	esc := func(v string) string {
		r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
		return r.Replace(v)
	}
	log := filepath.Join(s.Home, "serve.log")
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key><array><string>%s</string><string>serve</string></array>
  <key>EnvironmentVariables</key><dict><key>INNERNET_HOME</key><string>%s</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
</dict>
</plist>
`, launchdLabel, esc(s.Exe), esc(s.Home), esc(log), esc(log))
}

func unitPath(s serviceSpec) string {
	if s.Root {
		return "/etc/systemd/system/" + serviceName + ".service"
	}
	cfg := os.Getenv("XDG_CONFIG_HOME")
	if cfg == "" {
		h, _ := os.UserHomeDir()
		cfg = filepath.Join(h, ".config")
	}
	return filepath.Join(cfg, "systemd", "user", serviceName+".service")
}

func plistPath() string {
	h, _ := os.UserHomeDir()
	return filepath.Join(h, "Library", "LaunchAgents", launchdLabel+".plist")
}

func systemctl(s serviceSpec, args ...string) (string, error) {
	if !s.Root {
		args = append([]string{"--user"}, args...)
	}
	return run("systemctl", args...)
}

func cmdService(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: innernet-provider service install|uninstall|status [--dry-run]")
	}
	fs := flag.NewFlagSet("service", flag.ContinueOnError)
	dry := fs.Bool("dry-run", false, "print what would be installed, change nothing")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "install":
		return installService(*dry)
	case "uninstall", "remove":
		return uninstallService()
	case "status":
		return serviceStatus()
	}
	return fmt.Errorf("unknown service command %q", args[0])
}

func installService(dry bool) error {
	if os.Getenv("INNERNET_NO_SERVICE") == "1" {
		fmt.Println("Background service skipped (INNERNET_NO_SERVICE=1).")
		return nil
	}
	if _, err := loadConfig(); err != nil {
		return errors.New("set this machine up first: innernet-provider start")
	}
	s, err := currentSpec()
	if err != nil {
		return err
	}
	switch runtime.GOOS {
	case "linux":
		unit, path := systemdUnit(s), unitPath(s)
		if dry {
			fmt.Printf("Would write %s:\n\n%s\n", path, unit)
			return nil
		}
		if _, err := exec.LookPath("systemctl"); err != nil {
			return errors.New("systemd not found; keep `innernet-provider serve` running with your own service manager")
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
			return err
		}
		if out, err := systemctl(s, "daemon-reload"); err != nil {
			return fmt.Errorf("systemctl daemon-reload: %v %s", err, out)
		}
		if out, err := systemctl(s, "enable", "--now", serviceName); err != nil {
			return fmt.Errorf("systemctl enable: %v %s", err, out)
		}
		if !s.Root {
			// Without lingering, a user service stops when the user logs out.
			if u := os.Getenv("USER"); u != "" {
				if _, err := run("loginctl", "enable-linger", u); err != nil {
					fmt.Println("Note: to keep serving after you log out, run: sudo loginctl enable-linger " + u)
				}
			}
		}
		fmt.Println("Installed systemd service:", path)
	case "darwin":
		plist, path := launchdPlist(s), plistPath()
		if dry {
			fmt.Printf("Would write %s:\n\n%s\n", path, plist)
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(plist), 0o644); err != nil {
			return err
		}
		domain := "gui/" + strconv.Itoa(os.Getuid())
		_, _ = run("launchctl", "bootout", domain+"/"+launchdLabel) // replace an older copy
		if out, err := run("launchctl", "bootstrap", domain, path); err != nil {
			if out2, err2 := run("launchctl", "load", "-w", path); err2 != nil {
				return fmt.Errorf("launchctl: %v %s %s", err, out, out2)
			}
		}
		fmt.Println("Installed launchd agent:", path)
		fmt.Println("It runs while you are logged in. Turn off sleep (System Settings > Battery/Energy) to stay reachable.")
	case "windows":
		tr := fmt.Sprintf(`"%s" serve`, s.Exe)
		if dry {
			fmt.Printf("Would create scheduled task %q running: %s\n", winTask, tr)
			return nil
		}
		if out, err := run("schtasks", "/Create", "/TN", winTask, "/TR", tr, "/SC", "ONLOGON", "/RL", "LIMITED", "/F"); err != nil {
			return fmt.Errorf("schtasks: %v %s", err, out)
		}
		_, _ = run("schtasks", "/Run", "/TN", winTask)
		fmt.Println("Installed scheduled task:", winTask, "(starts when you log on)")
	default:
		return fmt.Errorf("no service support for %s; run `innernet-provider serve` yourself", runtime.GOOS)
	}
	if c, err := loadConfig(); err == nil && waitHealthy(c.Port, 8*time.Second) {
		fmt.Printf("Provider service is running on port %d.\n", c.Port)
	} else {
		fmt.Println("The service is installed but did not answer yet; check: innernet-provider service status")
	}
	return nil
}

func uninstallService() error {
	s, err := currentSpec()
	if err != nil {
		return err
	}
	switch runtime.GOOS {
	case "linux":
		_, _ = systemctl(s, "disable", "--now", serviceName)
		if err := os.Remove(unitPath(s)); err != nil && !os.IsNotExist(err) {
			return err
		}
		_, _ = systemctl(s, "daemon-reload")
	case "darwin":
		_, _ = run("launchctl", "bootout", "gui/"+strconv.Itoa(os.Getuid())+"/"+launchdLabel)
		if err := os.Remove(plistPath()); err != nil && !os.IsNotExist(err) {
			return err
		}
	case "windows":
		_, _ = run("schtasks", "/End", "/TN", winTask)
		if out, err := run("schtasks", "/Delete", "/TN", winTask, "/F"); err != nil && !strings.Contains(out, "cannot find") {
			return fmt.Errorf("schtasks: %v %s", err, out)
		}
	}
	fmt.Println("Background service removed. Your key and settings are untouched.")
	return nil
}

func serviceStatus() error {
	s, err := currentSpec()
	if err != nil {
		return err
	}
	state := "unknown"
	switch runtime.GOOS {
	case "linux":
		out, _ := systemctl(s, "is-active", serviceName)
		state = out
	case "darwin":
		if _, err := run("launchctl", "print", "gui/"+strconv.Itoa(os.Getuid())+"/"+launchdLabel); err == nil {
			state = "loaded"
		} else {
			state = "not installed"
		}
	case "windows":
		if out, err := run("schtasks", "/Query", "/TN", winTask); err == nil {
			state = "installed"
			if strings.Contains(out, "Running") {
				state = "running"
			}
		} else {
			state = "not installed"
		}
	}
	fmt.Println("Service:", state)
	if c, err := loadConfig(); err == nil {
		if waitHealthy(c.Port, time.Second) {
			fmt.Printf("Answering on port %d: yes\n", c.Port)
		} else {
			fmt.Printf("Answering on port %d: no\n", c.Port)
		}
	}
	return nil
}

func waitHealthy(port int, within time.Duration) bool {
	url := fmt.Sprintf("http://127.0.0.1:%d/healthz", port)
	client := &http.Client{Timeout: time.Second}
	for end := time.Now().Add(within); ; {
		if r, err := client.Get(url); err == nil {
			r.Body.Close()
			if r.StatusCode == 200 {
				return true
			}
		}
		if time.Now().After(end) {
			return false
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// offerService is called at the end of setup. It returns "ok:<text>" when the service
// runs, otherwise a short explanation ("" when switched off for tests).
func offerService(quiet, want bool) string {
	if os.Getenv("INNERNET_NO_SERVICE") == "1" {
		return ""
	}
	if quiet && !want {
		return "not installed · run: innernet-provider service install"
	}
	if !quiet && !askYes("  Keep serving in the background, also after a restart (recommended)", true) {
		return "skipped · later: innernet-provider service install"
	}
	if err := installService(false); err != nil {
		return "not installed (" + err.Error() + ") · run innernet-provider serve yourself"
	}
	if c, err := loadConfig(); err == nil && waitHealthy(c.Port, 2*time.Second) {
		return fmt.Sprintf("ok:running on port %d, starts with this computer", c.Port)
	}
	return "installed, not answering yet · check: innernet-provider service status"
}

// cmdUninstall removes the background service and the program. The key and settings
// stay unless --all is given, because the key is this provider's identity.
func cmdUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	all := fs.Bool("all", false, "also delete this machine's provider key, settings and stored pieces")
	if err := fs.Parse(args); err != nil {
		return err
	}
	banner("uninstall", "base-sepolia")
	if _, err := loadConfig(); err == nil {
		_ = uninstallService()
	}
	if *all {
		fmt.Println(amber("  This deletes the provider key and every stored piece. Clients will repair their files elsewhere,"))
		fmt.Println(amber("  but this machine's listing and earnings history cannot be taken over by a new key."))
		if !askYes("  Delete "+home(), false) {
			return errors.New("cancelled")
		}
		if err := os.RemoveAll(home()); err != nil {
			return err
		}
		fmt.Printf("  %s Deleted %s\n", green(markOK), home())
	} else {
		fmt.Printf("  %s Kept your key and settings in %s (use --all to delete them)\n", green(markOK), home())
	}
	exe, err := os.Executable()
	if err == nil {
		if runtime.GOOS == "windows" {
			fmt.Println("  Delete the program file yourself: " + exe)
		} else if err := os.Remove(exe); err == nil {
			fmt.Printf("  %s Removed %s\n", green(markOK), exe)
		}
	}
	fmt.Println(dim("  A firewall rule added during setup stays; remove it with your firewall settings if you want."))
	return nil
}
