package main

// Firewall on this machine: find out whether it may block incoming connections to the
// provider port, and add one allow rule when the person agrees. Every change asks for
// the operating system's own admin approval (sudo password, macOS password, Windows UAC);
// nothing is changed silently.

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

type firewallPlan struct {
	Name    string     // what was found, e.g. "ufw", "macOS application firewall"
	Active  bool       // switched on
	Allowed bool       // already allows the port or program (when it can be known)
	Cmds    [][]string // commands that add the rule (already including sudo/elevation)
	Undo    string     // how to remove it again, shown to the person
}

var lookPath = exec.LookPath

// firewallFor inspects the local firewall for this port and program.
func firewallFor(port int, exe string) firewallPlan {
	p := strconv.Itoa(port)
	switch runtime.GOOS {
	case "darwin":
		fw := "/usr/libexec/ApplicationFirewall/socketfilterfw"
		out, err := run(fw, "--getglobalstate")
		if err != nil || !strings.Contains(strings.ToLower(out), "enabled") {
			return firewallPlan{Name: "macOS firewall"}
		}
		apps, _ := run(fw, "--listapps")
		return firewallPlan{Name: "macOS firewall", Active: true, Allowed: strings.Contains(apps, exe),
			Cmds: [][]string{{"sudo", fw, "--add", exe}, {"sudo", fw, "--unblockapp", exe}},
			Undo: "sudo " + fw + " --remove " + exe}
	case "linux":
		if _, err := lookPath("ufw"); err == nil {
			out, _ := run("ufw", "status")
			if strings.Contains(out, "Status: active") {
				return firewallPlan{Name: "ufw", Active: true, Allowed: strings.Contains(out, p+"/tcp") || strings.Contains(out, p+" "),
					Cmds: [][]string{{"sudo", "ufw", "allow", p + "/tcp"}}, Undo: "sudo ufw delete allow " + p + "/tcp"}
			}
			if strings.Contains(out, "Status: inactive") {
				return firewallPlan{Name: "ufw"}
			}
		}
		if _, err := lookPath("firewall-cmd"); err == nil {
			if out, err := run("firewall-cmd", "--state"); err == nil && strings.Contains(out, "running") {
				ports, _ := run("firewall-cmd", "--list-ports")
				return firewallPlan{Name: "firewalld", Active: true, Allowed: strings.Contains(ports, p+"/tcp"),
					Cmds: [][]string{{"sudo", "firewall-cmd", "--permanent", "--add-port=" + p + "/tcp"}, {"sudo", "firewall-cmd", "--reload"}},
					Undo: "sudo firewall-cmd --permanent --remove-port=" + p + "/tcp && sudo firewall-cmd --reload"}
			}
		}
		return firewallPlan{Name: "no firewall found"}
	case "windows":
		rule := "INNERnet Provider " + p
		out, _ := run("netsh", "advfirewall", "show", "currentprofile", "state")
		active := strings.Contains(strings.ToUpper(out), "ON")
		existing, err := run("netsh", "advfirewall", "firewall", "show", "rule", "name="+rule)
		add := fmt.Sprintf("advfirewall firewall add rule name=\"%s\" dir=in action=allow protocol=TCP localport=%s", rule, p)
		return firewallPlan{Name: "Windows Defender Firewall", Active: active, Allowed: err == nil && strings.Contains(existing, rule),
			// Start-Process -Verb RunAs shows the Windows "allow changes" prompt.
			Cmds: [][]string{{"powershell", "-NoProfile", "-Command",
				"Start-Process netsh -Verb RunAs -Wait -ArgumentList '" + strings.ReplaceAll(add, "'", "''") + "'"}},
			Undo: "netsh advfirewall firewall delete rule name=\"" + rule + "\""}
	}
	return firewallPlan{Name: "unknown"}
}

// allowThroughFirewall adds the rule after asking. Returns true when a rule was added.
func allowThroughFirewall(port int, ask bool) bool {
	if os.Getenv("INNERNET_NO_FIREWALL") == "1" {
		return false
	}
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	plan := firewallFor(port, exe)
	if !plan.Active || plan.Allowed || len(plan.Cmds) == 0 {
		return false
	}
	note("The %s may block port %d.", plan.Name, port)
	if !ask || !askYes(fmt.Sprintf("  Allow port %d through the %s? (asks for your admin password)", port, plan.Name), true) {
		note("Skipped. To allow it later: %s", strings.Join(plan.Cmds[0], " "))
		return false
	}
	for _, c := range plan.Cmds {
		cmd := exec.Command(c[0], c[1:]...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr // sudo needs the terminal
		if err := cmd.Run(); err != nil {
			note("Could not change the firewall: %v", err)
			return false
		}
	}
	note("Firewall rule added. To remove it: %s", plan.Undo)
	return true
}
