package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// facts is what the machine can find out about itself. Nothing here is secret.
type facts struct {
	Name           string `json:"name,omitempty"`
	Region         string `json:"region,omitempty"`
	Host           string `json:"host,omitempty"`
	Port           int    `json:"port"`
	StorageFreeGiB int    `json:"storage_free_gib"`
	CPUs           int    `json:"cpus"`
	MemoryMiB      int    `json:"memory_mib"`
	OS             string `json:"os"`
	Arch           string `json:"arch"`
	Reachable      bool   `json:"reachable"`
	Version        string `json:"version"`
	reachChecked   bool
	reachNote      string
}

// detect gathers machine facts. The public address and reachability need the registry;
// everything else is local. verbose prints a line per finding.
func detect(registry string, port int, verbose bool) *facts {
	hostname, _ := os.Hostname()
	f := &facts{Name: sanitize(hostname), Region: regionFromTimezone(), Port: port, CPUs: runtime.NumCPU(),
		OS: runtime.GOOS, Arch: runtime.GOARCH, Version: version}
	f.StorageFreeGiB = freeDiskGiB(home())
	f.MemoryMiB = totalMemoryMiB()
	say := func(format string, a ...any) {
		if verbose {
			fmt.Printf("  "+format+"\n", a...)
		}
	}
	if verbose {
		fmt.Println("Checking this machine…")
	}
	say("System       %s/%s, %d CPUs, %s memory, %s free disk", f.OS, f.Arch, f.CPUs, mib(f.MemoryMiB), gib(f.StorageFreeGiB))
	if ip, err := whoami(registry); err == nil {
		f.Host = ip
		say("Public IP    %s", ip)
		f.Reachable, f.reachNote = reachable(registry, port)
		f.reachChecked = true
		if f.Reachable {
			say("Port %d     reachable from the internet", port)
		} else {
			say("Port %d     NOT reachable from the internet (%s)", port, f.reachNote)
		}
	} else {
		say("Public IP    unknown (%v)", err)
	}
	return f
}

func (f *facts) fill(c *Config) {
	if c.Name == "" {
		c.Name = f.Name
	}
	if c.Region == "" {
		c.Region = f.Region
	}
	if c.Host == "" {
		c.Host = f.Host
	}
	if c.Storage == 0 && f.StorageFreeGiB > 1 {
		c.Storage = min(200, f.StorageFreeGiB/2)
	}
	if c.CPUs <= 1 && f.CPUs > 1 {
		c.CPUs = min(4, f.CPUs-1)
	}
}

func mib(v int) string {
	if v <= 0 {
		return "unknown"
	}
	return fmt.Sprintf("%.1f GiB", float64(v)/1024)
}

func gib(v int) string {
	if v <= 0 {
		return "unknown"
	}
	return strconv.Itoa(v) + " GiB"
}

func whoami(registry string) (string, error) {
	resp, err := httpClient.Get(registry + "/whoami")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		IP string `json:"ip"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&out) != nil || net.ParseIP(out.IP) == nil {
		return "", fmt.Errorf("registry reply %s", resp.Status)
	}
	return out.IP, nil
}

// reachable listens on the port, asks the registry to connect back, and checks the
// registry saw our random nonce, so it really reached this machine.
func reachable(registry string, port int) (bool, string) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false, "port is in use on this machine, so it could not be tested"
	}
	defer ln.Close()
	nb := make([]byte, 16)
	_, _ = rand.Read(nb)
	nonce := hex.EncodeToString(nb)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = conn.Write([]byte(nonce))
			conn.Close()
		}
	}()
	body, _ := json.Marshal(map[string]any{"port": port, "nonce": nonce})
	resp, err := httpClient.Post(registry+"/reachability", "application/json", bytes.NewReader(body))
	if err != nil {
		return false, "could not ask the registry"
	}
	defer resp.Body.Close()
	var out struct {
		Reachable bool `json:"reachable"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&out) != nil {
		return false, "registry reply " + resp.Status
	}
	if !out.Reachable {
		return false, "open this TCP port in your firewall or router"
	}
	return true, ""
}

// regionFromTimezone maps the machine's IANA time zone to a coarse region label.
func regionFromTimezone() string {
	tz := os.Getenv("TZ")
	if tz == "" {
		if target, err := os.Readlink("/etc/localtime"); err == nil {
			if i := strings.Index(target, "zoneinfo/"); i >= 0 {
				tz = target[i+len("zoneinfo/"):]
			}
		}
	}
	return regionFor(tz)
}

func regionFor(tz string) string {
	table := []struct{ prefix, region string }{
		{"Asia/Karachi", "asia-south"}, {"Asia/Kolkata", "asia-south"}, {"Asia/Calcutta", "asia-south"},
		{"Asia/Dhaka", "asia-south"}, {"Asia/Colombo", "asia-south"}, {"Asia/Kathmandu", "asia-south"},
		{"Asia/Dubai", "middle-east"}, {"Asia/Riyadh", "middle-east"}, {"Asia/Qatar", "middle-east"},
		{"Asia/Bahrain", "middle-east"}, {"Asia/Kuwait", "middle-east"}, {"Asia/Muscat", "middle-east"},
		{"Asia/Tehran", "middle-east"}, {"Asia/Baghdad", "middle-east"}, {"Asia/Jerusalem", "middle-east"},
		{"Asia/Singapore", "asia-southeast"}, {"Asia/Jakarta", "asia-southeast"}, {"Asia/Bangkok", "asia-southeast"},
		{"Asia/Kuala_Lumpur", "asia-southeast"}, {"Asia/Manila", "asia-southeast"}, {"Asia/Ho_Chi_Minh", "asia-southeast"},
		{"Asia/Tokyo", "asia-east"}, {"Asia/Seoul", "asia-east"}, {"Asia/Shanghai", "asia-east"},
		{"Asia/Hong_Kong", "asia-east"}, {"Asia/Taipei", "asia-east"},
		{"Europe/London", "eu-west"}, {"Europe/Dublin", "eu-west"}, {"Europe/Lisbon", "eu-west"},
		{"Europe/Moscow", "eu-east"}, {"Europe/Kyiv", "eu-east"}, {"Europe/Istanbul", "eu-east"},
		{"Europe/", "eu-central"},
		{"America/New_York", "us-east"}, {"America/Toronto", "us-east"}, {"America/Chicago", "us-central"},
		{"America/Denver", "us-west"}, {"America/Los_Angeles", "us-west"}, {"America/Vancouver", "us-west"},
		{"America/Sao_Paulo", "sa-east"}, {"America/", "americas"},
		{"Africa/", "africa"}, {"Australia/", "oceania"}, {"Pacific/Auckland", "oceania"},
	}
	for _, e := range table {
		if strings.HasPrefix(tz, e.prefix) {
			return e.region
		}
	}
	return "global"
}
