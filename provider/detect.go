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
	PortMap        string `json:"port_map,omitempty"`
	Class          string `json:"class,omitempty"`
	Path           string `json:"path,omitempty"`
	Relay          *relayTarget
	Tunnel         bool
	TunnelHost     string
	TZ             string `json:"tz,omitempty"`
	reachChecked   bool
	reachNote      string
}

// detect gathers machine facts. The public address and reachability need the registry;
// everything else is local. With a stepper it reports each finding as a numbered step;
// interactive allows asking before changing the firewall.
func detect(registry string, port int, verbose bool) *facts {
	var st *stepper
	if verbose {
		st = newStepper(3)
	}
	return detectSteps(registry, port, st, verbose)
}

func detectSteps(registry string, port int, st *stepper, interactive bool) *facts {
	hostname, _ := os.Hostname()
	f := &facts{Name: sanitize(hostname), Region: regionFromTimezone(), Port: port, CPUs: runtime.NumCPU(),
		OS: runtime.GOOS, Arch: runtime.GOARCH, Version: version, TZ: localTZ()}
	if st != nil {
		st.begin("This machine")
	}
	f.StorageFreeGiB = freeDiskGiB(home())
	f.MemoryMiB = totalMemoryMiB()
	if st != nil {
		st.ok("%s %s · %d CPU · %s memory · %s free", osName(f.OS), f.Arch, f.CPUs, mib(f.MemoryMiB), gib(f.StorageFreeGiB))
		st.begin("Internet address")
	}
	ip, err := whoami(registry)
	if err != nil {
		f.Class = machineClass("")
		if st != nil {
			st.fail("unknown (%v)", err)
		}
		return f
	}
	f.Host = ip
	f.Class = machineClass(ip)
	if st != nil {
		st.ok("%s · %s", ip, f.Class)
		st.begin("Reachable")
	}
	if forceVia != "" {
		f.reachChecked = true
		f.forceOutgoing(registry, forceVia)
		if st != nil {
			if f.Reachable {
				st.ok("through %s (chosen with --via)", f.Path)
			} else {
				st.fail("could not set up %s", forceVia)
			}
		}
		return f
	}
	f.Reachable, f.reachNote = reachable(registry, port)
	f.reachChecked = true
	if f.Reachable {
		f.Path = "direct"
		if st != nil {
			st.ok("port %d is reachable from the internet", port)
		}
		return f
	}
	if st != nil {
		st.warn("port %d is not reachable yet (%s)", port, f.reachNote)
	}
	// 1) this machine's firewall, 2) the router.
	if allowThroughFirewall(port, interactive) {
		if f.Reachable, f.reachNote = reachable(registry, port); f.Reachable {
			f.Path = "direct"
			note("Reachable now.")
			return f
		}
	}
	f.tryRouter(registry, port, func(format string, a ...any) { note(format, a...) })
	if !f.Reachable {
		f.tryOutgoing(registry)
	}
	if !f.Reachable {
		note("You can finish setup now; the registry keeps checking and lists you once reachable.")
	}
	return f
}

func osName(goos string) string {
	if n, ok := map[string]string{"darwin": "macOS", "linux": "Linux", "windows": "Windows"}[goos]; ok {
		return n
	}
	return goos
}

func (f *facts) forceOutgoing(registry, via string) {
	priv, err := loadKey()
	if err != nil {
		return
	}
	switch via {
	case "relay":
		if r, err := tryRelays(registry, priv); err == nil {
			f.Relay, f.Reachable, f.Path = r, true, "relay"
		} else {
			note("Relay: %v.", err)
		}
	case "tunnel":
		if nc, err := fetchNetConfig(registry); err == nil && nc.Tunnel.Endpoint.Host != "" {
			f.Tunnel, f.TunnelHost, f.Reachable, f.Path = true, nc.Tunnel.Endpoint.Host, true, "tunnel"
		}
	}
}

// tryOutgoing uses an outgoing connection instead: an INNERnet relay over ST81, or the
// HTTPS tunnel when only web traffic gets out. Works behind any router or ISP.
func (f *facts) tryOutgoing(registry string) {
	if os.Getenv("INNERNET_NO_RELAY") == "1" {
		return
	}
	priv, err := loadKey()
	if err != nil {
		return
	}
	note("Trying an INNERnet relay (this machine connects out; clients reach it through the relay)…")
	if r, err := tryRelays(registry, priv); err == nil {
		f.Relay, f.Reachable, f.Path = r, true, "relay"
		note("Reachable through relay %s over ST81. Data stays encrypted end to end.", r.Addr)
		return
	} else {
		note("Relay: %v.", err)
	}
	if nc, err := fetchNetConfig(registry); err == nil && nc.Tunnel.Endpoint.Host != "" {
		f.Tunnel, f.TunnelHost, f.Reachable, f.Path = true, nc.Tunnel.Endpoint.Host, true, "tunnel"
		note("Using the HTTPS tunnel through %s (works where only web traffic gets out).", nc.Tunnel.Endpoint.Host)
	}
}

// tryRouter asks the home router to forward the port, then tests again from outside.
func (f *facts) tryRouter(registry string, port int, say func(string, ...any)) {
	if os.Getenv("INNERNET_NO_PORTMAP") == "1" {
		return
	}
	say("Asking your router to open port %d…", port)
	m, err := openPort(port)
	if err != nil {
		say("The router did not open it automatically (%s).", err)
		say("Open TCP port %d on your router to this machine, or use a server with a public IP.", port)
		return
	}
	say("Router opened port %d (%s).", port, map[string]string{"natpmp": "NAT-PMP", "upnp": "UPnP"}[m.Method])
	if m.ExternalIP != "" && sharedAddress(m.ExternalIP) {
		say("But its internet address %s is shared by your internet provider (carrier-grade NAT),", m.ExternalIP)
		say("so opening ports cannot make this machine reachable. Ask your provider for a public IP,")
		say("use a server with a public IP, or use relay mode when it ships.")
		return
	}
	f.Reachable, f.reachNote = reachable(registry, port)
	if f.Reachable {
		f.PortMap, f.Path = m.Method, "router"
		say("Port %d is reachable from the internet now.", port)
	} else {
		say("Port %d is still not reachable (%s).", port, f.reachNote)
	}
}

func (f *facts) fill(c *Config) {
	if f.PortMap != "" {
		c.PortMap = f.PortMap
	}
	if c.Class == "" {
		c.Class = f.Class
	}
	c.Relay, c.Tunnel, c.TunnelHost = f.Relay, f.Tunnel, f.TunnelHost
	if c.TZ == "" {
		c.TZ = f.TZ
	}
	if c.Hours == "" {
		c.Hours = "always"
		if f.Class == "laptop" {
			c.Hours = "daily 09:00-23:00"
		}
	}
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
	nb := make([]byte, 16)
	_, _ = rand.Read(nb)
	nonce := hex.EncodeToString(nb)
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		// Our own provider service may already hold the port; it answers /reach/<nonce>.
		if !waitHealthy(port, time.Second) {
			return false, "port is in use by another program on this machine"
		}
	} else {
		defer ln.Close()
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
	}
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
