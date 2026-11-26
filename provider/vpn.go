package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// VPN-1: internet exit, part of Bandwidth. A client opens an ST81 session to this provider (direct,
// or end to end through a relay) and asks for a TCP connection to host:port; the provider connects
// and carries the bytes both ways, sealed inside ST81 between the client and this machine. Billed per
// GiB from the client's credit, as the traffic flows. Off unless the owner switched it on and gave the
// VPN consent in setup. Destinations inside private networks are always refused, so a client can
// never reach the owner's own network, router or cloud metadata services.

const vpnChunk = 64 << 10

// blockedPrefixes are never reachable through the exit.
var blockedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "64:ff9b:1::/48"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func exitAllowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	if os.Getenv("INNERNET_TEST_HTTP") == "1" && ip.IsLoopback() {
		return true // tests only
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return ip.IsValid()
}

func (c *Config) vpnPortAllowed(port int) bool {
	if port < 1 || port > 65535 || port == 25 { // never mail: exits must not send spam
		return false
	}
	if c.VPNAllPorts {
		return true
	}
	return port == 80 || port == 443
}

// bandwidthMeter counts relay and VPN bytes against the owner's monthly cap.
type bandwidthMeter struct {
	mu    sync.Mutex
	path  string
	Month string `json:"month"`
	Bytes int64  `json:"bytes"`
}

func openMeter(dir string) *bandwidthMeter {
	m := &bandwidthMeter{path: filepath.Join(dir, "bandwidth.json")}
	if raw, err := os.ReadFile(m.path); err == nil {
		_ = json.Unmarshal(raw, m)
	}
	return m
}

// add records n bytes; it reports false once this month's cap (GiB) is used up.
func (m *bandwidthMeter) add(n int64, capGiB int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	month := time.Now().UTC().Format("2006-01")
	if m.Month != month {
		m.Month, m.Bytes = month, 0
	}
	m.Bytes += n
	if raw, err := json.Marshal(m); err == nil {
		_ = os.WriteFile(m.path, raw, 0o600)
	}
	return capGiB <= 0 || m.Bytes <= int64(capGiB)<<30
}

func (m *bandwidthMeter) left(capGiB int) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Month != time.Now().UTC().Format("2006-01") {
		return int64(capGiB) << 30
	}
	return max(0, int64(capGiB)<<30-m.Bytes)
}

// used is this month's relayed and VPN traffic, in bytes.
func (m *bandwidthMeter) used() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Month != time.Now().UTC().Format("2006-01") {
		return 0
	}
	return m.Bytes
}

var vpnDial = func(ctx context.Context, ip netip.Addr, port int) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	return d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
}

// serveVPN handles one exit connection on an ST81 session whose first frame asked for it.
func (s *server) serveVPN(sess *st81Session, h map[string]any) {
	client := fmt.Sprintf("%x", sess.Peer)
	fail := func(msg string) { _ = sess.Write(map[string]any{"ok": false, "error": msg}, nil) }
	if !s.cfg.VPN || s.cfg.VPNConsent == "" {
		fail("this provider does not offer VPN exit")
		return
	}
	terms, _ := h["terms"].(string)
	if err := s.checkClientTerms(terms); err != nil {
		fail(err.Error())
		return
	}
	host, _ := h["host"].(string)
	port64, _ := intField(h, "port")
	port := int(port64)
	if host == "" || len(host) > 253 || !s.cfg.vpnPortAllowed(port) {
		fail("this exit allows ports " + map[bool]string{true: "1-65535 except 25", false: "80 and 443"}[s.cfg.VPNAllPorts])
		return
	}
	if s.meter.left(s.cfg.RelayCap) <= 0 {
		fail("this provider's bandwidth for the month is used up")
		return
	}
	perMiB := micro("1/1024", s.cfg.Prices["VPN-1"]) // price is per GiB
	if s.credits.balance(client) < max(perMiB, 1) {
		fail("add credit on this provider first")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	cancel()
	if err != nil || len(addrs) == 0 {
		fail("could not resolve " + host)
		return
	}
	var target netip.Addr
	for _, a := range addrs {
		if exitAllowed(a) {
			target = a
			break
		}
	}
	if !target.IsValid() {
		fail("destination is inside a private network")
		return
	}
	conn, err := vpnDial(context.Background(), target, port)
	if err != nil {
		fail("could not connect: " + err.Error())
		return
	}
	defer conn.Close()
	if err := sess.Write(map[string]any{"ok": true}, nil); err != nil {
		return
	}
	s.stats.add("vpn_connections", 1)
	var mu sync.Mutex // one writer on the session at a time
	var total, unbilled int64
	var cost int64
	stop := make(chan struct{})
	var once sync.Once
	end := func() { once.Do(func() { close(stop); conn.Close() }) }
	// account bills each full MiB as it passes and stops when credit or the monthly cap runs out
	account := func(n int) bool {
		mu.Lock()
		defer mu.Unlock()
		total += int64(n)
		unbilled += int64(n)
		okCap := s.meter.add(int64(n), s.cfg.RelayCap)
		for unbilled >= 1<<20 {
			if err := s.credits.hold(client, perMiB); err != nil {
				return false
			}
			cost += perMiB
			unbilled -= 1 << 20
		}
		return okCap
	}
	downDone := make(chan struct{})
	go func() { // internet -> client
		defer close(downDone)
		buf := make([]byte, vpnChunk)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if !account(n) {
					break
				}
				mu.Lock()
				werr := sess.Write(map[string]any{"op": "data"}, buf[:n])
				mu.Unlock()
				if werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		end()
	}()
	mainDone := make(chan struct{})
	go func() { // once the destination is done, wake the reader below so the receipt can be sent
		<-stop
		for {
			_ = sess.conn.SetReadDeadline(time.Now())
			select {
			case <-mainDone:
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}()
	sess.Timeout = 10 * time.Minute
	for { // client -> internet
		h, body, err := sess.Read()
		if err != nil || h["op"] != "data" {
			break
		}
		if !account(len(body)) {
			break
		}
		if _, err := conn.Write(body); err != nil {
			break
		}
	}
	end()
	close(mainDone)
	<-downDone // no more data frames after this point
	// The last part of a MiB is charged too, so every byte is paid for.
	mu.Lock()
	if unbilled > 0 && s.credits.hold(client, max(1, micro(fmt.Sprintf("%d/%d", unbilled, int64(1)<<30), s.cfg.Prices["VPN-1"]))) == nil {
		cost += max(1, micro(fmt.Sprintf("%d/%d", unbilled, int64(1)<<30), s.cfg.Prices["VPN-1"]))
	}
	gib := fmt.Sprintf("%d/%d", total, int64(1)<<30)
	mu.Unlock()
	_ = sess.Write(map[string]any{"op": "close", "bytes": total,
		"receipt": s.receipt(client, "VPN-1", ratDecimal(gib), "GiB", cost, s.credits.balance(client), map[string]any{"bytes": total})}, nil)
}

// ratDecimal writes a fraction as a decimal with 6 places, for receipts.
func ratDecimal(frac string) string {
	var a, b int64
	if _, err := fmt.Sscanf(frac, "%d/%d", &a, &b); err != nil || b == 0 {
		return "0"
	}
	whole, rest := a/b, a%b
	return fmt.Sprintf("%d.%06d", whole, rest*1_000_000/b)
}
