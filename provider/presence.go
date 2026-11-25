package main

// Live presence: while `serve` runs it tells the registry, about once a minute, where
// this machine can be reached right now (it follows network changes on its own) and
// a few usage counters. The record is signed with the provider key, so the registry
// can pass it to clients but cannot change it.
//
// Also the intents a provider sends from the terminal: pause, resume, leave, reinstate.

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const (
	presenceDomain = "INNERnet/REG-1/provider-presence\x00"
	intentDomain   = "INNERnet/REG-1/provider-intent\x00"
)

// counters keeps 24 hourly buckets per name, so "last 24 h" needs no history file.
type counters struct {
	mu   sync.Mutex
	hour int64
	b    map[string]*[24]int64
}

func (c *counters) add(name string, n int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.roll(time.Now().Unix() / 3600)
	if c.b == nil {
		c.b = map[string]*[24]int64{}
	}
	if c.b[name] == nil {
		c.b[name] = &[24]int64{}
	}
	c.b[name][c.hour%24] += n
}

func (c *counters) roll(h int64) {
	if c.hour == 0 {
		c.hour = h
		return
	}
	for ; c.hour < h; c.hour++ {
		for _, arr := range c.b {
			arr[(c.hour+1)%24] = 0
		}
	}
}

func (c *counters) last24h(name string) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.roll(time.Now().Unix() / 3600)
	var t int64
	if arr := c.b[name]; arr != nil {
		for _, v := range arr {
			t += v
		}
	}
	return t
}

func (s *server) leases() int64 {
	entries, err := os.ReadDir(s.data)
	if err != nil {
		return 0
	}
	n := int64(0)
	for _, e := range entries {
		if e.IsDir() {
			n++
		}
	}
	return n
}

func presenceFile() string { return filepath.Join(home(), "presence.json") }

type presenceState struct {
	At        int64  `json:"at"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Path      string `json:"path"`
	State     string `json:"state"`
	Reachable bool   `json:"reachable"`
	Error     string `json:"error,omitempty"`
}

func (s *server) presenceLoop(registry string) {
	every := time.Minute
	if sec, err := strconv.Atoi(os.Getenv("INNERNET_PRESENCE_SEC")); err == nil && sec > 0 {
		every = time.Duration(sec) * time.Second
	}
	time.Sleep(time.Second) // let the listener start first
	lastHost := s.cfg.Host
	for {
		st := s.sendPresence(registry, &lastHost)
		raw, _ := json.Marshal(st)
		_ = os.WriteFile(presenceFile(), raw, 0o600)
		time.Sleep(every)
	}
}

func (s *server) sendPresence(registry string, lastHost *string) presenceState {
	now := time.Now()
	st := presenceState{At: now.Unix(), Port: s.cfg.Port, Path: "direct"}
	host, err := whoami(registry)
	if err != nil {
		st.Error = "registry not reachable: " + err.Error()
		return st
	}
	if host != *lastHost {
		log.Printf("network changed: public address %s -> %s", *lastHost, host)
		*lastHost = host
		if s.cfg.PortMap != "" {
			if _, err := openPort(s.cfg.Port); err != nil {
				log.Printf("router port mapping after network change: %v", err)
			}
		}
	}
	if s.cfg.PortMap != "" {
		st.Path = "router"
	}
	st.Host = host
	payload := map[string]any{
		"version": "REG-1-PRESENCE", "provider": providerID(s.priv),
		"endpoint": map[string]any{"host": host, "port": s.cfg.Port}, "path": st.Path,
		"seq": now.UnixMilli(), "issued_at": now.Unix(), "software": "innernet-provider/" + version,
		"stats": map[string]any{
			"stored_bytes": s.usedBytes(), "storage_limit_bytes": int64(s.cfg.Storage) << 30, "leases": s.leases(),
			"requests_24h": s.stats.last24h("requests"), "served_bytes_24h": s.stats.last24h("served"),
			"challenges_24h": s.stats.last24h("challenges"), "payments_24h": s.stats.last24h("payments"),
			"uptime_s": int64(now.Sub(s.started).Seconds()),
		},
	}
	sig, err := signCanonical(s.priv, presenceDomain, payload)
	if err != nil {
		st.Error = err.Error()
		return st
	}
	raw, _ := json.Marshal(map[string]any{"payload": payload, "signature": sig})
	resp, err := httpClient.Post(registry+"/presence", "application/json", bytes.NewReader(raw))
	if err != nil {
		st.Error = "registry not reachable: " + err.Error()
		return st
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	var out struct {
		State     string `json:"state"`
		Reachable bool   `json:"reachable"`
		Detail    string `json:"detail"`
	}
	_ = json.Unmarshal(body, &out)
	if resp.StatusCode != 200 {
		st.Error = fmt.Sprintf("registry refused presence (%s): %s", resp.Status, out.Detail)
		return st
	}
	st.State, st.Reachable = out.State, out.Reachable
	return st
}

// ---------- intents ----------

func cmdIntent(action string) error {
	c, err := loadConfig()
	if err != nil {
		return err
	}
	priv, err := loadKey()
	if err != nil {
		return err
	}
	nb := make([]byte, 16)
	_, _ = rand.Read(nb)
	payload := map[string]any{"version": "REG-1-INTENT", "provider": providerID(priv), "action": action,
		"nonce": hex.EncodeToString(nb), "issued_at": time.Now().Unix()}
	sig, err := signCanonical(priv, intentDomain, payload)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(map[string]any{"payload": payload, "signature": sig})
	resp, err := httpClient.Post(registryURL(c)+"/providers/"+providerID(priv)+"/intent", "application/json", bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("could not reach the registry: %v", err)
	}
	defer resp.Body.Close()
	var out struct {
		State, Reason, Detail string
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 8<<10)).Decode(&out)
	if resp.StatusCode != 200 {
		return errors.New(orDefault(out.Detail, resp.Status))
	}
	fmt.Printf(" %s %s\n", green(markOK), bold(stateLabel(out.State)))
	if out.Reason != "" {
		fmt.Println("   " + dim(out.Reason))
	}
	return nil
}

func stateLabel(s string) string {
	if l, ok := map[string]string{"testing": "Checking (not listed yet)", "listed": "Listed", "paused": "Paused",
		"leaving": "Leaving", "suspended": "Suspended", "gone": "Gone (not heard from)", "removed": "Removed"}[s]; ok {
		return l
	}
	return s
}
