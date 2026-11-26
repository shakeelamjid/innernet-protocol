package main

// Setup chosen on the website, applied here without questions.
//
// The person chooses everything on the website, including the key backup passphrase and whether the
// machine keeps serving after a restart, then confirms with their passkey. The machine receives
// exactly what the passkey signed, checks that signature itself against the passkeys it trusts,
// signs the offer with its own key, and reports each step back so the website shows it live.

import (
	"bytes"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
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
	"time"
)

const setupDomain = "INNERnet/REG-1/setup-offer\x00"

// webSetup is what the passkey signed (REG-1-SETUP).
type webSetup struct {
	Version  string   `json:"version"`
	Provider string   `json:"provider"`
	Offer    webOffer `json:"offer"`
	Service  bool     `json:"service"`
	Backup   *sealed  `json:"backup"`
	Escrow   bool     `json:"escrow"` // also keep the encrypted backup with the registry (recovery by passphrase)
	Nonce    string   `json:"nonce"`
	Issued   int64    `json:"issued_at"`
}

type setupStatus struct {
	Status string          `json:"status"`
	Offer  *webOffer       `json:"offer"`
	Setup  json.RawMessage `json:"setup"`
	Auth   *passkeyAuth    `json:"auth"`
	// Request: the person asked on the website to test the port again ("retest") or connect out ("outgoing").
	Request string `json:"request"`
}

// waitForSetup polls until the website submitted a passkey-confirmed setup.
func waitForSetup(reg, poll string, max time.Duration, say func(string), onRequest func(string), keys <-chan string) (*setupStatus, error) {
	deadline := time.Now().Add(max)
	last := ""
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("GET", reg+"/connect/status", nil)
		req.Header.Set("X-Poll-Token", poll)
		resp, err := httpClient.Do(req)
		if err == nil {
			var st setupStatus
			_ = json.NewDecoder(io.LimitReader(resp.Body, 128<<10)).Decode(&st)
			resp.Body.Close()
			if resp.StatusCode == http.StatusNotFound {
				return nil, errors.New("this setup was replaced by a newer one")
			}
			if st.Status != last {
				switch st.Status {
				case "claimed":
					say("claimed")
				case "expired", "superseded", "done":
					return nil, fmt.Errorf("the setup on the website %s; run innernet-provider start again", map[string]string{
						"expired": "expired", "superseded": "was replaced by a newer one", "done": "already finished"}[st.Status])
				}
				last = st.Status
			}
			if st.Request != "" && onRequest != nil {
				onRequest(st.Request) // the website asked: test the port again, or connect out
				continue
			}
			if st.Status == "submitted" {
				if len(st.Setup) == 0 || st.Auth == nil {
					return nil, errors.New("the registry sent an offer without your passkey confirmation; nothing was applied")
				}
				return &st, nil
			}
		}
		select {
		case k := <-keys:
			if onRequest != nil {
				onRequest(k)
			}
		case <-time.After(pollEvery):
		}
	}
	return nil, errors.New("timed out waiting for the website; run innernet-provider start again")
}

// verifySetup checks the passkey confirmation and returns what it confirmed. trustNew: the person is
// at this machine (its terminal is open), so a passkey this machine has not seen before is accepted
// and remembered; otherwise only remembered passkeys count.
func verifySetup(st *setupStatus, priv ed25519.PrivateKey, box *sealBox, trustNew bool) (*webSetup, error) {
	canon, err := canonicalRaw(st.Setup)
	if err != nil {
		return nil, fmt.Errorf("setup is malformed: %v", err)
	}
	sum := sha256.Sum256(append([]byte(setupDomain), canon...))
	key, err := func() (*coseKey, error) {
		raw, err := unb64u(st.Auth.PublicKey)
		if err != nil {
			return nil, err
		}
		return parseCOSE(raw)
	}()
	if err != nil {
		return nil, fmt.Errorf("passkey key: %v", err)
	}
	trusted := loadTrustedPasskeys()
	known := trusted[st.Auth.CredID] == st.Auth.PublicKey
	if !known && !trustNew && len(trusted) > 0 {
		return nil, errors.New("confirmed with a passkey this machine does not know; confirm with one it knows, " +
			"or run innernet-provider start on the machine")
	}
	if err := verifyAssertion(st.Auth, key, sum[:]); err != nil {
		return nil, err
	}
	var ws webSetup
	dec := json.NewDecoder(bytes.NewReader(st.Setup))
	if err := dec.Decode(&ws); err != nil {
		return nil, fmt.Errorf("setup is malformed: %v", err)
	}
	if ws.Version != "REG-1-SETUP" || ws.Provider != providerID(priv) {
		return nil, errors.New("this setup is for another machine")
	}
	if d := time.Since(time.Unix(ws.Issued, 0)); d > 2*time.Hour || d < -10*time.Minute {
		return nil, errors.New("this setup is too old; press Apply again on the website")
	}
	if usedSetupNonce(ws.Nonce) {
		return nil, errors.New("this setup was already applied")
	}
	if ws.Backup != nil && (box == nil || ws.Backup.To != box.public()) {
		return nil, errors.New("the backup passphrase was sealed to a different machine key; nothing was applied")
	}
	if !known {
		if err := trustPasskey(st.Auth.CredID, st.Auth.PublicKey); err != nil {
			return nil, err
		}
	}
	return &ws, nil
}

// canonicalRaw re-encodes JSON canonically, exactly as the registry hashed it.
func canonicalRaw(raw json.RawMessage) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeCanonical(tree, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func setupNoncesPath() string { return filepath.Join(home(), "setup-nonces.json") }

func usedSetupNonce(n string) bool {
	var seen []string
	if raw, err := os.ReadFile(setupNoncesPath()); err == nil {
		_ = json.Unmarshal(raw, &seen)
	}
	for _, s := range seen {
		if s == n {
			return true
		}
	}
	return false
}

func rememberSetupNonce(n string) {
	var seen []string
	if raw, err := os.ReadFile(setupNoncesPath()); err == nil {
		_ = json.Unmarshal(raw, &seen)
	}
	seen = append(seen, n)
	if len(seen) > 50 {
		seen = seen[len(seen)-50:]
	}
	raw, _ := json.Marshal(seen)
	_ = os.WriteFile(setupNoncesPath(), raw, 0o600)
}

// progress reports steps to the website (and prints them when a terminal is open).
type progress struct {
	reg, poll string
	steps     []map[string]string
	st        *stepper
}

func (p *progress) set(id, label, state, text string) {
	for _, s := range p.steps {
		if s["id"] == id {
			s["state"], s["text"] = state, text
			p.send("/connect/progress")
			p.print(label, state, text)
			return
		}
	}
	p.steps = append(p.steps, map[string]string{"id": id, "label": label, "state": state, "text": text})
	p.send("/connect/progress")
	p.print(label, state, text)
}

func (p *progress) print(label, state, text string) {
	if state == "run" {
		return
	}
	if p.st == nil {
		log.Printf("setup: %s: %s %s", label, state, text)
		return
	}
	p.st.n++
	p.st.label = label
	mark := map[string]string{"ok": green(markOK), "warn": amber(markWarn), "fail": red(markFail), "skip": dim("–")}[state]
	fmt.Printf("%s %s %s\n", p.st.prefix(), mark, text)
}

func (p *progress) send(path string) {
	raw, _ := json.Marshal(map[string]any{"steps": p.steps})
	req, _ := http.NewRequest("POST", p.reg+path, bytes.NewReader(raw))
	req.Header.Set("X-Poll-Token", p.poll)
	req.Header.Set("Content-Type", "application/json")
	if r, err := httpClient.Do(req); err == nil {
		r.Body.Close()
	}
}

// applyWebSetup verifies, signs and applies a setup from the website, then backs up the key and
// installs the background service if the person asked for it. terminal: a person is at the machine.
func applyWebSetup(reg, poll string, priv ed25519.PrivateKey, f *facts, box *sealBox, st *setupStatus, terminal bool) error {
	var stp *stepper
	if terminal {
		stp = setupStep
		if stp == nil {
			stp = newStepper(8)
		}
		stp.total = stp.n + 5
	}
	p := &progress{reg: reg, poll: poll, st: stp}
	fail := func(id, label string, err error) error {
		p.set(id, label, "fail", err.Error())
		p.send("/connect/finish")
		return err
	}
	ws, err := verifySetup(st, priv, box, terminal)
	if err != nil {
		return fail("check", "Passkey", err)
	}
	p.set("check", "Passkey", "ok", "your passkey confirmed this exact offer")
	c, err := ws.Offer.toConfig(reg, f)
	if err != nil {
		return fail("sign", "Offer", fmt.Errorf("the offer is not valid: %v", err))
	}
	if old, err := loadConfig(); err == nil && !terminal {
		c.Created = old.Created
	}
	quietApply = true
	err = finishSetup(c, priv)
	quietApply = false
	if err != nil {
		return fail("sign", "Offer", err)
	}
	rememberSetupNonce(ws.Nonce)
	p.set("sign", "Offer", "ok", "signed with this machine's key and sent to the registry: "+offerSummary(c))
	switch {
	case ws.Backup == nil:
		p.set("backup", "Key backup", "skip", "not requested · later: innernet-provider backup FILE")
	default:
		pass, err := box.open(ws.Backup)
		if err == nil {
			path := backupPath()
			if err = writeBackup(priv, path, pass); err == nil {
				where := "saved on this machine: " + path
				if ws.Escrow {
					if raw, rerr := os.ReadFile(path); rerr == nil && uploadBackup(reg, priv, raw) == nil {
						where += "; an encrypted copy is kept with INNERnet for \"Forgot your key?\""
					} else {
						where += "; keeping a copy with INNERnet failed (run innernet-provider backup again later)"
					}
				}
				p.set("backup", "Key backup", "ok", "encrypted with your passphrase, "+where)
				break
			}
		}
		p.set("backup", "Key backup", "warn", "not written ("+err.Error()+") · run: innernet-provider backup FILE")
	}
	if terminal {
		switch res := serviceFromWeb(ws.Service); {
		case strings.HasPrefix(res, "ok:"):
			p.set("service", "Background service", "ok", res[3:])
		case strings.HasPrefix(res, "skip:"):
			p.set("service", "Background service", "skip", res[5:])
		default:
			p.set("service", "Background service", "warn", res)
		}
	} else {
		p.set("service", "Background service", "ok", "restarting with the new settings")
	}
	p.set("registry", "Registry", "run", "checking your machine; it is listed once the checks pass")
	p.send("/connect/finish")
	if terminal {
		p.st.n++
		p.st.label = "Registry"
		fmt.Printf("%s %s checking your machine; follow it on the website or with: innernet-provider status\n",
			p.st.prefix(), green(markOK))
		fmt.Println()
		fmt.Println("  " + green(markOK) + " Setup finished. You can close this terminal; the website shows the rest.")
		fmt.Println()
	}
	return nil
}

func backupPath() string {
	p := filepath.Join(filepath.Dir(home()), "provider-backup.json")
	if _, err := os.Stat(p); err == nil {
		p = filepath.Join(filepath.Dir(home()), "provider-backup-"+time.Now().UTC().Format("20060102-150405")+".json")
	}
	return p
}

func serviceFromWeb(want bool) string {
	if os.Getenv("INNERNET_NO_SERVICE") == "1" {
		return "skip:not installed here (INNERNET_NO_SERVICE)"
	}
	if !want {
		return "skip:not requested · run innernet-provider serve, or: innernet-provider service install"
	}
	if err := installService(false); err != nil {
		return "not installed (" + err.Error() + ") · run innernet-provider serve yourself"
	}
	if c, err := loadConfig(); err == nil && waitHealthy(c.Port, 3*time.Second) {
		if note := lingerMissing(); note != "" {
			return fmt.Sprintf("running on port %d, but %s", c.Port, note)
		}
		return fmt.Sprintf("ok:running on port %d, starts with this computer", c.Port)
	}
	return "installed, not answering yet · check: innernet-provider service status"
}

func offerSummary(c *Config) string {
	var parts []string
	if c.Storage > 0 {
		parts = append(parts, fmt.Sprintf("storage %d GiB", c.Storage))
	}
	if c.Compute {
		parts = append(parts, fmt.Sprintf("CPU %d", c.CPUs))
	}
	if c.GPU {
		parts = append(parts, fmt.Sprintf("GPU %d × %s", c.GPUs, c.GPUModel))
	}
	if c.RelayCap > 0 && !c.NoRelay {
		parts = append(parts, "relay")
	}
	if c.VPN {
		parts = append(parts, "VPN exit")
	}
	parts = append(parts, "payout "+c.Payout)
	return strings.Join(parts, " · ")
}

// toConfig turns the website's offer into this machine's settings. Hardware facts (GPU model,
// reachability) come from this machine's own detection, never from the website.
func (o *webOffer) toConfig(reg string, f *facts) (*Config, error) {
	c := o.config(reg)
	if o.GPU {
		if err := c.setGPU(f.GPUs, o.GPUs); err != nil {
			return nil, err
		}
	}
	if o.Port == f.Port {
		c.PortMap = f.PortMap
	}
	c.Relay, c.Tunnel, c.TunnelHost, c.Class, c.TZ = f.Relay, f.Tunnel, f.TunnelHost, f.Class, f.TZ
	if o.Reserve != nil && *o.Reserve >= 0 {
		c.ReserveMiB = *o.Reserve << 10
		if c.ReserveMiB == 0 {
			c.ReserveMiB = 1 // "keep nothing" (0 would mean the default)
		}
	}
	c.PerClient = o.PerClient
	c.TermsSHA = o.Terms // agreed on the website, inside what the passkey signed
	if o.Relay != nil {
		c.NoRelay = !*o.Relay
	}
	if o.VPN && o.VPNOK {
		if f.Tunnel {
			return nil, errors.New("VPN exit needs clients to reach this machine directly or through a relay, not the HTTPS tunnel")
		}
		c.VPN, c.VPNAllPorts, c.VPNConsent = true, o.VPNPorts == "all", time.Now().UTC().Format(time.RFC3339)
	}
	return c, c.validate(true)
}

// ---------- the background service picks up changes made on the website ----------

// factsFromConfig describes a running machine without the reachability tests (it is serving).
func factsFromConfig(c *Config) *facts {
	f := &facts{Name: c.Name, Region: c.Region, Host: c.Host, Port: c.Port, CPUs: runtime.NumCPU(), OS: runtime.GOOS, Arch: runtime.GOARCH,
		Version: version, PortMap: c.PortMap, Class: c.Class, TZ: c.TZ, Relay: c.Relay, Tunnel: c.Tunnel,
		TunnelHost: c.TunnelHost, Reachable: true}
	f.StorageFreeGiB = freeDiskGiB(home())
	f.MemoryMiB = totalMemoryMiB()
	f.GPUs = detectGPUs()
	switch {
	case c.Tunnel:
		f.Path = "tunnel"
	case c.Relay != nil:
		f.Path = "relay"
	case c.PortMap != "":
		f.Path = "router"
	default:
		f.Path = "direct"
	}
	return f
}

// setupWatch runs inside serve: when the owner opens the setup page, join it, wait for their
// passkey-confirmed choice, apply it and restart with the new settings.
func (s *server) setupWatch(reg string, restart func()) {
	every := 10 * time.Second
	if pollEvery < time.Second {
		every = pollEvery
	}
	pid := providerID(s.priv)
	for {
		time.Sleep(every)
		resp, err := httpClient.Get(reg + "/providers/" + pid + "/setup-pending")
		if err != nil {
			continue
		}
		var out struct{ Pending bool }
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&out)
		resp.Body.Close()
		if !out.Pending {
			continue
		}
		if err := s.joinWebSetup(reg); err != nil {
			log.Printf("website setup: %v", err)
			continue
		}
		restart()
		return
	}
}

func (s *server) joinWebSetup(reg string) error {
	got, err := signedIntent(reg, s.priv, "setup-fetch", "")
	if err != nil {
		return err
	}
	poll, _ := got["poll"].(string)
	if poll == "" {
		return errors.New("registry sent no setup token")
	}
	f := factsFromConfig(s.cfg)
	box, err := newSealBox()
	if err != nil {
		return err
	}
	rec, err := connectRecord(s.priv, f, time.Now().Unix(), box.public())
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(rec)
	req, _ := http.NewRequest("POST", reg+"/connect/attach", bytes.NewReader(raw))
	req.Header.Set("X-Poll-Token", poll)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("registry refused to join the setup (%s)", resp.Status)
	}
	log.Printf("website setup: joined; waiting for the owner to apply")
	st, err := waitForSetup(reg, poll, 2*time.Hour, func(string) {}, nil, nil)
	if err != nil {
		return err
	}
	return applyWebSetup(reg, poll, s.priv, f, box, st, false)
}

// lingerMissing: on Linux a user service stops at logout and does not start at boot unless
// "lingering" is on for that user. Returns what to run, or "".
func lingerMissing() string {
	if runtime.GOOS != "linux" || os.Geteuid() == 0 {
		return ""
	}
	u := os.Getenv("USER")
	if u == "" {
		return ""
	}
	out, err := exec.Command("loginctl", "show-user", u, "-p", "Linger").Output()
	if err != nil || strings.TrimSpace(string(out)) != "Linger=no" {
		return ""
	}
	return "it stops when you log out and does not start after a reboot. Run once: sudo loginctl enable-linger " + u
}

// uploadBackup keeps the encrypted backup file with the registry, signed by this machine. The registry
// cannot open it; the owner's browser opens it with the passphrase on the recovery page.
func uploadBackup(reg string, priv ed25519.PrivateKey, raw []byte) error {
	blob := strings.TrimSpace(string(raw))
	sum := sha256.Sum256([]byte(blob))
	nb := make([]byte, 16)
	_, _ = cryptorand.Read(nb)
	payload := map[string]any{"version": "REG-1-INTENT", "provider": providerID(priv), "action": "backup-store",
		"target": hex.EncodeToString(sum[:]), "nonce": hex.EncodeToString(nb), "issued_at": time.Now().Unix()}
	sig, err := signCanonical(priv, intentDomain, payload)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{"intent": map[string]any{"payload": payload, "signature": sig}, "backup": blob})
	resp, err := httpClient.Post(strings.TrimRight(reg, "/")+"/providers/"+providerID(priv)+"/backup", "application/json",
		bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("registry answered %s", resp.Status)
	}
	return nil
}
