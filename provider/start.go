package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const connectDomain = "INNERnet/REG-1/provider-connect\x00"

var pollEvery = 3 * time.Second // shortened in tests

// forceVia skips the direct test ("relay" or "tunnel").
var forceVia string

// setupStep carries the numbered steps of `start` through the setup paths.
var setupStep *stepper

// cmdStart is the one-command onboarding: detect, then set up on the website or in the terminal.
func cmdStart(args []string) error {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	mode := fs.String("mode", "", "web or terminal (asked if empty)")
	yes := fs.Bool("yes", false, "terminal mode without questions (agents, scripts)")
	wallet := fs.String("wallet", "", "wallet that receives your share (terminal mode)")
	registry := fs.String("registry", defaultRegistry, "registry URL")
	port := fs.Int("port", 9443, "public port to offer")
	noOpen := fs.Bool("no-browser", false, "do not try to open the browser")
	svc := fs.Bool("service", false, "with --yes: also install the background service")
	via := fs.String("via", "", "force how clients reach this machine: relay (ST81 relay) or tunnel (HTTPS); default: try direct first")
	again := fs.Bool("again", false, "run the whole setup again on a machine that is already set up")
	network := fs.String("network", "base", "terminal mode: base (real USDC) or base-sepolia (testnet)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	reg := strings.TrimRight(orDefault(os.Getenv("INNERNET_REGISTRY"), *registry), "/")
	if ms, err := strconv.Atoi(os.Getenv("INNERNET_POLL_MS")); err == nil && ms > 0 {
		pollEvery = time.Duration(ms) * time.Millisecond
	}
	updateBeforeStart()
	if !*again && !*yes && *mode == "" && alreadySetUp() {
		return showSetUp(reg)
	}
	if _, ok := networks[*network]; !ok {
		return fmt.Errorf("--network: base or base-sepolia")
	}
	banner("provider setup", *network)
	if *network == "base-sepolia" {
		fmt.Println(dim("  Test network: no real money moves. Your key never leaves this machine."))
	} else {
		fmt.Println(dim("  Payments are real USDC on Base. Your key never leaves this machine."))
	}
	fmt.Println()
	total := 9 // 4 checks here, then 5 steps applying the website's choice
	if *yes || strings.EqualFold(*mode, "terminal") {
		total = 6
	}
	st := newStepper(total)
	st.begin("Machine key")
	priv, err := loadKey()
	if err != nil {
		if priv, err = newKey(); err != nil {
			st.fail("%v", err)
			return err
		}
		st.ok("created · provider %s…", providerID(priv)[:16])
	} else {
		st.ok("using existing · provider %s…", providerID(priv)[:16])
	}
	forceVia = *via
	f := detectSteps(reg, *port, st, !*yes)
	setupStep = st
	m := strings.ToLower(*mode)
	if *yes && m == "" {
		m = "terminal"
	}
	fmt.Println()
	if m == "" {
		m = "web" // agents and power users: --mode terminal (or --yes)
	}
	switch m {
	case "web":
		return startWeb(reg, priv, f, *noOpen)
	case "terminal":
		return startTerminal(reg, priv, f, *yes, *wallet, *svc, *network)
	}
	return errors.New("--mode must be web or terminal")
}

// ---------- website setup ----------

// alreadySetUp: settings and a signed listing exist, so `start` shows where things stand instead of
// starting over. Changes are made on the website; the background service applies them.
func alreadySetUp() bool {
	if _, err := loadConfig(); err != nil {
		return false
	}
	_, err := os.Stat(descPath())
	return err == nil
}

func showSetUp(reg string) error {
	_ = cmdStatus(nil)
	fmt.Println("  " + green(markOK) + " This machine is already set up.")
	fmt.Println()
	setupURL := strings.TrimSuffix(strings.TrimRight(reg, "/"), "/v1") + "/setup"
	fmt.Println("  Change what you offer: " + bold(setupURL) + " (sign in with your passkey).")
	if code, ok := machineCode(); ok && code != "" {
		fmt.Println("  No passkey on this device? Enter the machine code at the claim page: " + bold(code))
	}
	fmt.Println(dim("  The background service applies the change; no terminal needed. Start over: innernet-provider start --again"))
	fmt.Println()
	return nil
}

func connectRecord(priv ed25519.PrivateKey, f *facts, now int64, sealKey string) (map[string]any, error) {
	nb := make([]byte, 16)
	_, _ = rand.Read(nb)
	detected := map[string]any{"name": f.Name, "region": f.Region, "port": f.Port, "storage_free_gib": f.StorageFreeGiB,
		"cpus": f.CPUs, "memory_mib": f.MemoryMiB, "os": f.OS, "arch": f.Arch, "reachable": f.Reachable,
		"version": f.Version}
	if f.Host != "" {
		detected["host"] = f.Host
	}
	if f.Class != "" {
		detected["class"] = f.Class
	}
	if f.TZ != "" {
		detected["tz"] = f.TZ
	}
	if f.PortMap != "" {
		detected["port_map"] = f.PortMap
	}
	if f.Path != "" {
		detected["path"] = f.Path
	}
	if (!f.Reachable || f.Path == "tunnel") && f.reachNote != "" {
		detected["reach_note"] = f.reachNote
	}
	gpus := []any{}
	for _, g := range f.GPUs {
		m := map[string]any{"vendor": g.Vendor, "model": g.Model}
		if g.VRAMMiB > 0 {
			m["vram_mib"] = g.VRAMMiB
		}
		if g.Cores > 0 {
			m["cores"] = g.Cores
		}
		if g.API != "" {
			m["api"] = g.API
		}
		if g.Driver != "" {
			m["driver"] = g.Driver
		}
		gpus = append(gpus, m)
	}
	detected["gpus"] = gpus
	if sealKey != "" {
		detected["seal_key"] = sealKey
	}
	payload := map[string]any{"version": "REG-1-CONNECT", "provider": providerID(priv), "detected": detected,
		"nonce": hex.EncodeToString(nb), "issued_at": now}
	sig, err := signCanonical(priv, connectDomain, payload)
	if err != nil {
		return nil, err
	}
	return map[string]any{"payload": payload, "signature": sig}, nil
}

type webOffer struct {
	Name      string            `json:"name"`
	Region    string            `json:"region"`
	Host      string            `json:"host"`
	Port      int               `json:"port"`
	StorageGB int               `json:"storage_gib"`
	RelayGB   int               `json:"relay_gib"`
	Compute   bool              `json:"compute"`
	CPUs      int               `json:"cpus"`
	MemMiB    int               `json:"memory_mib"`
	GPU       bool              `json:"gpu"`
	GPUs      int               `json:"gpus"`
	Reserve   *int              `json:"reserve_gib"`
	Terms     string            `json:"terms"`
	Relay     *bool             `json:"relay"`
	VPN       bool              `json:"vpn"`
	VPNOK     bool              `json:"vpn_consent"`
	VPNPorts  string            `json:"vpn_ports"`
	Hours     string            `json:"hours"`
	MonthDays []int             `json:"month_days"`
	SkipDates []string          `json:"skip_dates"`
	PerClient int               `json:"per_client"`
	Prices    map[string]string `json:"prices"`
	Network   string            `json:"network"`
	Payout    string            `json:"payout"`
}

func networkKey(caip2 string) string {
	for k, v := range networks {
		if v == caip2 {
			return k
		}
	}
	return ""
}

func (o *webOffer) config(reg string) *Config {
	c := &Config{Version: "1", Name: o.Name, Region: o.Region, Host: o.Host, Port: o.Port, Network: networkKey(o.Network),
		Payout: o.Payout, Registry: reg, Storage: o.StorageGB, RelayCap: o.RelayGB, Compute: o.Compute, CPUs: o.CPUs,
		MemMiB: o.MemMiB, Prices: defaultPrices(), Hours: o.Hours, MonthDays: o.MonthDays, SkipDates: o.SkipDates,
		Created: time.Now().UTC().Format(time.RFC3339)}
	for k, v := range o.Prices {
		if _, ok := units[k]; ok && v != "" {
			c.Prices[k] = v
		}
	}
	return c
}

// stdinLines reads what the person types while the terminal waits (empty when stdin is not a terminal).
func stdinLines() <-chan string {
	ch := make(chan string, 4)
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			switch strings.ToLower(strings.TrimSpace(sc.Text())) {
			case "r":
				ch <- "retest"
			case "o":
				ch <- "outgoing"
			}
		}
	}()
	return ch
}

// sendFacts tells the website what this machine found after a new reachability test.
func sendFacts(reg, poll string, priv ed25519.PrivateKey, f *facts, box *sealBox) error {
	seal := ""
	if box != nil {
		seal = box.public()
	}
	rec, err := connectRecord(priv, f, time.Now().Unix(), seal)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(rec)
	req, _ := http.NewRequest("POST", reg+"/connect/facts", bytes.NewReader(raw))
	req.Header.Set("X-Poll-Token", poll)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("registry answered %s", resp.Status)
	}
	return nil
}

func startWeb(reg string, priv ed25519.PrivateKey, f *facts, noOpen bool) error {
	box, err := newSealBox()
	if err != nil {
		return err
	}
	var cr struct {
		Code, Poll, URL string
		ExpiresAt       int64            `json:"expires_at"`
		Passkeys        []map[string]any `json:"passkeys"`
		Resumed         bool             `json:"resumed"`
		SetupURL        string           `json:"setup_url"`
	}
	for attempt := 0; ; attempt++ {
		seal := box.public()
		if attempt > 0 {
			seal, box = "", nil // an older registry does not know the sealed backup yet
		}
		rec, err := connectRecord(priv, f, time.Now().Unix(), seal)
		if err != nil {
			return err
		}
		raw, _ := json.Marshal(rec)
		resp, err := httpClient.Post(reg+"/connect", "application/json", bytes.NewReader(raw))
		if err != nil {
			return fmt.Errorf("could not reach the registry: %v", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		resp.Body.Close()
		if resp.StatusCode == 422 && attempt == 0 && strings.Contains(string(body), "detected") {
			continue
		}
		if resp.StatusCode != 200 || json.Unmarshal(body, &cr) != nil || cr.Code == "" {
			return fmt.Errorf("registry refused to start setup (%s)", resp.Status)
		}
		break
	}
	fmt.Println()
	claimURL := strings.TrimSuffix(strings.TrimRight(reg, "/"), "/v1") + "/claim"
	if code, err := ensureMachineCode(reg, priv); err == nil {
		// The machine code is the one to remember: it stays the same until innernet-provider rekey.
		fmt.Println("  Finish on the website: open " + bold(claimURL) + " and enter your machine code:")
		fmt.Println()
		fmt.Println("    Machine code:  " + bold(code))
		fmt.Println()
		fmt.Println(dim("  It stays the same until you run innernet-provider rekey (see it again: innernet-provider code)."))
		cr.URL = claimURL
	} else {
		fmt.Println(dim("  (Machine code not available: " + err.Error() + "; using a one-time code.)"))
		fmt.Println("  Finish on the website: open this link, or go to " + claimURL + " and enter the code:")
		fmt.Println()
		fmt.Println("    " + bold(cr.URL))
		fmt.Println()
		fmt.Println("    Code:  " + bold(cr.Code))
		fmt.Println()
	}
	if cr.Resumed {
		fmt.Println("  " + green(markOK) + " You started this setup earlier. If that page is still open, finish there: " + bold(cr.SetupURL))
	}
	if n := len(cr.Passkeys); n > 0 {
		names := make([]string, n)
		for i, m := range cr.Passkeys {
			name, _ := m["name"].(string)
			names[i] = fmt.Sprintf("%s (%s)", name, passkeyWhen(m))
		}
		fmt.Printf("  Passkeys for this machine: %s\n", strings.Join(names, "; "))
	}
	fmt.Println(dim("  Everything is chosen on the website and confirmed with your passkey. This terminal asks nothing;"))
	fmt.Println(dim("  it applies your choice, then finishes on its own. Ctrl+C stops waiting."))
	fmt.Println()
	if !noOpen {
		openBrowser(cr.URL)
	}
	keys := stdinLines()
	reachMenu := func() {
		if f.Reachable {
			return
		}
		fmt.Printf("  %s Clients cannot reach port %d yet (%s). Choose on the website, or here:\n", amber(markWarn), f.Port,
			orDefault(f.reachNote, "closed"))
		fmt.Printf("    r + Enter  test again (after opening TCP port %d on your router to this machine)\n", f.Port)
		fmt.Println("    o + Enter  connect out instead: an INNERNET relay, or the HTTPS tunnel when no relay is available")
		fmt.Println()
	}
	reachMenu()
	act := func(action string) {
		switch action {
		case "retest":
			f.retestDirect(reg, func(format string, a ...any) { note(format, a...) })
		case "outgoing":
			f.Relay, f.Tunnel, f.TunnelHost, f.Path = nil, false, "", ""
			f.tryOutgoing(reg)
			if !f.Reachable {
				note("No relay and no HTTPS tunnel is available right now.")
			}
		default:
			return
		}
		if err := sendFacts(reg, cr.Poll, priv, f, box); err != nil {
			note("Could not update the website: %v", err)
		}
		fmt.Println()
		reachMenu()
	}
	st, err := waitForSetup(reg, cr.Poll, 24*time.Hour, func(string) {
		fmt.Println("  " + green(markOK) + " Signed in on the website. Waiting for you to press Apply…")
	}, func(req string) { act(req) }, keys)
	if err != nil {
		return err
	}
	fmt.Println()
	return applyWebSetup(reg, cr.Poll, priv, f, box, st, true)
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return // a server: no browser here
		}
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

// ---------- terminal setup ----------

func startTerminal(reg string, priv ed25519.PrivateKey, f *facts, yes bool, wallet string, wantService bool, network string) error {
	c := &Config{Version: "1", Registry: reg, Network: network, Port: f.Port, CPUs: 1, MemMiB: 512,
		Prices: defaultPrices()}
	if old, err := loadConfig(); err == nil {
		c = old
		c.Registry = reg
	}
	for !f.Reachable && !yes {
		fmt.Println()
		fmt.Printf("  Clients cannot reach port %d yet (%s).\n", f.Port, orDefault(f.reachNote, "closed"))
		fmt.Printf("    r  test again (after opening TCP port %d on your router to this machine)\n", f.Port)
		fmt.Println("    o  connect out instead: an INNERNET relay, or the HTTPS tunnel when no relay is available")
		fmt.Println("    q  stop here")
		switch strings.ToLower(ask("  Choose r, o or q", "r")) {
		case "o":
			f.tryOutgoing(reg)
		case "q":
			return errors.New("stopped; run innernet-provider start again when ready")
		default:
			f.retestDirect(reg, func(format string, a ...any) { note(format, a...) })
		}
	}
	f.fill(c)
	if !yes {
		askOffer(c)
		fmt.Println()
	}
	if err := c.validate(false); err != nil {
		return err
	}
	if c.Payout == "" || wallet != "" {
		if wallet == "" {
			if yes {
				return errors.New("--wallet 0x… is required with --yes (the wallet that receives your share)")
			}
			wallet = ask("Your wallet address on Base Sepolia (receives your share)", "")
		}
		split, err := findPayout(reg, wallet, !yes)
		if err != nil {
			return err
		}
		c.Payout = split
	}
	c.Created = time.Now().UTC().Format(time.RFC3339)
	fmt.Println()
	sha, err := askTerms(reg, yes)
	if err != nil {
		return err
	}
	c.TermsSHA = sha
	printOffer(c)
	if !yes && !askYes("Sign this offer and apply", true) {
		return errors.New("cancelled; your answers are saved, nothing was applied")
	}
	if err := finishSetup(c, priv); err != nil {
		return err
	}
	afterSetup(yes, wantService)
	return nil
}

// findPayout returns the payout contract for wallet, waiting while the person creates it in the browser.
func findPayout(reg, wallet string, wait bool) (string, error) {
	if !reEVM.MatchString(wallet) {
		return "", errors.New("that is not a wallet address (0x followed by 40 hex characters)")
	}
	deadline := time.Now().Add(20 * time.Minute)
	shown := false
	for {
		resp, err := httpClient.Get(reg + "/split?receiver=" + wallet)
		if err != nil {
			return "", fmt.Errorf("could not reach the registry: %v", err)
		}
		var out struct {
			Split     *string `json:"split"`
			Ready     bool    `json:"ready"`
			CreateURL string  `json:"create_url"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 8<<10)).Decode(&out)
		resp.Body.Close()
		if !out.Ready {
			return "", errors.New("payout contracts are not open yet (the split factory is not deployed); try again later")
		}
		if out.Split != nil {
			fmt.Println("Payout contract:", *out.Split)
			return *out.Split, nil
		}
		if !wait {
			return "", fmt.Errorf("no payout contract for %s yet; create it at %s and run again", wallet, out.CreateURL)
		}
		if !shown {
			fmt.Println("You do not have a payout contract yet. Create it with your wallet (one click):")
			fmt.Println("    " + out.CreateURL)
			fmt.Println("Waiting for it to appear on-chain…")
			openBrowser(out.CreateURL)
			shown = true
		}
		if time.Now().After(deadline) {
			return "", errors.New("timed out waiting for the payout contract; run again once it is created")
		}
		time.Sleep(pollEvery * 2)
	}
}

func cmdPayout(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: innernet-provider payout 0x<your wallet>  (finds or helps you create your payout contract)")
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	priv, err := loadKey()
	if err != nil {
		return err
	}
	split, err := findPayout(registryURL(c), args[0], true)
	if err != nil {
		return err
	}
	c.Payout = split
	if err := saveConfig(c); err != nil {
		return err
	}
	fmt.Println("Saved. Next: innernet-provider apply")
	return writeDetails(c, providerID(priv))
}

// ---------- shared ----------

func printOffer(c *Config) {
	rows := [][2]string{{"Name", c.Name + " (" + c.Region + ")"}, {"Address", fmt.Sprintf("%s:%d", c.Host, c.Port)},
		{"Machine", orDefault(c.Class, "unknown")}, {"Hours", describeHours(c.Hours) + " · " + orDefault(c.TZ, "UTC")}}
	if c.Storage > 0 {
		rows = append(rows, [2]string{"Storage", fmt.Sprintf("%d GiB at %s USDC per GiB-day", c.Storage, c.Prices["STO-1"])})
	}
	if c.RelayCap > 0 {
		rows = append(rows, [2]string{"Bandwidth", fmt.Sprintf("%d GiB/month (relay %s USDC per GiB)", c.RelayCap, c.Prices["RLY-1"])})
	}
	if c.Compute {
		rows = append(rows, [2]string{"CPU", fmt.Sprintf("%d CPUs, %d MiB at %s USDC per CPU-hour", c.CPUs, c.MemMiB, c.Prices["CMP-1"])})
	}
	if c.GPU {
		rows = append(rows, [2]string{"GPU", fmt.Sprintf("%d × %s at %s USDC per GPU-hour", c.GPUs, c.GPUModel, c.Prices["GPU-1"])})
	}
	if c.VPN {
		rows = append(rows, [2]string{"VPN exit", fmt.Sprintf("%s at %s USDC per GiB; you confirmed you may offer internet exit and accept the abuse policy",
			map[bool]string{true: "all ports but 25", false: "web only"}[c.VPNAllPorts], c.Prices["VPN-1"])})
	}
	rows = append(rows, [2]string{"Payout", c.Payout + " (" + c.Network + ")"})
	box("Offer to sign", rows)
	fmt.Println(dim("  Check the payout contract is the one you created: clients pay it, and it pays you."))
	fmt.Println()
}

func finishSetup(c *Config, priv ed25519.PrivateKey) error {
	if err := saveConfig(c); err != nil {
		return err
	}
	if err := writeDetails(c, providerID(priv)); err != nil {
		return err
	}
	desc, err := buildDescriptor(c, priv)
	if err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(desc, "", "  ")
	if err := os.WriteFile(descPath(), append(raw, '\n'), 0o644); err != nil {
		return err
	}
	return postApplication(c, raw)
}

func afterSetup(quiet, wantService bool) {
	st := setupStep
	if st == nil {
		st = newStepper(2)
		st.n = 0
	}
	if st.n < st.total-1 {
		st.n = st.total - 2
	}
	st.begin("Setup")
	st.ok("offer signed and sent to the registry")
	backup := filepath.Join(filepath.Dir(home()), "provider-backup.json")
	if _, err := os.Stat(backup); err != nil && !quiet {
		fmt.Println()
		if askYes("  Back up this machine's key now (encrypted with a passphrase)", true) {
			if err := cmdBackup([]string{backup}); err != nil {
				note("Backup skipped: %v", err)
			}
		} else {
			note("Later: innernet-provider backup ~/innernet-provider-backup.json")
		}
		fmt.Println()
	}
	st.n++
	st.label = "Background service"
	switch res := offerService(quiet, wantService); {
	case strings.HasPrefix(res, "ok:"):
		fmt.Printf("%s %s %s\n", st.prefix(), green(markOK), res[3:])
	case res != "":
		fmt.Printf("%s %s %s\n", st.prefix(), amber(markWarn), res)
	}
	c, _ := loadConfig()
	priv, _ := loadKey()
	rows := [][2]string{}
	if c != nil && priv != nil {
		rows = append(rows, [2]string{"Provider", providerID(priv)[:16] + "…"},
			[2]string{"Address", fmt.Sprintf("%s:%d", c.Host, c.Port)},
			[2]string{"Hours", describeHours(c.Hours)})
	}
	rows = append(rows, [2]string{"Details", detailsPath()},
		[2]string{"Dashboard", "https://innernetcorp.com/dashboard"},
		[2]string{"Next", "innernet-provider status"})
	box("You are set up", rows)
	fmt.Println(dim("  The registry checks your machine for a while, then lists it. Keep it online."))
	fmt.Println()
}
