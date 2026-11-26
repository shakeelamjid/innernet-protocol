// innernet-provider: register this machine's spare storage, bandwidth or
// compute with the INNERnet resource market (IRM-1 DRAFT, testnet first).
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var version = "0.3.0-draft" // set at build time with -ldflags "-X main.version=..."

const defaultRegistry = "https://innernetcorp.com/registry/v1"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "start":
		err = cmdStart(args)
	case "init":
		err = cmdInit(args)
	case "payout":
		err = cmdPayout(args)
	case "show":
		err = cmdShow()
	case "wallet":
		err = cmdWallet(args)
	case "apply":
		err = cmdApply(args)
	case "status":
		err = cmdStatus(args)
	case "serve":
		err = cmdServe(args)
	case "service":
		err = cmdService(args)
	case "passkeys":
		err = cmdPasskeys(args)
	case "relay":
		err = cmdRelay(args)
	case "update":
		err = cmdUpdate(args)
	case "terms":
		err = cmdTerms(args)
	case "st81-echo", "st81-ping":
		err = cmdST81Debug(cmd, args)
	case "uninstall":
		err = cmdUninstall(args)
	case "pause", "resume", "leave", "reinstate":
		err = cmdIntent(cmd)
	case "login":
		err = cmdLogin(args)
	case "backup":
		err = cmdBackup(args)
	case "restore":
		err = cmdRestore(args)
	case "version", "--version", "-v":
		fmt.Println("innernet-provider", version, runtime.GOOS+"/"+runtime.GOARCH)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`innernet-provider ` + version + ` - rent out storage, bandwidth or compute on INNERnet (IRM-1 draft, testnet)

Setup
  start                one-command setup: checks this machine, then set up on the website or here
  init                 step-by-step setup in the terminal: what you offer, prices
  payout 0x...         find (or open the page to create) the payout contract for your wallet
  wallet set 0x...     set your payout split contract address
  show                 print your provider details (safe to share)
  backup FILE          write a passphrase-encrypted backup of your identity key
  restore FILE         restore your identity key on this machine

Run
  serve                serve clients: store encrypted pieces, answer storage checks, issue payment receipts
  service install      keep serving in the background, also after a restart (systemd, launchd, Task Scheduler)
  service status       is the background service running and answering
  service uninstall    remove the background service

Registry
  pause                stop taking new files (what you hold is still served and paid)
  resume               take new files again, or cancel leaving
  leave                clients move their files away, then you can stop
  reinstate            after a suspension or a long absence: start a 24 h trial to be listed again
  apply [--dry-run]    send your signed provider form to the registry
  status [--watch]     one screen: listing, service, online, address, hours, uptime, earnings
  login                get a one-time link to the web dashboard (add a passkey there)
  passkeys [remove N]  list the passkeys that open your dashboard; remove a lost one
  terms [accept]       show the provider and client terms; agree to the current provider terms

Other
  update [--check]     install the newest release (start and serve also update by themselves;
                       INNERNET_NO_UPDATE=1 turns that off)
  uninstall [--all]    remove the background service and this program (--all: also the key)
  version, help

Files live in ~/.innernet/provider (override with INNERNET_HOME).
`)
}

// ---------------- prompts ----------------

var stdin = bufio.NewReader(os.Stdin)

func ask(question, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", question, def)
	} else {
		fmt.Printf("%s: ", question)
	}
	line, _ := stdin.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func askInt(question string, def int) int {
	for {
		v, err := strconv.Atoi(ask(question, strconv.Itoa(def)))
		if err == nil && v >= 0 {
			return v
		}
		fmt.Println("  please enter a whole number (0 or more)")
	}
}

func askYes(question string, def bool) bool {
	d := "n"
	if def {
		d = "y"
	}
	return strings.HasPrefix(strings.ToLower(ask(question+" (y/n)", d)), "y")
}

func readPassphrase(prompt string) (string, error) {
	if p := os.Getenv("INNERNET_BACKUP_PASSPHRASE"); p != "" {
		return p, nil
	}
	fmt.Print(prompt)
	if runtime.GOOS != "windows" {
		off := exec.Command("stty", "-echo")
		off.Stdin = os.Stdin
		if off.Run() == nil {
			defer func() {
				on := exec.Command("stty", "echo")
				on.Stdin = os.Stdin
				_ = on.Run()
				fmt.Println()
			}()
		}
	}
	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		return "", errors.New("no passphrase entered")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// ---------------- commands ----------------

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "non-interactive: take every value from flags")
	c := &Config{Version: "1", Registry: defaultRegistry, Network: "base-sepolia", Port: 9443,
		CPUs: 1, MemMiB: 512, Prices: defaultPrices()}
	fs.StringVar(&c.Name, "name", "", "provider name")
	fs.StringVar(&c.Region, "region", "", "region label, e.g. asia-south")
	fs.StringVar(&c.Host, "host", "", "public DNS name or IP")
	fs.IntVar(&c.Port, "port", c.Port, "public port")
	fs.StringVar(&c.Network, "network", c.Network, "base-sepolia or base")
	fs.StringVar(&c.Registry, "registry", c.Registry, "registry URL")
	fs.IntVar(&c.Storage, "storage-gib", 0, "storage to offer in GiB (0 = none)")
	fs.IntVar(&c.RelayCap, "relay-gib", 0, "relay bandwidth per month in GiB (0 = none)")
	fs.BoolVar(&c.Compute, "compute", false, "offer CPU jobs (sandboxed WebAssembly)")
	fs.IntVar(&c.CPUs, "cpus", c.CPUs, "max CPUs for compute jobs")
	fs.IntVar(&c.MemMiB, "memory-mib", c.MemMiB, "max memory for compute jobs")
	ps, pr, pc := fs.String("price-storage", c.Prices["STO-1"], "USDC per GiB-day"),
		fs.String("price-relay", c.Prices["RLY-1"], "USDC per GiB"),
		fs.String("price-compute", c.Prices["CMP-1"], "USDC per CPU-hour")
	gpuN := fs.Int("gpus", 0, "GPUs to offer (0 = none); the model is detected")
	acceptTerms := fs.Bool("accept-terms", false, "agree to the current provider terms (read them first: innernet-provider terms)")
	reserveGiB := fs.Int("reserve-gib", -1, "memory compute never uses, kept for you (default 4, servers 1)")
	fs.IntVar(&c.PerClient, "per-client", 2, "CPU jobs and GPU sessions one client may run at once")
	pg := fs.String("price-gpu", c.Prices["GPU-1"], "USDC per GPU-hour")
	force := fs.Bool("force", false, "overwrite an existing config (the identity key is kept)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := os.Stat(configPath()); err == nil && !*force {
		return errors.New("already set up here; use --force to redo the setup (your key is kept)")
	}
	c.Prices = map[string]string{"STO-1": *ps, "RLY-1": *pr, "CMP-1": *pc, "GPU-1": *pg}
	if *acceptTerms {
		if docs, err := fetchTerms(registryURL(c)); err == nil {
			c.TermsSHA = docs["provider"].SHA256
		} else {
			return fmt.Errorf("could not read the provider terms: %v", err)
		}
	}
	if *reserveGiB >= 0 {
		c.ReserveMiB = max(1, *reserveGiB<<10)
	}
	if *gpuN > 0 {
		if err := c.setGPU(detectGPUs(), *gpuN); err != nil {
			return err
		}
	}

	if !*yes || c.Host == "" || c.Name == "" || c.Region == "" {
		d := detect(registryURL(c), c.Port, !*yes)
		d.fill(c)
	}
	if !*yes {
		fmt.Println("INNERnet provider setup. Press Enter to accept the value in [brackets].")
		fmt.Println("This runs on TESTNET (Base Sepolia). No real money moves yet.")
		fmt.Println()
		askOffer(c)
	}
	if err := c.validate(false); err != nil {
		return err
	}
	priv, err := loadKey()
	if err != nil {
		if priv, err = newKey(); err != nil {
			return err
		}
		fmt.Println("Created a new identity key:", keyPath())
	}
	c.Created = time.Now().UTC().Format(time.RFC3339)
	if err := saveConfig(c); err != nil {
		return err
	}
	if err := writeDetails(c, providerID(priv)); err != nil {
		return err
	}
	fmt.Println()
	fmt.Println("Setup saved.")
	fmt.Println("  Provider id:", providerID(priv))
	fmt.Println("  Details:    ", detailsPath())
	fmt.Println()
	fmt.Println("Next: innernet-provider backup ~/innernet-provider-backup.json")
	return nil
}

func orDefault(v, d string) string {
	if v != "" {
		return v
	}
	return d
}

func orInt(v, d int) int {
	if v != 0 {
		return v
	}
	return d
}

var unsafeName = regexp.MustCompile(`[^a-z0-9._-]+`)

func sanitize(s string) string {
	s = unsafeName.ReplaceAllString(strings.ToLower(s), "-")
	s = strings.Trim(s, "-._")
	if s == "" {
		return "provider"
	}
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

func cmdShow() error {
	raw, err := os.ReadFile(detailsPath())
	if err != nil {
		return errors.New("nothing set up here yet; run: innernet-provider init")
	}
	fmt.Print(string(raw))
	return nil
}

func cmdWallet(args []string) error {
	if len(args) != 2 || args[0] != "set" {
		return errors.New("usage: innernet-provider wallet set 0x<payout split contract>")
	}
	if !reEVM.MatchString(args[1]) {
		return errors.New("that is not an EVM address (0x followed by 40 hex characters)")
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	priv, err := loadKey()
	if err != nil {
		return err
	}
	c.Payout = args[1]
	if err := saveConfig(c); err != nil {
		return err
	}
	fmt.Println("Payout contract set to", c.Payout, "on", c.Network)
	fmt.Println("The registry will check that this contract is locked and sends the 2.5% network fee automatically.")
	return writeDetails(c, providerID(priv))
}

func registryURL(c *Config) string {
	if r := os.Getenv("INNERNET_REGISTRY"); r != "" {
		return strings.TrimRight(r, "/")
	}
	return strings.TrimRight(c.Registry, "/")
}

func buildDescriptor(c *Config, priv ed25519.PrivateKey) (map[string]any, error) {
	if err := c.validate(true); err != nil {
		return nil, err
	}
	payload := map[string]any{"version": "REG-1-DESCRIPTOR", "provider": c.descriptorEntry(providerID(priv))}
	sig, err := signCanonical(priv, descriptorDomain, payload)
	if err != nil {
		return nil, err
	}
	return map[string]any{"payload": payload, "signature": sig}, nil
}

var httpClient = &http.Client{Timeout: 20 * time.Second}

func cmdApply(args []string) error {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	dry := fs.Bool("dry-run", false, "only write descriptor.json, do not send it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	priv, err := loadKey()
	if err != nil {
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
	fmt.Println("Signed provider form written to", descPath())
	if *dry {
		return nil
	}
	return postApplication(c, raw)
}

func postApplication(c *Config, raw []byte) error {
	resp, err := httpClient.Post(registryURL(c)+"/apply", "application/json", bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("could not reach the registry (%v); the signed form is saved, try again later", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode == http.StatusNotFound {
		return errors.New("the registry is not accepting applications yet; your signed form is saved")
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("registry refused the application (%s): %s", resp.Status, strings.TrimSpace(string(body)))
	}
	fmt.Println("Application received. The registry now checks your machine; follow it with: innernet-provider status")
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	watch := fs.Bool("watch", false, "refresh every 5 seconds (Ctrl+C to stop)")
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	priv, err := loadKey()
	if err != nil {
		return err
	}
	for {
		v := gatherStatus(c, providerID(priv))
		if *asJSON {
			raw, _ := json.MarshalIndent(v, "", "  ")
			fmt.Println(string(raw))
			return nil
		}
		if *watch && isTTY {
			fmt.Print("\x1b[H\x1b[2J")
		}
		renderStatus(c, v)
		if !*watch {
			return nil
		}
		fmt.Println(dim("  Refreshing every 5 s · Ctrl+C to stop"))
		time.Sleep(5 * time.Second)
	}
}

type statusView struct {
	Provider  string         `json:"provider"`
	Registry  *statusReply   `json:"registry,omitempty"`
	RegError  string         `json:"registry_error,omitempty"`
	Service   bool           `json:"service_answering"`
	Presence  *presenceState `json:"presence,omitempty"`
	Stats     map[string]any `json:"stats,omitempty"`
	CheckedAt int64          `json:"checked_at"`
}

func gatherStatus(c *Config, id string) statusView {
	v := statusView{Provider: id, CheckedAt: time.Now().Unix(), Service: waitHealthy(c.Port, 600*time.Millisecond)}
	if resp, err := httpClient.Get(registryURL(c) + "/providers/" + id + "/status"); err != nil {
		v.RegError = "registry not reachable"
	} else {
		if resp.StatusCode == http.StatusNotFound {
			v.RegError = "not applied yet"
		} else {
			var s statusReply
			if json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&s) == nil {
				v.Registry = &s
			}
		}
		resp.Body.Close()
	}
	if raw, err := os.ReadFile(presenceFile()); err == nil {
		var p presenceState
		if json.Unmarshal(raw, &p) == nil {
			v.Presence = &p
		}
	}
	return v
}

func renderStatus(c *Config, v statusView) {
	banner("provider status", c.Network)
	state, reason := "unknown", v.RegError
	if v.Registry != nil {
		state, reason = v.Registry.State, v.Registry.Reason
	}
	mark := map[string]string{"listed": green(markOK), "testing": amber(markWait), "paused": amber(markWait),
		"leaving": amber(markWait)}[state]
	if mark == "" {
		mark = red(markFail)
	}
	rows := [][2]string{{"Listing", mark + " " + stateLabel(state)}}
	if reason != "" {
		rows = append(rows, [2]string{"", dim(reason)})
	}
	svc := red(markFail) + " not running · innernet-provider service install"
	if v.Service {
		svc = green(markOK) + fmt.Sprintf(" running on port %d", c.Port)
	}
	rows = append(rows, [2]string{"Service", svc})
	if p := v.Presence; p != nil && p.At > 0 {
		ago := time.Since(time.Unix(p.At, 0)).Round(time.Second)
		if p.Error != "" {
			rows = append(rows, [2]string{"Online", red(markFail) + " " + p.Error})
		} else {
			reach := green(markOK) + " reachable"
			if !p.Reachable {
				reach = amber(markWarn) + " not reachable from the internet"
			}
			rows = append(rows, [2]string{"Online", fmt.Sprintf("%s last check-in %s ago", green(markOK), ago)},
				[2]string{"Address", fmt.Sprintf("%s:%d via %s · %s", p.Host, p.Port, p.Path, reach)})
		}
	} else {
		rows = append(rows, [2]string{"Online", dim("no check-in yet (the service sends one every minute)")})
	}
	rows = append(rows, [2]string{"Hours", describeHours(c.Hours) + " · " + orDefault(c.TZ, "UTC")})
	if r := v.Registry; r != nil {
		if r.Health != nil {
			rows = append(rows, [2]string{"Uptime 7 d", r.Health.Uptime7d})
		}
		if r.Earnings != nil {
			rows = append(rows, [2]string{"Earned 30 d", fmt.Sprintf("%s %s to you (%s paid, %s fee)",
				r.Earnings.Net, r.Earnings.Asset, r.Earnings.Gross, r.Earnings.Fee)})
		}
	}
	box("Provider "+v.Provider[:16]+"…", rows)
	switch state {
	case "paused":
		fmt.Println(dim("  Take new files again: innernet-provider resume"))
	case "leaving":
		fmt.Println(dim("  Changed your mind: innernet-provider resume"))
	case "suspended", "gone":
		fmt.Println(dim("  Back to normal: innernet-provider reinstate (24 h trial)"))
	}
	fmt.Println(dim("  Usage, earnings and payments in detail: https://innernetcorp.com/dashboard"))
	fmt.Println()
}

// loginRecord signs a registry-issued challenge. The registry verifies it and
// returns a one-time link where the provider can add a passkey for the web dashboard.
func loginRecord(priv ed25519.PrivateKey, challenge, registryHost string, expires int64) (map[string]any, error) {
	if b, err := hex.DecodeString(challenge); err != nil || len(b) != 32 {
		return nil, errors.New("registry sent an invalid login challenge")
	}
	payload := map[string]any{"version": "REG-1-LOGIN", "provider": providerID(priv), "challenge": challenge,
		"registry": registryHost, "expires_at": expires}
	sig, err := signCanonical(priv, loginDomain, payload)
	if err != nil {
		return nil, err
	}
	return map[string]any{"payload": payload, "signature": sig}, nil
}

func cmdLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	offline := fs.String("sign-challenge", "", "advanced: sign this challenge offline and print the record")
	host := fs.String("registry-host", "innernetcorp.com", "advanced: registry host for --sign-challenge")
	exp := fs.Int64("expires", 0, "advanced: expiry for --sign-challenge")
	if err := fs.Parse(args); err != nil {
		return err
	}
	priv, err := loadKey()
	if err != nil {
		return err
	}
	if *offline != "" {
		rec, err := loginRecord(priv, *offline, *host, *exp)
		if err != nil {
			return err
		}
		raw, _ := json.Marshal(rec)
		fmt.Println(string(raw))
		return nil
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	base := registryURL(c)
	u, err := url.Parse(base)
	if err != nil {
		return err
	}
	resp, err := httpClient.Get(base + "/login/challenge?provider=" + providerID(priv))
	if err != nil {
		return fmt.Errorf("could not reach the registry: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return errors.New("the registry dashboard is not live yet")
	}
	var ch struct {
		Challenge string `json:"challenge"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<10)).Decode(&ch); err != nil {
		return fmt.Errorf("unexpected registry reply: %v", err)
	}
	rec, err := loginRecord(priv, ch.Challenge, u.Host, ch.ExpiresAt)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(rec)
	resp2, err := httpClient.Post(base+"/login", "application/json", bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("could not reach the registry: %v", err)
	}
	defer resp2.Body.Close()
	var out struct {
		URL string `json:"url"`
	}
	if resp2.StatusCode/100 != 2 || json.NewDecoder(io.LimitReader(resp2.Body, 8<<10)).Decode(&out) != nil || out.URL == "" {
		return fmt.Errorf("registry refused the login (%s)", resp2.Status)
	}
	fmt.Println("Open this one-time link within 10 minutes to reach your dashboard and add a passkey:")
	fmt.Println(out.URL)
	return nil
}

func cmdBackup(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: innernet-provider backup FILE")
	}
	if _, err := os.Stat(args[0]); err == nil {
		return errors.New("that file already exists; choose a new name")
	}
	priv, err := loadKey()
	if err != nil {
		return err
	}
	pass, err := readPassphrase("Choose a backup passphrase (12+ characters): ")
	if err != nil {
		return err
	}
	if os.Getenv("INNERNET_BACKUP_PASSPHRASE") == "" {
		again, err := readPassphrase("Type it again: ")
		if err != nil {
			return err
		}
		if again != pass {
			return errors.New("passphrases do not match")
		}
	}
	raw, err := sealBackup(priv.Seed(), pass)
	if err != nil {
		return err
	}
	if err := os.WriteFile(args[0], append(raw, '\n'), 0o600); err != nil {
		return err
	}
	fmt.Println("Encrypted backup written to", args[0])
	fmt.Println("Keep it offline (USB stick, password manager). Without it and the passphrase, a lost key cannot be recovered.")
	return nil
}

func cmdRestore(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: innernet-provider restore FILE")
	}
	if _, err := os.Stat(keyPath()); err == nil {
		return fmt.Errorf("an identity key already exists at %s; move it away first", keyPath())
	}
	raw, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	pass, err := readPassphrase("Backup passphrase: ")
	if err != nil {
		return err
	}
	seed, err := openBackup(raw, pass)
	if err != nil {
		return err
	}
	if err := writeKey(seed); err != nil {
		return err
	}
	fmt.Println("Identity restored. Provider id:", providerID(ed25519.NewKeyFromSeed(seed)))
	fmt.Println("Run innernet-provider init --force to set up this machine's offer.")
	return nil
}

// statusReply is the registry's public+private summary; the web dashboard shows the same data.
type statusReply struct {
	State     string `json:"state"`
	Reason    string `json:"reason"`
	CheckedAt int64  `json:"checked_at"`
	Health    *struct {
		Uptime7d    string `json:"uptime_7d"`
		ChallengeOK string `json:"challenge_pass_7d"`
	} `json:"health"`
	Earnings *struct {
		Asset string `json:"asset"`
		Gross string `json:"gross_30d"`
		Fee   string `json:"fee_30d"`
		Net   string `json:"net_30d"`
	} `json:"earnings"`
	Activity map[string]string `json:"activity"`
}

func printStatus(w io.Writer, s *statusReply) {
	fmt.Fprintln(w, "Status:", s.State)
	if s.Reason != "" {
		fmt.Fprintln(w, "Reason:", s.Reason)
	}
	if s.CheckedAt > 0 {
		fmt.Fprintln(w, "Last checked:", time.Unix(s.CheckedAt, 0).UTC().Format(time.RFC3339))
	}
	if s.Health != nil {
		fmt.Fprintf(w, "Health (7 days): uptime %s, storage challenges passed %s\n", s.Health.Uptime7d, s.Health.ChallengeOK)
	}
	for _, k := range []string{"STO-1", "RLY-1", "CMP-1", "GPU-1"} {
		if v, ok := s.Activity[k]; ok {
			fmt.Fprintf(w, "Activity %s: %s\n", k, v)
		}
	}
	if s.Earnings != nil {
		fmt.Fprintf(w, "Earnings (30 days): %s %s paid, %s network fee, %s to you\n",
			s.Earnings.Gross, s.Earnings.Asset, s.Earnings.Fee, s.Earnings.Net)
		fmt.Fprintln(w, "Every payment and split, with transaction links: innernet-provider login, then open the dashboard")
	}
}

// askOffer asks every setup question, with the current values as defaults.
func askOffer(c *Config) {
	c.Name = strings.ToLower(ask("Provider name (lowercase, shown publicly)", c.Name))
	c.Region = strings.ToLower(ask("Region label (e.g. asia-south, eu-central)", c.Region))
	fmt.Println()
	fmt.Println("Clients reach this machine at this address. Behind a router, start finds a way in by itself")
	fmt.Println("(router port, ST81 relay or HTTPS tunnel); here, give the address you want listed.")
	c.Host = ask("Public host name or IP", c.Host)
	c.Port = askInt("Public port", c.Port)
	fmt.Println()
	c.Storage = askInt("Storage to offer, in GiB (0 = none)", c.Storage)
	if c.Storage > 0 {
		c.Prices["STO-1"] = ask("  Price, USDC per GiB per day", c.Prices["STO-1"])
	}
	c.RelayCap = askInt("Bandwidth to relay per month, in GiB (0 = none)", c.RelayCap)
	if c.RelayCap > 0 {
		fmt.Println("  Check that your internet plan allows reselling bandwidth.")
		c.Prices["RLY-1"] = ask("  Price, USDC per GiB relayed", c.Prices["RLY-1"])
	}
	c.Compute = askYes("Rent CPU time? Clients' jobs run sandboxed (WebAssembly), with no network or file access", c.Compute)
	if c.Compute {
		c.CPUs = askInt("  Max CPUs at once", c.CPUs)
		c.MemMiB = askInt("  Max memory per job, MiB", c.MemMiB)
		c.Prices["CMP-1"] = ask("  Price, USDC per CPU-hour", c.Prices["CMP-1"])
	}
	if gpus := detectGPUs(); len(gpus) > 0 {
		if _, have, ok := bestGPU(gpus); ok {
			fmt.Printf("GPU found: %s\n", gpuSummary(gpus))
			if askYes("  Rent GPU time? Clients run their own model files on it", c.GPU) {
				n := askInt("  How many to offer", max(1, min(have, c.GPUs)))
				if c.Prices["GPU-1"] == "" {
					c.Prices["GPU-1"] = defaultPrices()["GPU-1"]
				}
				c.Prices["GPU-1"] = ask("  Price, USDC per GPU per hour", c.Prices["GPU-1"])
				if err := c.setGPU(gpus, n); err != nil {
					fmt.Println("  " + err.Error())
					c.GPU = false
				}
			} else {
				c.GPU = false
			}
		}
	}
}
