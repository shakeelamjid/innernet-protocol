package main

import (
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

// cmdStart is the one-command onboarding: detect, then set up on the website or in the terminal.
func cmdStart(args []string) error {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	mode := fs.String("mode", "", "web or terminal (asked if empty)")
	yes := fs.Bool("yes", false, "terminal mode without questions (agents, scripts)")
	wallet := fs.String("wallet", "", "wallet that receives your share (terminal mode)")
	registry := fs.String("registry", defaultRegistry, "registry URL")
	port := fs.Int("port", 9443, "public port to offer")
	noOpen := fs.Bool("no-browser", false, "do not try to open the browser")
	if err := fs.Parse(args); err != nil {
		return err
	}
	reg := strings.TrimRight(orDefault(os.Getenv("INNERNET_REGISTRY"), *registry), "/")
	if ms, err := strconv.Atoi(os.Getenv("INNERNET_POLL_MS")); err == nil && ms > 0 {
		pollEvery = time.Duration(ms) * time.Millisecond
	}
	fmt.Println("INNERnet provider setup (Base Sepolia testnet: no real money moves yet)")
	fmt.Println()
	priv, err := loadKey()
	if err != nil {
		if priv, err = newKey(); err != nil {
			return err
		}
		fmt.Println("Created this machine's provider key:", keyPath())
	} else {
		fmt.Println("Using this machine's provider key:", keyPath())
	}
	fmt.Println("Provider id:", providerID(priv))
	fmt.Println()
	f := detect(reg, *port, true)
	fmt.Println()
	if f.reachChecked && !f.Reachable {
		fmt.Println("Note: clients must be able to reach this machine. You can finish setup now and open the port later;")
		fmt.Println("the registry will keep checking.")
		fmt.Println()
	}
	m := strings.ToLower(*mode)
	if *yes && m == "" {
		m = "terminal"
	}
	if m == "" {
		fmt.Println("How do you want to set up?")
		fmt.Println("  1) On the website (recommended): you get a code, then choose everything in your browser")
		fmt.Println("  2) Here in the terminal (power users and agents)")
		if strings.HasPrefix(ask("Choose 1 or 2", "1"), "2") {
			m = "terminal"
		} else {
			m = "web"
		}
		fmt.Println()
	}
	switch m {
	case "web":
		return startWeb(reg, priv, f, *noOpen)
	case "terminal":
		return startTerminal(reg, priv, f, *yes, *wallet)
	}
	return errors.New("--mode must be web or terminal")
}

// ---------- website setup ----------

func connectRecord(priv ed25519.PrivateKey, f *facts, now int64) (map[string]any, error) {
	nb := make([]byte, 16)
	_, _ = rand.Read(nb)
	detected := map[string]any{"name": f.Name, "region": f.Region, "port": f.Port, "storage_free_gib": f.StorageFreeGiB,
		"cpus": f.CPUs, "memory_mib": f.MemoryMiB, "os": f.OS, "arch": f.Arch, "reachable": f.Reachable,
		"version": f.Version}
	if f.Host != "" {
		detected["host"] = f.Host
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
		MemMiB: o.MemMiB, Prices: map[string]string{"STO-1": "0.0010", "RLY-1": "0.0050", "CMP-1": "0.0100"},
		Created: time.Now().UTC().Format(time.RFC3339)}
	for k, v := range o.Prices {
		if _, ok := units[k]; ok && v != "" {
			c.Prices[k] = v
		}
	}
	return c
}

func startWeb(reg string, priv ed25519.PrivateKey, f *facts, noOpen bool) error {
	rec, err := connectRecord(priv, f, time.Now().Unix())
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(rec)
	resp, err := httpClient.Post(reg+"/connect", "application/json", bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("could not reach the registry: %v", err)
	}
	var cr struct {
		Code, Poll, URL string
		ExpiresAt       int64 `json:"expires_at"`
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 8<<10)).Decode(&cr)
	resp.Body.Close()
	if resp.StatusCode != 200 || err != nil || cr.Code == "" {
		return fmt.Errorf("registry refused to start setup (%s)", resp.Status)
	}
	fmt.Println("Open this link, or go to innernetcorp.com/registry/claim and enter the code:")
	fmt.Println()
	fmt.Println("    " + cr.URL)
	fmt.Println()
	fmt.Println("    Code:  " + cr.Code)
	fmt.Println()
	fmt.Println("The code works once and expires in 30 minutes. Keep this terminal open.")
	if !noOpen {
		openBrowser(cr.URL)
	}
	offer, err := waitForOffer(reg, cr.Poll)
	if err != nil {
		return err
	}
	c := offer.config(strings.TrimSuffix(reg, ""))
	if err := c.validate(true); err != nil {
		return fmt.Errorf("the offer from the website is not valid: %v", err)
	}
	fmt.Println()
	printOffer(c)
	if !askYes("Sign this offer with this machine's key and apply", true) {
		return errors.New("cancelled; nothing was applied. Run innernet-provider start again when ready")
	}
	if err := finishSetup(c, priv); err != nil {
		return err
	}
	req, _ := http.NewRequest("POST", reg+"/connect/finish", nil)
	req.Header.Set("X-Poll-Token", cr.Poll)
	if r, err := httpClient.Do(req); err == nil {
		r.Body.Close()
	}
	afterSetup(false)
	return nil
}

func waitForOffer(reg, poll string) (*webOffer, error) {
	deadline := time.Now().Add(31 * time.Minute)
	last := ""
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("GET", reg+"/connect/status", nil)
		req.Header.Set("X-Poll-Token", poll)
		resp, err := httpClient.Do(req)
		if err == nil {
			var st struct {
				Status string    `json:"status"`
				Offer  *webOffer `json:"offer"`
			}
			_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&st)
			resp.Body.Close()
			if st.Status != last {
				switch st.Status {
				case "claimed":
					fmt.Println("Code accepted. Waiting for you to finish on the website…")
				case "expired":
					return nil, errors.New("the code expired; run innernet-provider start again")
				}
				last = st.Status
			}
			if st.Status == "submitted" && st.Offer != nil {
				return st.Offer, nil
			}
		}
		time.Sleep(pollEvery)
	}
	return nil, errors.New("timed out waiting for the website; run innernet-provider start again")
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

func startTerminal(reg string, priv ed25519.PrivateKey, f *facts, yes bool, wallet string) error {
	c := &Config{Version: "1", Registry: reg, Network: "base-sepolia", Port: f.Port, CPUs: 1, MemMiB: 512,
		Prices: map[string]string{"STO-1": "0.0010", "RLY-1": "0.0050", "CMP-1": "0.0100"}}
	if old, err := loadConfig(); err == nil {
		c = old
		c.Registry = reg
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
	printOffer(c)
	if !yes && !askYes("Sign this offer and apply", true) {
		return errors.New("cancelled; your answers are saved, nothing was applied")
	}
	if err := finishSetup(c, priv); err != nil {
		return err
	}
	afterSetup(yes)
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
	fmt.Println("Offer to sign")
	fmt.Printf("  Name       %s (%s)\n", c.Name, c.Region)
	fmt.Printf("  Address    %s:%d\n", c.Host, c.Port)
	if c.Storage > 0 {
		fmt.Printf("  Storage    %d GiB at %s USDC per GiB-day\n", c.Storage, c.Prices["STO-1"])
	}
	if c.RelayCap > 0 {
		fmt.Printf("  Bandwidth  %d GiB/month at %s USDC per GiB\n", c.RelayCap, c.Prices["RLY-1"])
	}
	if c.Compute {
		fmt.Printf("  Compute    %d CPUs, %d MiB at %s USDC per billion instructions\n", c.CPUs, c.MemMiB, c.Prices["CMP-1"])
	}
	fmt.Printf("  Payout     %s on %s\n", c.Payout, c.Network)
	fmt.Println("             (check this is the contract you created; payments go there)")
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

func afterSetup(quiet bool) {
	fmt.Println()
	fmt.Println("Your details:", detailsPath())
	backup := filepath.Join(filepath.Dir(home()), "provider-backup.json")
	if _, err := os.Stat(backup); err != nil && !quiet {
		if askYes("Back up this machine's key now (encrypted with a passphrase)", true) {
			if err := cmdBackup([]string{backup}); err != nil {
				fmt.Println("Backup skipped:", err)
			}
		} else {
			fmt.Println("Back it up later with: innernet-provider backup ~/innernet-provider-backup.json")
		}
	}
	fmt.Println()
	fmt.Println("Next:")
	fmt.Println("  innernet-provider serve     start serving clients (keep it running)")
	fmt.Println("  innernet-provider status    see where your listing stands")
	fmt.Println("  Dashboard: https://innernetcorp.com/dashboard")
}
