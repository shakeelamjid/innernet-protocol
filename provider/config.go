package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var (
	reName    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	reRegion  = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	reHost    = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)
	reEVM     = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
	reDecimal = regexp.MustCompile(`^(0|[1-9][0-9]{0,17})(\.[0-9]{1,18})?$`)
)

// Networks a provider can be paid on. CAIP-2 ids.
var networks = map[string]string{
	"base-sepolia": "eip155:84532", // testnet: default until mainnet launch
	"base":         "eip155:8453",
}

var units = map[string]string{"STO-1": "GiB-day", "RLY-1": "GiB", "CMP-1": "CPU-hour", "GPU-1": "GPU-hour"}

func defaultPrices() map[string]string {
	return map[string]string{"STO-1": "0.0010", "RLY-1": "0.0050", "CMP-1": "0.0200", "GPU-1": "0.2500"}
}

type Config struct {
	Version    string            `json:"version"`
	Name       string            `json:"name"`
	Region     string            `json:"region"`
	Host       string            `json:"host"`
	Port       int               `json:"port"`
	Network    string            `json:"network"`
	Payout     string            `json:"payout_contract"`
	Registry   string            `json:"registry"`
	Storage    int               `json:"storage_gib"`
	RelayCap   int               `json:"relay_gib_per_month"`
	Compute    bool              `json:"compute"`
	CPUs       int               `json:"compute_max_cpus"`
	MemMiB     int               `json:"compute_max_memory_mib"`
	GPU        bool              `json:"gpu,omitempty"`
	GPUs       int               `json:"gpu_count,omitempty"`
	GPUVendor  string            `json:"gpu_vendor,omitempty"`
	GPUModel   string            `json:"gpu_model,omitempty"`
	GPUAPI     string            `json:"gpu_api,omitempty"`
	GPUVRAM    int               `json:"gpu_vram_mib,omitempty"`
	ReserveMiB int               `json:"reserve_memory_mib,omitempty"`  // memory compute never uses (for the owner)
	PerClient  int               `json:"max_jobs_per_client,omitempty"` // running CPU jobs + GPU sessions per client
	Prices     map[string]string `json:"prices_usdc"`
	Created    string            `json:"created_at"`
	PortMap    string            `json:"port_map,omitempty"` // natpmp or upnp: serve keeps the router mapping alive
	Hours      string            `json:"hours,omitempty"`    // "always" or e.g. "mon-fri 21:00-08:00"
	TZ         string            `json:"tz,omitempty"`       // time zone the hours are in
	Class      string            `json:"class,omitempty"`    // server, desktop or laptop
	State      string            `json:"state,omitempty"`    // paused or leaving, set by pause/leave
	Relay      *relayTarget      `json:"relay,omitempty"`    // reached through this ST81 relay (RLY-0)
	Tunnel     bool              `json:"tunnel,omitempty"`   // reached through the registry's HTTPS tunnel
	TunnelHost string            `json:"tunnel_host,omitempty"`
}

func home() string {
	if h := os.Getenv("INNERNET_HOME"); h != "" {
		return h
	}
	d, err := os.UserHomeDir()
	if err != nil {
		d = "."
	}
	return filepath.Join(d, ".innernet", "provider")
}

func keyPath() string     { return filepath.Join(home(), "identity.key") }
func configPath() string  { return filepath.Join(home(), "config.json") }
func detailsPath() string { return filepath.Join(home(), "PROVIDER-DETAILS.txt") }
func descPath() string    { return filepath.Join(home(), "descriptor.json") }

func ensureHome() error {
	if err := os.MkdirAll(home(), 0o700); err != nil {
		return err
	}
	return os.Chmod(home(), 0o700)
}

func newKey() (ed25519.PrivateKey, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), writeKey(seed)
}

func writeKey(seed []byte) error {
	if err := ensureHome(); err != nil {
		return err
	}
	tmp := keyPath() + ".tmp"
	if err := os.WriteFile(tmp, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, keyPath())
}

func loadKey() (ed25519.PrivateKey, error) {
	info, err := os.Stat(keyPath())
	if err != nil {
		return nil, errors.New("no provider identity here yet; run: innernet-provider init")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by other users; run: chmod 600 %s", keyPath(), keyPath())
	}
	raw, err := os.ReadFile(keyPath())
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("identity.key is damaged; restore it from your backup file")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func providerID(priv ed25519.PrivateKey) string {
	return hex.EncodeToString(priv.Public().(ed25519.PublicKey))
}

func loadConfig() (*Config, error) {
	raw, err := os.ReadFile(configPath())
	if err != nil {
		return nil, errors.New("no provider config here yet; run: innernet-provider init")
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("config.json is not valid JSON: %w", err)
	}
	return &c, nil
}

func saveConfig(c *Config) error {
	if err := ensureHome(); err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(configPath(), append(raw, '\n'), 0o600)
}

func (c *Config) services() []string {
	var s []string
	if c.Storage > 0 {
		s = append(s, "STO-1")
	}
	if c.RelayCap > 0 {
		s = append(s, "RLY-1")
	}
	if c.Compute {
		s = append(s, "CMP-1")
	}
	if c.GPU {
		s = append(s, "GPU-1")
	}
	return s
}

func (c *Config) validate(forApply bool) error {
	var problems []string
	if !reName.MatchString(c.Name) {
		problems = append(problems, "name: use 1-64 lowercase letters, digits, '.', '_' or '-'")
	}
	if !reRegion.MatchString(c.Region) {
		problems = append(problems, "region: use lowercase letters, digits and '-', e.g. asia-south")
	}
	if !reHost.MatchString(c.Host) || strings.Contains(c.Host, "..") {
		problems = append(problems, "host: a public DNS name or IP other machines can reach")
	}
	if c.Port < 1 || c.Port > 65535 {
		problems = append(problems, "port: 1-65535")
	}
	if _, ok := networks[c.Network]; !ok {
		problems = append(problems, "network: base-sepolia (testnet) or base")
	}
	if len(c.services()) == 0 {
		problems = append(problems, "offer at least one of storage, bandwidth, CPU or GPU")
	}
	if c.GPU && (c.GPUs < 1 || c.GPUs > 16 || c.GPUModel == "" || hwText(c.GPUModel) != c.GPUModel) {
		problems = append(problems, "gpu: 1-16 GPUs of a model this machine detected")
	}
	for _, s := range c.services() {
		if !reDecimal.MatchString(c.Prices[s]) {
			problems = append(problems, fmt.Sprintf("price for %s: a decimal USDC amount per %s", s, units[s]))
		}
	}
	if _, err := parseHours(c.Hours); err != nil {
		problems = append(problems, "hours: "+err.Error())
	}
	if c.Class != "" && c.Class != "server" && c.Class != "desktop" && c.Class != "laptop" {
		problems = append(problems, "class: server, desktop or laptop")
	}
	if forApply && !reEVM.MatchString(c.Payout) {
		problems = append(problems, "payout contract: set it with: innernet-provider wallet set 0x...")
	}
	if len(problems) > 0 {
		return errors.New("config problems:\n  - " + strings.Join(problems, "\n  - "))
	}
	return nil
}

// descriptorEntry builds the REG-1 provider entry exactly as the Python reference validates it.
func (c *Config) descriptorEntry(id string) map[string]any {
	services := c.services()
	prices := map[string]any{}
	limits := map[string]any{}
	for _, s := range services {
		prices[s] = map[string]any{"asset": "USDC", "unit": units[s], "amount": c.Prices[s]}
	}
	if c.Storage > 0 {
		limits["STO-1"] = map[string]any{"max_storage_gib": c.Storage}
	}
	if c.RelayCap > 0 {
		limits["RLY-1"] = map[string]any{"max_gib_per_month": c.RelayCap}
	}
	if c.Compute {
		limits["CMP-1"] = map[string]any{"max_cpus": c.CPUs, "max_memory_mib": c.MemMiB}
	}
	var hardware map[string]any
	if c.GPU {
		limits["GPU-1"] = map[string]any{"max_gpus": c.GPUs}
		hardware = map[string]any{"gpu_vendor": c.GPUVendor, "gpu_model": c.GPUModel, "gpu_api": orDefault(c.GPUAPI, "none")}
		if c.GPUVRAM > 0 {
			hardware["gpu_vram_mib"] = c.GPUVRAM
		}
	}
	entry := map[string]any{
		"id": id, "name": c.Name, "region": c.Region,
		"endpoints": []any{c.publicEndpoint()},
		"services":  toAny(services),
		"payto":     map[string]any{networks[c.Network]: c.Payout},
		"prices":    prices,
	}
	if len(limits) > 0 {
		entry["limits"] = limits
	}
	if hardware != nil {
		entry["hardware"] = hardware
	}
	if av, err := availabilityEntry(c.Hours, orDefault(c.TZ, "UTC")); err == nil && av != nil {
		entry["availability"] = av
	}
	if c.Class != "" {
		entry["class"] = c.Class
	}
	return entry
}

func toAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

func writeDetails(c *Config, id string) error {
	var b strings.Builder
	b.WriteString("INNERnet provider details\n")
	b.WriteString("=========================\n")
	b.WriteString("This file is safe to share. It contains NO secret key.\n")
	b.WriteString("Your secret key is in identity.key next to this file. Never share that one.\n\n")
	fmt.Fprintf(&b, "Provider id      %s\n", id)
	fmt.Fprintf(&b, "Name             %s\n", c.Name)
	fmt.Fprintf(&b, "Region           %s\n", c.Region)
	fmt.Fprintf(&b, "Address          %s:%d\n", c.Host, c.Port)
	fmt.Fprintf(&b, "Payment network  %s (%s)\n", c.Network, networks[c.Network])
	payout := c.Payout
	if payout == "" {
		payout = "(not set: innernet-provider wallet set 0x...)"
	}
	fmt.Fprintf(&b, "Payout contract  %s\n\n", payout)
	b.WriteString("Offering\n")
	if c.Storage > 0 {
		fmt.Fprintf(&b, "  Storage        %d GiB at %s USDC per GiB-day\n", c.Storage, c.Prices["STO-1"])
	}
	if c.RelayCap > 0 {
		fmt.Fprintf(&b, "  Bandwidth      %d GiB/month at %s USDC per GiB\n", c.RelayCap, c.Prices["RLY-1"])
	}
	if c.Compute {
		fmt.Fprintf(&b, "  CPU            %d CPUs, %d MiB at %s USDC per CPU-hour\n", c.CPUs, c.MemMiB, c.Prices["CMP-1"])
	}
	if c.GPU {
		fmt.Fprintf(&b, "  GPU            %d × %s at %s USDC per GPU-hour\n", c.GPUs, c.GPUModel, c.Prices["GPU-1"])
	}
	fmt.Fprintf(&b, "\nRegistry         %s\n", c.Registry)
	fmt.Fprintf(&b, "Status page      %s/providers/%s\n", strings.TrimSuffix(c.Registry, "/registry/v1"), id)
	fmt.Fprintf(&b, "Files            %s\n", home())
	fmt.Fprintf(&b, "Written          %s\n\n", time.Now().UTC().Format(time.RFC3339))
	b.WriteString("Next steps\n")
	b.WriteString("  1. innernet-provider backup ~/innernet-provider-backup.json   (keep it offline)\n")
	b.WriteString("  2. innernet-provider wallet set 0x...                          (your payout split contract)\n")
	b.WriteString("  3. innernet-provider apply\n")
	b.WriteString("  4. innernet-provider status\n")
	return os.WriteFile(detailsPath(), []byte(b.String()), 0o644)
}

// publicEndpoint is the address in the signed descriptor: the machine itself, or the
// relay or tunnel that reaches it. Live presence carries the current one.
func (c *Config) publicEndpoint() map[string]any {
	switch {
	case c.Relay != nil:
		if i := strings.LastIndex(c.Relay.Addr, ":"); i > 0 {
			port, _ := strconv.Atoi(c.Relay.Addr[i+1:])
			return map[string]any{"host": c.Relay.Addr[:i], "port": port}
		}
	case c.Tunnel && c.TunnelHost != "":
		return map[string]any{"host": c.TunnelHost, "port": 443}
	}
	return map[string]any{"host": c.Host, "port": c.Port}
}

// setGPU offers n of this machine's best GPU. The model is what the machine detected.
func (c *Config) setGPU(gpus []gpuInfo, n int) error {
	g, have, ok := bestGPU(gpus)
	if !ok {
		return errors.New("this machine has no GPU that can run jobs")
	}
	if n < 1 || n > have {
		return fmt.Errorf("this machine has %d %s", have, g.Model)
	}
	c.GPU, c.GPUs, c.GPUVendor, c.GPUModel, c.GPUAPI, c.GPUVRAM = true, n, g.Vendor, g.Model, g.API, g.VRAMMiB
	if c.Prices["GPU-1"] == "" {
		c.Prices["GPU-1"] = defaultPrices()["GPU-1"]
	}
	return nil
}
