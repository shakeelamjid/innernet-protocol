package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
)

// Compute services (CMP-1 CPU time, GPU-1 GPU time) share one prepaid credit
// balance per client. A client pays USDC to this provider's payout contract once; the provider
// credits it after checking the transfer on-chain. Every job or request takes its cost off the
// balance and comes back with a usage receipt signed by this provider.

const usageDomain = "INNERnet/PAY-1/usage-receipt\x00"

type ledger struct {
	mu   sync.Mutex
	path string
	bal  map[string]int64 // client -> USDC base units (6 decimals)
}

func openLedger(dir string) *ledger {
	l := &ledger{path: filepath.Join(dir, "credits.json"), bal: map[string]int64{}}
	if raw, err := os.ReadFile(l.path); err == nil {
		_ = json.Unmarshal(raw, &l.bal)
	}
	return l
}

func (l *ledger) saveLocked() {
	raw, _ := json.Marshal(l.bal)
	tmp := l.path + ".tmp"
	if os.WriteFile(tmp, raw, 0o600) == nil {
		_ = os.Rename(tmp, l.path)
	}
}

func (l *ledger) balance(client string) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.bal[client]
}

func (l *ledger) add(client string, v int64) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.bal[client] += v
	l.saveLocked()
	return l.bal[client]
}

// hold takes v off the balance up front (refunded with release); it fails if the balance is short.
func (l *ledger) hold(client string, v int64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.bal[client] < v {
		return fmt.Errorf("balance %s USDC is below the %s USDC this needs; add credit first",
			usdc(l.bal[client]), usdc(v))
	}
	l.bal[client] -= v
	l.saveLocked()
	return nil
}

// settle turns a hold into the real cost: the unused part goes back. It returns the new balance.
func (l *ledger) settle(client string, held, cost int64) int64 {
	if cost > held {
		cost = held
	}
	return l.add(client, held-cost)
}

func usdc(v int64) string {
	r := new(big.Rat).SetFrac(big.NewInt(v), big.NewInt(1_000_000))
	return strings.TrimRight(strings.TrimRight(r.FloatString(6), "0"), ".")
}

// micro returns units × price in USDC base units, rounded up (never below 1 for a non-zero cost).
func micro(units, price string) int64 {
	v, err := owed(units, price)
	if err != nil || !v.IsInt64() {
		return 0
	}
	return v.Int64()
}

func (s *server) receipt(client, service, units, unit string, cost, balance int64, extra map[string]any) map[string]any {
	payload := map[string]any{"version": "PAY-1-USAGE", "provider": providerID(s.priv), "client": client,
		"service": service, "units": units, "unit": unit, "cost": usdc(cost), "asset": "USDC",
		"balance": usdc(balance), "at": s.now().Unix()}
	for k, v := range extra {
		payload[k] = v
	}
	sig, err := signCanonical(s.priv, usageDomain, payload)
	if err != nil {
		return nil
	}
	return map[string]any{"payload": payload, "signature": sig}
}

// ---------- credit ----------

func (s *server) credit(w http.ResponseWriter, client string, body []byte) {
	var req struct {
		Tx string `json:"tx"`
	}
	if json.Unmarshal(body, &req) != nil || !reTx.MatchString(req.Tx) {
		s.fail(w, 400, "credit needs tx (0x + 64 hex): a USDC transfer to this provider's payout contract")
		return
	}
	tx := strings.ToLower(req.Tx)
	s.mu.Lock()
	already := s.used[tx]
	s.mu.Unlock()
	if already {
		s.fail(w, 409, "this payment was already used")
		return
	}
	paid, err := s.paidTo(tx)
	if err != nil {
		s.fail(w, 402, err.Error())
		return
	}
	if !paid.IsInt64() {
		s.fail(w, 400, "payment too large")
		return
	}
	s.mu.Lock()
	if s.used[tx] {
		s.mu.Unlock()
		s.fail(w, 409, "this payment was already used")
		return
	}
	s.used[tx] = true
	if f, err := os.OpenFile(s.usedLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
		fmt.Fprintf(f, "%s %s credit %s %d\n", tx, client, usdc(paid.Int64()), s.now().Unix())
		f.Close()
	}
	s.mu.Unlock()
	bal := s.credits.add(client, paid.Int64())
	s.stats.add("payments", 1)
	s.reply(w, 200, map[string]any{"credited": usdc(paid.Int64()), "balance": usdc(bal), "asset": "USDC"})
}

// ---------- CMP-1: CPU jobs ----------

const (
	maxJobSeconds = 300
	maxJobOutput  = 256 << 10
	maxJobWasm    = 1536 << 10
)

type cpuJob struct {
	Wasm       string   `json:"wasm"`        // base64 WebAssembly module (WASI command), or:
	WasmURL    string   `json:"wasm_url"`    // https address of the module (large modules), with
	WasmSHA    string   `json:"wasm_sha256"` // its SHA-256; downloaded once, kept by hash
	Input      string   `json:"input"`       // base64, given as standard input
	Args       []string `json:"args"`
	Seed       int64    `json:"seed"`
	MaxSeconds int      `json:"max_seconds"`
	MaxMemMiB  int      `json:"max_memory_mib"`
	QueueSecs  *int     `json:"queue_seconds"` // how long to wait for a free slot (0-120, default 30; 0 = do not wait)
}

type jobResult struct {
	Output   []byte
	Stderr   []byte
	ExitCode uint32
	Seconds  float64
	Err      string
}

// runWasm runs a module with no files, no network, no environment, a fixed clock and seeded
// randomness, so the same module, input and seed give the same output on any provider.
func runWasm(ctx context.Context, wasm, input []byte, args []string, seed int64, memMiB int, limit time.Duration) jobResult {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	pages := uint32(memMiB * 16) // 64 KiB pages
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().
		WithMemoryLimitPages(pages).WithCloseOnContextDone(true))
	defer rt.Close(context.Background())
	wasi_snapshot_preview1.MustInstantiate(ctx, rt)
	var stdout, stderr limitedBuffer
	stdout.max, stderr.max = maxJobOutput, 16<<10
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano()
	tick := int64(1)
	cfg := wazero.NewModuleConfig().WithStdin(bytes.NewReader(input)).WithStdout(&stdout).WithStderr(&stderr).
		WithArgs(append([]string{"job"}, args...)...).
		WithWalltime(func() (int64, int32) { return fixed / 1e9, int32(fixed % 1e9) }, sys.ClockResolution(1)).
		WithNanotime(func() int64 { tick += 1000; return tick }, sys.ClockResolution(1)). // advances per read: same on every run
		WithRandSource(rand.New(rand.NewSource(seed)))
	start := time.Now()
	compiled, err := rt.CompileModule(ctx, wasm)
	if err != nil {
		return jobResult{Err: "not a valid WebAssembly module: " + err.Error()}
	}
	_, err = rt.InstantiateModule(ctx, compiled, cfg)
	res := jobResult{Output: stdout.Bytes(), Stderr: stderr.Bytes(), Seconds: time.Since(start).Seconds()}
	var exit *sys.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		res.ExitCode = exit.ExitCode()
		if exit.ExitCode() == sys.ExitCodeDeadlineExceeded || ctx.Err() != nil {
			res.Err = fmt.Sprintf("stopped after the %s time limit", limit)
		}
	default:
		res.Err = err.Error()
	}
	if stdout.over {
		res.Err = fmt.Sprintf("output is larger than %d KiB", maxJobOutput>>10)
	}
	return res
}

type limitedBuffer struct {
	bytes.Buffer
	max  int
	over bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.max {
		b.over = true
		return 0, errors.New("output limit")
	}
	return b.Buffer.Write(p)
}

func (s *server) cpuJob(w http.ResponseWriter, client string, body []byte) {
	if !s.cfg.Compute {
		s.fail(w, 404, "this provider does not offer CPU jobs")
		return
	}
	var j cpuJob
	if json.Unmarshal(body, &j) != nil || (j.Wasm == "") == (j.WasmURL == "") {
		s.fail(w, 400, "job needs wasm (base64 module) or wasm_url with wasm_sha256")
		return
	}
	var wasm []byte
	var err1 error
	if j.WasmURL != "" {
		if !okURL(j.WasmURL) || !reHex64.MatchString(j.WasmSHA) {
			s.fail(w, 400, "wasm_url must be https and wasm_sha256 64 hex")
			return
		}
		p := filepath.Join(s.data, "wasm", j.WasmSHA+".wasm")
		if err := downloadVerified(j.WasmURL, p, j.WasmSHA, 64<<20, nil); err != nil {
			s.fail(w, 422, "module: "+err.Error())
			return
		}
		wasm, err1 = os.ReadFile(p)
	} else {
		wasm, err1 = base64.StdEncoding.DecodeString(j.Wasm)
	}
	input, err2 := base64.StdEncoding.DecodeString(j.Input)
	if err1 != nil || err2 != nil || len(j.Args) > 32 || (j.WasmURL == "" && len(wasm) > maxJobWasm) {
		s.fail(w, 400, "wasm and input must be base64; an inline module at most 1.5 MiB (larger: wasm_url); at most 32 args")
		return
	}
	if j.MaxSeconds <= 0 || j.MaxSeconds > maxJobSeconds {
		j.MaxSeconds = 60
	}
	if j.MaxMemMiB <= 0 || j.MaxMemMiB > s.cfg.MemMiB {
		j.MaxMemMiB = s.cfg.MemMiB
	}
	price := s.cfg.Prices["CMP-1"]
	held := micro(fmt.Sprintf("%d/3600", j.MaxSeconds), price)
	if err := s.credits.hold(client, held); err != nil {
		s.fail(w, 402, err.Error())
		return
	}
	wait := 30 * time.Second
	if j.QueueSecs != nil {
		wait = time.Duration(min(max(*j.QueueSecs, 0), 120)) * time.Second
	}
	release, err := s.sched.acquire(context.Background(), demand{Client: client, CPU: 1, MemMiB: j.MaxMemMiB + 32}, wait)
	if err != nil {
		s.credits.settle(client, held, 0)
		if errors.Is(err, errBusy) {
			w.Header().Set("Retry-After", "10")
			s.fail(w, 503, "busy ("+err.Error()+"); try again or use another provider")
		} else {
			s.fail(w, 422, err.Error())
		}
		return
	}
	res := runWasm(context.Background(), wasm, input, j.Args, j.Seed, j.MaxMemMiB, time.Duration(j.MaxSeconds)*time.Second)
	release()
	ms := int64(max(res.Seconds, 0.001)*1000 + 0.999)
	secs := fmt.Sprintf("%d.%03d", ms/1000, ms%1000)
	cost := micro(fmt.Sprintf("%d/3600000", ms), price)
	if res.Err != "" && len(res.Output) == 0 && res.Seconds < 0.05 {
		cost = 0 // refused before it ran: no charge
	}
	bal := s.credits.settle(client, held, cost)
	wh, ih, oh := sha256.Sum256(wasm), sha256.Sum256(input), sha256.Sum256(res.Output)
	s.stats.add("jobs", 1)
	out := map[string]any{"output": base64.StdEncoding.EncodeToString(res.Output), "exit_code": res.ExitCode,
		"stderr": string(res.Stderr), "seconds": secs,
		"receipt": s.receipt(client, "CMP-1", secs, "CPU-second", cost, bal, map[string]any{
			"wasm_sha256": hex.EncodeToString(wh[:]), "input_sha256": hex.EncodeToString(ih[:]),
			"output_sha256": hex.EncodeToString(oh[:]), "seed": j.Seed, "exit_code": res.ExitCode})}
	if res.Err != "" {
		out["error"] = res.Err
	}
	s.reply(w, 200, out)
}

// okURL allows https only (tests may allow http on this machine with INNERNET_TEST_HTTP=1).
func okURL(u string) bool {
	return strings.HasPrefix(u, "https://") ||
		(os.Getenv("INNERNET_TEST_HTTP") == "1" && strings.HasPrefix(u, "http://127.0.0.1:"))
}
