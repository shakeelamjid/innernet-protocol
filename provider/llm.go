package main

import (
	"archive/zip"
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

// GPU-1: the client brings the model file (GGUF); this provider supplies the GPU, priced per
// GPU-hour while the model is loaded. The engine is llama.cpp's llama-server, bound to 127.0.0.1
// only: clients never reach it directly, every request goes through this provider (signed, paid).

// llamaTag is the llama.cpp release used when no llama-server is installed. The registry may name
// another in /v1/config ("runtimes"); downloads must match GitHub's published SHA-256 digest.
var llamaTag = "b6100"

var ghAPI = "https://api.github.com"

func llmDir(parts ...string) string {
	return filepath.Join(append([]string{home(), "llm"}, parts...)...)
}

// ---------- llama-server ----------

// findLlama returns a llama-server program: INNERNET_LLAMA_SERVER, one on PATH (Homebrew:
// brew install llama.cpp), or the copy this provider downloaded earlier.
func findLlama() string {
	if p := os.Getenv("INNERNET_LLAMA_SERVER"); p != "" {
		return p
	}
	if p, err := exec.LookPath("llama-server"); err == nil {
		return p
	}
	found := ""
	_ = filepath.Walk(llmDir("bin"), func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && (info.Name() == "llama-server" || info.Name() == "llama-server.exe") {
			found = p
		}
		return nil
	})
	return found
}

// llamaAsset chooses the llama.cpp release file for this machine.
func llamaAsset(names []string, gpus []gpuInfo) string {
	nvidia := false
	for _, g := range gpus {
		if g.API == "cuda" {
			nvidia = true
		}
	}
	var want []string
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "darwin/arm64":
		want = []string{"bin-macos-arm64.zip"}
	case "darwin/amd64":
		want = []string{"bin-macos-x64.zip"}
	case "linux/amd64":
		want = []string{"bin-ubuntu-vulkan-x64.zip", "bin-ubuntu-x64.zip"}
	case "linux/arm64":
		want = []string{"bin-ubuntu-arm64.zip"}
	case "windows/amd64":
		if nvidia {
			want = append(want, "bin-win-cuda-12.4-x64.zip", "bin-win-cuda-x64.zip")
		}
		want = append(want, "bin-win-vulkan-x64.zip", "bin-win-cpu-x64.zip")
	case "windows/arm64":
		want = []string{"bin-win-cpu-arm64.zip"}
	}
	for _, w := range want {
		for _, n := range names {
			if strings.HasSuffix(n, w) {
				return n
			}
		}
	}
	return ""
}

// installLlama downloads llama.cpp for this machine and checks it against GitHub's digest.
func installLlama(tag string, gpus []gpuInfo) (string, error) {
	var rel struct {
		Assets []struct {
			Name   string `json:"name"`
			URL    string `json:"browser_download_url"`
			Digest string `json:"digest"`
			Size   int64  `json:"size"`
		} `json:"assets"`
	}
	b, err := fetch(ghAPI+"/repos/ggml-org/llama.cpp/releases/tags/"+tag, 4<<20)
	if err != nil || json.Unmarshal(b, &rel) != nil {
		return "", fmt.Errorf("could not read llama.cpp release %s: %v", tag, err)
	}
	var names []string
	for _, a := range rel.Assets {
		names = append(names, a.Name)
	}
	pick := llamaAsset(names, gpus)
	if pick == "" {
		return "", fmt.Errorf("llama.cpp %s has no build for %s/%s; install llama-server yourself (macOS: brew install llama.cpp)", tag, runtime.GOOS, runtime.GOARCH)
	}
	for _, a := range rel.Assets {
		if a.Name != pick {
			continue
		}
		want := strings.TrimPrefix(a.Digest, "sha256:")
		if len(want) != 64 {
			return "", fmt.Errorf("GitHub gives no checksum for %s; not installing it", pick)
		}
		log.Printf("downloading llama.cpp %s (%s, %d MiB)", tag, pick, a.Size>>20)
		zipBytes, err := fetch(a.URL, 512<<20)
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256(zipBytes)
		if hex.EncodeToString(sum[:]) != want {
			return "", errors.New("llama.cpp download does not match GitHub's checksum; not installing it")
		}
		dir := llmDir("bin", tag)
		if err := unzipTo(zipBytes, dir); err != nil {
			return "", err
		}
		if p := findLlama(); p != "" {
			return p, nil
		}
		return "", errors.New("llama-server not found in the llama.cpp download")
	}
	return "", errors.New("llama.cpp asset vanished")
}

func unzipTo(b []byte, dir string) error {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		name := filepath.Clean(f.Name)
		if strings.HasPrefix(name, "..") || filepath.IsAbs(name) {
			continue
		}
		p := filepath.Join(dir, name)
		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(p, 0o755)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(out, io.LimitReader(rc, 1<<30))
		rc.Close()
		out.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func ensureLlama(gpus []gpuInfo) (string, error) {
	if p := findLlama(); p != "" {
		return p, nil
	}
	return installLlama(llamaTag, gpus)
}

// ---------- model files ----------

var dlClient = &http.Client{Timeout: 0}

// downloadVerified streams url into path, checking SHA-256 and size; the file appears only if it matches.
func downloadVerified(url, path, wantSHA string, maxBytes int64, progress func(int64)) error {
	if fileSHA(path) == wantSHA {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	resp, err := dlClient.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxBytes {
		return fmt.Errorf("file is %d MiB, over the %d MiB limit", resp.ContentLength>>20, maxBytes>>20)
	}
	tmp := path + ".part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	h := sha256.New()
	var n int64
	buf := make([]byte, 1<<20)
	for {
		k, rerr := resp.Body.Read(buf)
		if k > 0 {
			n += int64(k)
			if n > maxBytes {
				f.Close()
				os.Remove(tmp)
				return fmt.Errorf("file is over the %d MiB limit", maxBytes>>20)
			}
			h.Write(buf[:k])
			if _, err := f.Write(buf[:k]); err != nil {
				f.Close()
				os.Remove(tmp)
				return err
			}
			if progress != nil {
				progress(n)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			f.Close()
			os.Remove(tmp)
			return rerr
		}
	}
	f.Close()
	if got := hex.EncodeToString(h.Sum(nil)); got != wantSHA {
		os.Remove(tmp)
		return fmt.Errorf("downloaded file does not match its SHA-256 (got %s…)", got[:12])
	}
	return os.Rename(tmp, path)
}

func fileSHA(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ---------- running llama-server ----------

type llamaProc struct {
	cmd  *exec.Cmd
	port int
	done chan struct{}
}

func freeLocalPort() int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// startLlama runs llama-server on 127.0.0.1 with the model and waits until it answers /health.
func startLlama(bin, model string, ctxSize int, wait time.Duration) (*llamaProc, error) {
	port := freeLocalPort()
	if ctxSize <= 0 {
		ctxSize = 8192
	}
	cmd := exec.Command(bin, "-m", model, "--host", "127.0.0.1", "--port", fmt.Sprint(port),
		"-c", fmt.Sprint(ctxSize), "-ngl", "999")
	cmd.Dir = filepath.Dir(bin)
	logf, _ := os.OpenFile(llmDir("llama-server.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if logf != nil {
		cmd.Stdout, cmd.Stderr = logf, logf
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &llamaProc{cmd: cmd, port: port, done: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(p.done); logf.Close() }()
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		select {
		case <-p.done:
			return nil, errors.New("llama-server stopped while loading the model (see ~/.innernet/provider/llm/llama-server.log)")
		default:
		}
		if r, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port)); err == nil {
			r.Body.Close()
			if r.StatusCode == 200 {
				return p, nil
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	p.stop()
	return nil, errors.New("the model did not load in time")
}

func (p *llamaProc) stop() {
	if p == nil || p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Kill()
	<-p.done
}

func (p *llamaProc) alive() bool {
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

var llmHTTP = &http.Client{Timeout: 10 * time.Minute}

// chat sends an OpenAI-style chat request to llama-server and returns its JSON answer.
func (p *llamaProc) chat(ctx context.Context, req map[string]any) (map[string]any, int, error) {
	body, _ := json.Marshal(req)
	hr, _ := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("http://127.0.0.1:%d/v1/chat/completions", p.port), bytes.NewReader(body))
	hr.Header.Set("Content-Type", "application/json")
	resp, err := llmHTTP.Do(hr)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&out); err != nil {
		return nil, resp.StatusCode, errors.New("the model returned an unreadable answer")
	}
	return out, resp.StatusCode, nil
}

func usageOf(out map[string]any) (int64, int64) {
	u, _ := out["usage"].(map[string]any)
	in, _ := u["prompt_tokens"].(float64)
	o, _ := u["completion_tokens"].(float64)
	return int64(in), int64(o)
}

// cleanChat keeps only the fields a client may set, turns streaming off and bounds the answer length.
func cleanChat(req map[string]any) (map[string]any, int64, error) {
	msgs, ok := req["messages"].([]any)
	if !ok || len(msgs) == 0 || len(msgs) > 256 {
		return nil, 0, errors.New("messages: 1-256 chat messages")
	}
	out := map[string]any{"messages": msgs, "stream": false}
	maxTok := int64(512)
	for _, k := range []string{"max_tokens", "max_completion_tokens"} {
		if v, ok := req[k].(float64); ok && v > 0 {
			maxTok = int64(v)
		}
	}
	if maxTok > 8192 {
		maxTok = 8192
	}
	out["max_tokens"] = maxTok
	for _, k := range []string{"temperature", "top_p", "top_k", "seed", "stop", "presence_penalty", "frequency_penalty",
		"response_format", "min_p", "repeat_penalty"} {
		if v, ok := req[k]; ok {
			out[k] = v
		}
	}
	return out, maxTok, nil
}

// ---------- GPU-1: the client's own model ----------

type gpuSession struct {
	ID, Client, SHA, URL string
	Status               string
	Held                 int64
	MaxSeconds           int
	IdleSeconds          int
	Started              time.Time // billing starts when the model is loaded
	LastUse              time.Time
	proc                 *llamaProc
	release              func()
	done                 bool
	cost                 int64
}

const maxClientModel = 64 << 30

func (s *server) gpuStart(w http.ResponseWriter, client string, body []byte) {
	if !s.cfg.GPU {
		s.fail(w, 404, "this provider does not offer GPU time")
		return
	}
	var req struct {
		URL         string `json:"url"`
		SHA256      string `json:"sha256"`
		MaxSeconds  int    `json:"max_seconds"`
		IdleSeconds int    `json:"idle_seconds"` // end the session after this long without requests (default 900)
		Context     int    `json:"context"`
	}
	if json.Unmarshal(body, &req) != nil || !okURL(req.URL) || len(req.URL) > 2048 ||
		!reHex64.MatchString(req.SHA256) {
		s.fail(w, 400, "session needs url (https, a single .gguf file) and sha256 (64 hex)")
		return
	}
	if req.MaxSeconds <= 0 || req.MaxSeconds > 4*3600 {
		req.MaxSeconds = 3600
	}
	held := micro(fmt.Sprintf("%d/3600", req.MaxSeconds), s.cfg.Prices["GPU-1"])
	if req.IdleSeconds <= 0 || req.IdleSeconds > req.MaxSeconds {
		req.IdleSeconds = min(900, req.MaxSeconds)
	}
	s.gpuMu.Lock()
	open, mine := 0, 0
	for _, g := range s.gpu {
		if !g.done {
			open++
			if g.Client == client {
				mine++
			}
		}
	}
	// Sessions may download while others run, but the line stays short: GPUs × 2 open sessions.
	if open >= 2*max(1, s.cfg.GPUs) || mine >= orInt(s.cfg.PerClient, 2) {
		s.gpuMu.Unlock()
		w.Header().Set("Retry-After", "60")
		s.fail(w, 503, "all GPUs on this provider are in use or booked; try another provider or later")
		return
	}
	if err := s.credits.hold(client, held); err != nil {
		s.gpuMu.Unlock()
		s.fail(w, 402, err.Error())
		return
	}
	id := randHex(32)
	g := &gpuSession{ID: id, Client: client, SHA: req.SHA256, URL: req.URL, Status: "downloading", Held: held,
		MaxSeconds: req.MaxSeconds, IdleSeconds: req.IdleSeconds}
	s.gpu[id] = g
	s.gpuMu.Unlock()
	go s.runGPUSession(g, req.Context)
	s.reply(w, 202, map[string]any{"session": id, "status": g.Status, "held": usdc(held),
		"note": "the model is downloaded and loaded first; billing starts when status is ready"})
}

func (s *server) runGPUSession(g *gpuSession, ctxSize int) {
	set := func(st string) { s.gpuMu.Lock(); g.Status = st; s.gpuMu.Unlock() }
	fail := func(err error) {
		s.gpuMu.Lock()
		g.Status, g.done = "error: "+err.Error(), true
		s.gpuMu.Unlock()
		s.credits.settle(g.Client, g.Held, 0)
	}
	path := llmDir("client", g.SHA+".gguf")
	err := downloadVerified(g.URL, path, g.SHA, maxClientModel, func(n int64) {
		set(fmt.Sprintf("downloading %d MiB", n>>20))
	})
	if err != nil {
		fail(err)
		return
	}
	_ = os.Chtimes(path, time.Now(), time.Now())
	pruneClientModels(40 << 30)
	bin, err := ensureLlama(detectGPUs())
	if err != nil {
		fail(err)
		return
	}
	// Memory for the model: its file, plus about 15 % and the context's working memory.
	info, _ := os.Stat(path)
	need := int(info.Size()>>20)*115/100 + max(ctxSize, 8192)/8
	set("waiting for a free GPU")
	release, err := s.sched.acquire(context.Background(), demand{Client: g.Client, GPU: 1, MemMiB: need}, 15*time.Minute)
	if err != nil {
		fail(err)
		return
	}
	set("loading")
	p, err := startLlama(bin, path, ctxSize, 15*time.Minute)
	if err != nil {
		release()
		fail(err)
		return
	}
	s.gpuMu.Lock()
	g.proc, g.release, g.Started, g.LastUse, g.Status = p, release, s.now(), s.now(), "ready"
	s.gpuMu.Unlock()
	end := time.After(time.Duration(g.MaxSeconds) * time.Second)
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
loop:
	for {
		select {
		case <-end:
			break loop
		case <-p.done:
			break loop
		case <-tick.C:
			s.gpuMu.Lock()
			idle, done := s.now().Sub(g.LastUse) > time.Duration(g.IdleSeconds)*time.Second, g.done
			s.gpuMu.Unlock()
			if idle || done {
				break loop // unused: free the GPU for the next client and stop charging
			}
		}
	}
	s.endGPUSession(g)
}

// endGPUSession stops the model and charges the loaded time; it is safe to call twice.
func (s *server) endGPUSession(g *gpuSession) int64 {
	s.gpuMu.Lock()
	if g.done {
		s.gpuMu.Unlock()
		return g.cost
	}
	g.done = true
	p, started, release := g.proc, g.Started, g.release
	s.gpuMu.Unlock()
	p.stop()
	if release != nil {
		release()
	}
	secs := 0
	if !started.IsZero() {
		secs = int(s.now().Sub(started).Seconds() + 0.999)
	}
	if secs > g.MaxSeconds {
		secs = g.MaxSeconds
	}
	cost := micro(fmt.Sprintf("%d/3600", secs), s.cfg.Prices["GPU-1"])
	s.credits.settle(g.Client, g.Held, cost)
	s.gpuMu.Lock()
	g.cost, g.Status = cost, fmt.Sprintf("ended after %d s", secs)
	s.gpuMu.Unlock()
	return cost
}

// pruneClientModels keeps the cache of clients' model files under limit, removing the least recent.
func pruneClientModels(limit int64) {
	ents, _ := os.ReadDir(llmDir("client"))
	type f struct {
		p string
		t time.Time
		n int64
	}
	var fs []f
	var total int64
	for _, e := range ents {
		if info, err := e.Info(); err == nil && !e.IsDir() {
			fs = append(fs, f{llmDir("client", e.Name()), info.ModTime(), info.Size()})
			total += info.Size()
		}
	}
	sort.Slice(fs, func(i, j int) bool { return fs[i].t.Before(fs[j].t) })
	for i := 0; total > limit && i < len(fs)-1; i++ {
		_ = os.Remove(fs[i].p)
		total -= fs[i].n
	}
}

var reGPUPath = regexp.MustCompile(`^/gpu/v1/sessions/([0-9a-f]{32})(/chat/completions)?$`)

func (s *server) gpuSessionRoute(w http.ResponseWriter, r *http.Request, client, id, sub string, body []byte) {
	s.gpuMu.Lock()
	g := s.gpu[id]
	s.gpuMu.Unlock()
	if g == nil || g.Client != client {
		s.fail(w, 404, "no such session")
		return
	}
	switch {
	case sub == "" && r.Method == "GET":
		s.gpuMu.Lock()
		st := map[string]any{"session": id, "status": g.Status, "max_seconds": g.MaxSeconds}
		if !g.Started.IsZero() {
			st["loaded_seconds"] = int(s.now().Sub(g.Started).Seconds())
		}
		s.gpuMu.Unlock()
		s.reply(w, 200, st)
	case sub == "" && r.Method == "DELETE":
		cost := s.endGPUSession(g)
		s.gpuMu.Lock()
		st := g.Status
		s.gpuMu.Unlock()
		bal := s.credits.balance(client)
		secs := strings.TrimSuffix(strings.TrimPrefix(st, "ended after "), " s")
		s.reply(w, 200, map[string]any{"session": id, "status": st,
			"receipt": s.receipt(client, "GPU-1", secs, "GPU-second", cost, bal, map[string]any{"session": id, "model_sha256": g.SHA})})
	case sub == "/chat/completions" && r.Method == "POST":
		s.gpuMu.Lock()
		p, ready := g.proc, g.Status == "ready"
		s.gpuMu.Unlock()
		if !ready || p == nil {
			s.fail(w, 409, "session is not ready ("+g.Status+")")
			return
		}
		var req map[string]any
		if json.Unmarshal(body, &req) != nil {
			s.fail(w, 400, "body must be an OpenAI-style chat request")
			return
		}
		clean, _, err := cleanChat(req)
		if err != nil {
			s.fail(w, 400, err.Error())
			return
		}
		s.gpuMu.Lock()
		g.LastUse = s.now()
		s.gpuMu.Unlock()
		out, code, err := p.chat(context.Background(), clean)
		s.gpuMu.Lock()
		g.LastUse = s.now()
		s.gpuMu.Unlock()
		if err != nil || code != 200 {
			s.fail(w, 502, "the model failed")
			return
		}
		in, o := usageOf(out)
		s.stats.add("tokens", in+o)
		out["model"] = g.SHA
		s.reply(w, 200, out)
	default:
		s.fail(w, 405, "method not allowed")
	}
}

func randHex(n int) string {
	b := make([]byte, n/2)
	_, _ = crand.Read(b)
	return hex.EncodeToString(b)
}

// stopGPUSessions ends every running session (charging its loaded time) when the provider stops.
func (s *server) stopGPUSessions() {
	s.gpuMu.Lock()
	var open []*gpuSession
	for _, g := range s.gpu {
		if !g.done {
			open = append(open, g)
		}
	}
	s.gpuMu.Unlock()
	for _, g := range open {
		s.endGPUSession(g)
	}
}
