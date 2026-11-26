package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// STO-1 storage service over HTTP. Requests are signed by the client's Ed25519 key;
// JSON responses are signed by this provider's key, so both sides keep evidence.
const (
	stoRequestDomain  = "INNERnet/STO-1/request\x00"
	stoResponseDomain = "INNERnet/STO-1/response\x00"
	ticketDomain      = "INNERnet/PAY-1/service-ticket\x00"
	maxChunk          = 2 << 20
	holdbackBps       = 2000 // clients may hold back 20 % of each storage payment until the next proof
	clockSkew         = 300
)

var (
	reHex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)
	reHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reTx    = regexp.MustCompile(`^0x[0-9a-fA-F]{64}$`)
	usdcBy  = map[string]string{"eip155:84532": "0x036CbD53842c5426634e7929541eC2318f3dCF7e", "eip155:8453": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"}
)

const transferTopic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

type server struct {
	cfg     *Config
	priv    ed25519.PrivateKey
	data    string
	rpc     string
	mu      sync.Mutex
	seen    map[string]int64 // replay cache: signature -> expiry
	used    map[string]bool  // payment transactions already credited
	usedLog string
	now     func() time.Time
	stats   counters
	started time.Time
	pathUp  atomic.Bool

	credits  *ledger
	meter    *bandwidthMeter
	terms    clientTerms
	sched    *scheduler
	stoSlots chan struct{}

	keeperNudge chan struct{} // wakes the port keeper (network change, registry could not reach us)
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", "", "address to listen on (default :<port from setup>)")
	dataDir := fs.String("data", "", "where to keep stored pieces (default ~/.innernet/provider/data)")
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
	s, err := newServer(c, priv, orDefault(*dataDir, filepath.Join(home(), "data")),
		rpcFor(c.Network))
	if err != nil {
		return err
	}
	if c.PortMap != "" && os.Getenv("INNERNET_NO_PORTMAP") != "1" {
		go keepPortOpen(c.Port)
	}
	s.startReachability(registryURL(c))
	go s.terms.keepFresh(registryURL(c))
	s.prepareGPU()
	go func() {
		for range time.Tick(5 * time.Second) {
			s.sched.kick() // the owner's own memory use changes; waiting work may fit now
		}
	}()
	if os.Getenv("INNERNET_NO_PRESENCE") != "1" {
		go s.presenceLoop(registryURL(c))
	}
	addr := orDefault(*listen, fmt.Sprintf(":%d", c.Port))
	log.Printf("innernet-provider %s serving STO-1 over ST81 and HTTP on %s (provider %s)", version, addr, providerID(priv))
	srv := &http.Server{Handler: s, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second,
		WriteTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	ln, err := listenRetry(addr)
	if err != nil {
		return err
	}
	go updateLoop(func() {
		s.sched.drain(30 * time.Minute) // let running jobs finish first
		_ = ln.Close()
	})
	if os.Getenv("INNERNET_NO_PRESENCE") != "1" {
		// Keep the port open; fall back to the HTTPS tunnel and come back by itself.
		go s.portKeeper(registryURL(c), s.keeperNudge, func() {
			s.sched.drain(2 * time.Minute)
			if runtime.GOOS == "windows" {
				_ = ln.Close()
			}
			log.Printf("restarting with the new connection path")
			restartSelf()
		})
		// Changes made on the website: join, apply after the passkey check, restart with them.
		go s.setupWatch(registryURL(c), func() {
			s.sched.drain(30 * time.Minute)
			if runtime.GOOS == "windows" {
				_ = ln.Close()
			}
			log.Printf("restarting with the settings chosen on the website")
			restartSelf()
		})
	}
	return s.serveBoth(ln, srv)
}

func newServer(c *Config, priv ed25519.PrivateKey, data, rpc string) (*server, error) {
	if err := os.MkdirAll(data, 0o700); err != nil {
		return nil, err
	}
	s := &server{cfg: c, priv: priv, data: data, rpc: rpc, seen: map[string]int64{}, used: map[string]bool{},
		usedLog: filepath.Join(data, "payments.log"), now: time.Now, started: time.Now(),
		credits: openLedger(data), meter: openMeter(data), sched: newScheduler(c, totalMemoryMiB()), stoSlots: make(chan struct{}, 64), keeperNudge: make(chan struct{}, 1),
	}
	if raw, err := os.ReadFile(s.usedLog); err == nil {
		for _, l := range strings.Split(string(raw), "\n") {
			if f := strings.Fields(l); len(f) > 0 {
				s.used[strings.ToLower(f[0])] = true
			}
		}
	}
	return s, nil
}

// ---------- plumbing ----------

func (s *server) reply(w http.ResponseWriter, code int, v any) {
	body, _ := json.Marshal(v)
	sig := ed25519.Sign(s.priv, append([]byte(stoResponseDomain), body...))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Innernet-Provider", providerID(s.priv))
	w.Header().Set("X-Innernet-Signature", hex.EncodeToString(sig))
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

func (s *server) fail(w http.ResponseWriter, code int, msg string) {
	s.reply(w, code, map[string]string{"error": msg})
}

// requestMessage is what clients sign: domain || method \n path \n sha256(body) \n time \n nonce.
// The random nonce makes two identical honest requests in the same second distinct.
func requestMessage(method, path string, body []byte, ts, nonce string) []byte {
	sum := sha256.Sum256(body)
	return []byte(stoRequestDomain + method + "\n" + path + "\n" + hex.EncodeToString(sum[:]) + "\n" + ts + "\n" + nonce)
}

func (s *server) authenticate(r *http.Request, body []byte) (string, error) {
	client := r.Header.Get("X-Innernet-Client")
	ts := r.Header.Get("X-Innernet-Time")
	sigHex := r.Header.Get("X-Innernet-Signature")
	nonce := r.Header.Get("X-Innernet-Nonce")
	if !reHex64.MatchString(client) || len(sigHex) != 128 || !reHex32.MatchString(nonce) {
		return "", errors.New("missing or malformed signature headers")
	}
	t, err := strconv.ParseInt(ts, 10, 64)
	now := s.now().Unix()
	if err != nil || t < now-clockSkew || t > now+clockSkew {
		return "", errors.New("request time is too far from the provider's clock")
	}
	pub, _ := hex.DecodeString(client)
	sig, err := hex.DecodeString(sigHex)
	if err != nil || !ed25519.Verify(pub, requestMessage(r.Method, r.URL.Path, body, ts, nonce), sig) {
		return "", errors.New("bad request signature")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, exp := range s.seen {
		if exp < now {
			delete(s.seen, k)
		}
	}
	if _, dup := s.seen[sigHex]; dup {
		return "", errors.New("replayed request")
	}
	s.seen[sigHex] = now + 2*clockSkew
	return client, nil
}

func (s *server) leaseDir(lease string) string { return filepath.Join(s.data, lease) }

// owner returns the lease owner, creating the lease for client if it does not exist and create is set.
func (s *server) owner(lease, client string, create bool) error {
	p := filepath.Join(s.leaseDir(lease), "owner")
	raw, err := os.ReadFile(p)
	if err == nil {
		if strings.TrimSpace(string(raw)) != client {
			return errors.New("this lease belongs to another client")
		}
		return nil
	}
	if !create {
		return errors.New("no such lease")
	}
	if err := os.MkdirAll(s.leaseDir(lease), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(client+"\n"), 0o600)
}

func (s *server) usedBytes() int64 {
	var total int64
	_ = filepath.WalkDir(s.data, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".chunk") {
			if info, e := d.Info(); e == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return total
}

// ---------- routes ----------

var reChunkPath = regexp.MustCompile(`^/sto/v1/leases/([0-9a-f]{32})/objects/([0-9a-f]{32})/chunks/([0-9]{1,6})$`)
var reLeasePath = regexp.MustCompile(`^/sto/v1/leases/([0-9a-f]{32})(/challenge|/pay)?$`)

var reReach = regexp.MustCompile(`^/reach/([0-9a-f]{32})$`)

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok\n"))
		return
	}
	if m := reReach.FindStringSubmatch(r.URL.Path); m != nil && r.Method == "GET" {
		// Reachability test from the registry: echo its random nonce (nothing else is revealed).
		_, _ = w.Write([]byte(m[1]))
		return
	}
	if r.URL.Path == "/sto/v1/info" && r.Method == "GET" {
		s.reply(w, 200, s.info())
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxChunk+1))
	if err != nil || len(body) > maxChunk {
		s.fail(w, 413, "request too large")
		return
	}
	if m := reChunkPath.FindStringSubmatch(r.URL.Path); m != nil {
		s.stats.add("requests", 1)
		client, err := s.authenticate(r, body)
		if err != nil {
			s.fail(w, 401, err.Error())
			return
		}
		// Storage has its own pool, so compute load never delays it.
		select {
		case s.stoSlots <- struct{}{}:
		case <-time.After(10 * time.Second):
			w.Header().Set("Retry-After", "5")
			s.fail(w, 503, "busy; try again")
			return
		}
		s.chunk(w, r, client, m[1], m[2], m[3], body)
		<-s.stoSlots
		return
	}
	if m := reLeasePath.FindStringSubmatch(r.URL.Path); m != nil {
		client, err := s.authenticate(r, body)
		if err != nil {
			s.fail(w, 401, err.Error())
			return
		}
		switch {
		case m[2] == "/challenge" && r.Method == "POST":
			s.challenge(w, client, m[1], body)
		case m[2] == "/pay" && r.Method == "POST":
			s.pay(w, client, m[1], body)
		case m[2] == "" && r.Method == "DELETE":
			if err := s.owner(m[1], client, false); err != nil {
				s.fail(w, 404, err.Error())
				return
			}
			_ = os.RemoveAll(s.leaseDir(m[1]))
			s.reply(w, 200, map[string]any{"deleted": m[1]})
		default:
			s.fail(w, 405, "method not allowed")
		}
		return
	}
	if s.computeRoute(w, r, body) {
		return
	}
	s.fail(w, 404, "not found")
}

// computeRoute serves CMP-1 (CPU) and GPU-1 (GPU); every request is signed by the client.
func (s *server) computeRoute(w http.ResponseWriter, r *http.Request, body []byte) bool {
	p := r.URL.Path
	known := p == "/cmp/v1/credit" || p == "/cmp/v1/balance" || p == "/cmp/v1/jobs" || p == "/gpu/v1/jobs"
	if !known {
		return false
	}
	client, err := s.authenticate(r, body)
	if err != nil {
		s.fail(w, 401, err.Error())
		return true
	}
	s.stats.add("requests", 1)
	switch {
	case p == "/cmp/v1/credit" && r.Method == "POST":
		s.credit(w, client, body)
	case p == "/cmp/v1/balance" && r.Method == "GET":
		s.reply(w, 200, map[string]any{"balance": usdc(s.credits.balance(client)), "asset": "USDC"})
	case p == "/cmp/v1/jobs" && r.Method == "POST":
		s.cpuJob(w, client, body)
	case p == "/gpu/v1/jobs" && r.Method == "POST":
		s.gpuJobHandler(w, client, body)
	default:
		s.fail(w, 405, "method not allowed")
	}
	return true
}

func (s *server) info() map[string]any {
	limit := int64(s.cfg.Storage) << 30
	used := s.usedBytes()
	return map[string]any{"provider": providerID(s.priv), "name": s.cfg.Name, "services": toAny(s.cfg.services()),
		"prices": s.cfg.Prices, "payout": s.cfg.Payout, "network": networks[s.cfg.Network],
		"storage_free_bytes": max(0, limit-used), "version": version, "time": s.now().Unix()}
}

func (s *server) chunk(w http.ResponseWriter, r *http.Request, client, lease, object, idx string, body []byte) {
	path := filepath.Join(s.leaseDir(lease), object, idx+".chunk")
	switch r.Method {
	case "PUT":
		if s.cfg.Storage <= 0 {
			s.fail(w, 403, "this provider does not offer storage")
			return
		}
		if len(body) == 0 {
			s.fail(w, 400, "empty chunk")
			return
		}
		if s.usedBytes()+int64(len(body)) > int64(s.cfg.Storage)<<30 {
			s.fail(w, 507, "provider storage is full")
			return
		}
		if err := s.owner(lease, client, true); err != nil {
			s.fail(w, 403, err.Error())
			return
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			s.fail(w, 500, "could not store")
			return
		}
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, body, 0o600); err != nil || os.Rename(tmp, path) != nil {
			s.fail(w, 500, "could not store")
			return
		}
		root, n := stoRoot(body)
		s.reply(w, 201, map[string]any{"lease": lease, "object": object, "index": idx, "root": hex.EncodeToString(root), "blocks": n, "bytes": len(body)})
	case "GET":
		if err := s.owner(lease, client, false); err != nil {
			s.fail(w, 404, err.Error())
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			s.fail(w, 404, "no such chunk")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(data)
		s.stats.add("served", int64(len(data)))
	default:
		s.fail(w, 405, "method not allowed")
	}
}

func (s *server) challenge(w http.ResponseWriter, client, lease string, body []byte) {
	if err := s.owner(lease, client, false); err != nil {
		s.fail(w, 404, err.Error())
		return
	}
	var req struct {
		Object string `json:"object"`
		Index  int    `json:"index"`
		Block  int    `json:"block"`
	}
	if json.Unmarshal(body, &req) != nil || !reHex32.MatchString(req.Object) || req.Index < 0 {
		s.fail(w, 400, "challenge needs object, index and block")
		return
	}
	data, err := os.ReadFile(filepath.Join(s.leaseDir(lease), req.Object, strconv.Itoa(req.Index)+".chunk"))
	if err != nil {
		s.fail(w, 404, "no such chunk")
		return
	}
	block, path, ok := stoProve(data, req.Block)
	if !ok {
		s.fail(w, 400, "block out of range")
		return
	}
	hexPath := make([]any, len(path))
	for i, p := range path {
		hexPath[i] = hex.EncodeToString(p)
	}
	s.stats.add("challenges", 1)
	s.reply(w, 200, map[string]any{"lease": lease, "object": req.Object, "index": req.Index, "block": req.Block,
		"data": hex.EncodeToString(block), "path": hexPath, "time": s.now().Unix()})
}

// pay checks an on-chain USDC transfer to this provider's payout contract and returns a signed PAY-1 ticket.
func (s *server) pay(w http.ResponseWriter, client, lease string, body []byte) {
	if err := s.owner(lease, client, false); err != nil {
		s.fail(w, 404, err.Error())
		return
	}
	var req struct {
		Units    string `json:"units"`
		Tx       string `json:"tx"`
		Terms    string `json:"terms"`
		Held     int64  `json:"held"`     // base units the client holds back this period (at most 20 %)
		Released int64  `json:"released"` // base units held back last period, paid now that a new proof passed
	}
	if json.Unmarshal(body, &req) != nil || !reTx.MatchString(req.Tx) || !reDecimal.MatchString(req.Units) ||
		req.Held < 0 || req.Released < 0 {
		s.fail(w, 400, "pay needs units (decimal GiB-days) and tx (0x + 64 hex)")
		return
	}
	if err := s.checkClientTerms(req.Terms); err != nil {
		s.fail(w, 412, err.Error())
		return
	}
	heldPath := filepath.Join(s.leaseDir(lease), "held")
	outstanding := int64(0)
	if b, err := os.ReadFile(heldPath); err == nil {
		outstanding, _ = strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	}
	if req.Released != outstanding {
		s.fail(w, 402, fmt.Sprintf("release the %d base units held back last period with this payment", outstanding))
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
	need, err := owed(req.Units, s.cfg.Prices["STO-1"])
	if err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	paid, err := s.paidTo(tx)
	if err != nil {
		s.fail(w, 402, err.Error())
		return
	}
	// Holdback (spec 4.5): at most 20 % of this period, rounded up.
	maxHeld := new(big.Int).Div(new(big.Int).Add(new(big.Int).Mul(need, big.NewInt(holdbackBps)), big.NewInt(9999)), big.NewInt(10000))
	if big.NewInt(req.Held).Cmp(maxHeld) > 0 {
		s.fail(w, 402, fmt.Sprintf("at most %s base units may be held back this period", maxHeld))
		return
	}
	due := new(big.Int).Add(new(big.Int).Sub(need, big.NewInt(req.Held)), big.NewInt(req.Released))
	if paid.Cmp(due) < 0 {
		s.fail(w, 402, fmt.Sprintf("payment too small: %s base units, %s due", paid, due))
		return
	}
	s.mu.Lock()
	if s.used[tx] {
		s.mu.Unlock()
		s.fail(w, 409, "this payment was already used")
		return
	}
	s.used[tx] = true
	f, err := os.OpenFile(s.usedLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		fmt.Fprintf(f, "%s %s %s %s %d held=%d released=%d terms=%s\n", tx, client, lease, req.Units, s.now().Unix(),
			req.Held, req.Released, req.Terms)
		f.Close()
	}
	_ = os.WriteFile(heldPath, []byte(strconv.FormatInt(req.Held, 10)+"\n"), 0o600)
	s.mu.Unlock()
	payload := map[string]any{"version": "PAY-1-TICKET", "provider": providerID(s.priv), "client": client,
		"service": "STO-1", "lease": lease, "units": req.Units, "unit": "GiB-day", "payment_tx": req.Tx,
		"expires_at": s.now().Unix() + 30*86400, "held": req.Held, "released": req.Released, "terms": req.Terms}
	sig, err := signCanonical(s.priv, ticketDomain, payload)
	if err != nil {
		s.fail(w, 500, "could not sign ticket")
		return
	}
	s.stats.add("payments", 1)
	s.reply(w, 200, map[string]any{"payload": payload, "signature": sig})
}

// owed returns units × price in USDC base units (6 decimals), rounded up.
func owed(units, price string) (*big.Int, error) {
	u, ok1 := new(big.Rat).SetString(units)
	p, ok2 := new(big.Rat).SetString(price)
	if !ok1 || !ok2 {
		return nil, errors.New("bad units or price")
	}
	v := new(big.Rat).Mul(new(big.Rat).Mul(u, p), big.NewRat(1_000_000, 1))
	q, r := new(big.Int).QuoRem(v.Num(), v.Denom(), new(big.Int))
	if r.Sign() > 0 {
		q.Add(q, big.NewInt(1))
	}
	return q, nil
}

// paidTo sums USDC transferred to this provider's payout contract in a successful transaction.
func (s *server) paidTo(tx string) (*big.Int, error) {
	network := networks[s.cfg.Network]
	usdc := strings.ToLower(usdcBy[network])
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionReceipt", "params": []any{tx}})
	resp, err := httpClient.Post(s.rpc, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("could not check the payment on-chain; try again")
	}
	defer resp.Body.Close()
	var out struct {
		Result *struct {
			Status string `json:"status"`
			Logs   []struct {
				Address string   `json:"address"`
				Topics  []string `json:"topics"`
				Data    string   `json:"data"`
			} `json:"logs"`
		} `json:"result"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out) != nil || out.Result == nil {
		return nil, errors.New("payment transaction not found (yet)")
	}
	if out.Result.Status != "0x1" {
		return nil, errors.New("payment transaction failed")
	}
	payTopic := "0x" + strings.Repeat("0", 24) + strings.ToLower(strings.TrimPrefix(s.cfg.Payout, "0x"))
	total := new(big.Int)
	for _, l := range out.Result.Logs {
		if strings.ToLower(l.Address) != usdc || len(l.Topics) != 3 || strings.ToLower(l.Topics[0]) != transferTopic ||
			strings.ToLower(l.Topics[2]) != payTopic {
			continue
		}
		v, ok := new(big.Int).SetString(strings.TrimPrefix(l.Data, "0x"), 16)
		if ok {
			total.Add(total, v)
		}
	}
	if total.Sign() == 0 {
		return nil, errors.New("no USDC transfer to this provider's payout contract in that transaction")
	}
	if err := s.claimTx(network, tx); err != nil {
		return nil, err
	}
	return total, nil
}

// claimTx registers a payment with the registry before it is credited here. Machines of one owner can
// share a payout contract; the registry lets only the first of them credit a given transaction.
func (s *server) claimTx(network, tx string) error {
	if os.Getenv("INNERNET_NO_TX_CLAIM") == "1" {
		return nil
	}
	_, err := signedIntent(registryURL(s.cfg), s.priv, "tx-claim", network+":"+strings.ToLower(tx))
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "another machine") {
		return errors.New("this payment was already credited on another machine")
	}
	return fmt.Errorf("could not register the payment with the registry (%v); try again", err)
}

// rpcFor is the JSON-RPC endpoint for the payout network (INNERNET_RPC overrides it).
func rpcFor(network string) string {
	if v := os.Getenv("INNERNET_RPC"); v != "" {
		return v
	}
	if network == "base" {
		return "https://mainnet.base.org"
	}
	return "https://sepolia.base.org"
}

// keepPortOpen renews the router mapping every 20 minutes (it is asked for an hour).
func keepPortOpen(port int) {
	for {
		if m, err := openPort(port); err != nil {
			log.Printf("router port mapping: %v", err)
		} else {
			log.Printf("router port %d open (%s)", port, m.Method)
		}
		time.Sleep(20 * time.Minute)
	}
}

// listenRetry waits up to 15 s for the port: after an update on Windows the old process may still hold it.
func listenRetry(addr string) (net.Listener, error) {
	var err error
	for i := 0; i < 15; i++ {
		var ln net.Listener
		if ln, err = net.Listen("tcp", addr); err == nil {
			return ln, nil
		}
		time.Sleep(time.Second)
	}
	return nil, err
}
