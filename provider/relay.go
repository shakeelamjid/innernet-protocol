package main

// RLY-0: the ST81 relay for providers that cannot accept incoming connections.
//
//   provider --ST81--> relay        {"op":"attach"}            (kept open; the ST81 key IS the provider id)
//   client   --ST81--> relay        {"op":"open","to":<id>}    -> {"ok":true}
//   relay    --> provider           {"op":"open","stream":n}
//   both ways                       {"op":"data","stream":n} + bytes,  {"op":"close","stream":n}
//
// Inside each stream the client runs a second, end-to-end ST81 handshake pinned to the
// provider's key, so the relay only ever forwards encrypted bytes it cannot read or change.
// The relay itself is just this program: `innernet-provider relay`.

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

const relayChunk = 64 << 10 // bytes per data frame

// ---------- multiplexed session (both relay and provider sides use it) ----------

type muxSession struct {
	sess    *st81Session
	wmu     sync.Mutex
	mu      sync.Mutex
	streams map[int64]*streamConn
	closed  chan struct{}
	once    sync.Once
}

func newMux(s *st81Session) *muxSession {
	return &muxSession{sess: s, streams: map[int64]*streamConn{}, closed: make(chan struct{})}
}

func (m *muxSession) write(h map[string]any, body []byte) error {
	m.wmu.Lock()
	defer m.wmu.Unlock()
	return m.sess.Write(h, body)
}

func (m *muxSession) close() {
	m.once.Do(func() {
		close(m.closed)
		m.sess.Close()
		m.mu.Lock()
		for _, s := range m.streams {
			s.remoteClose()
		}
		m.mu.Unlock()
	})
}

func (m *muxSession) add(id int64) *streamConn {
	s := newStreamConn(m, id)
	m.mu.Lock()
	m.streams[id] = s
	m.mu.Unlock()
	return s
}

func (m *muxSession) get(id int64) *streamConn {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.streams[id]
}

func (m *muxSession) drop(id int64) {
	m.mu.Lock()
	delete(m.streams, id)
	m.mu.Unlock()
}

// streamConn is one relayed stream presented as a net.Conn.
type streamConn struct {
	m        *muxSession
	id       int64
	in       chan []byte
	buf      []byte
	dmu      sync.Mutex
	rdl      time.Time
	gone     chan struct{}
	goneOnce sync.Once
	sentEnd  atomic.Bool
}

func newStreamConn(m *muxSession, id int64) *streamConn {
	return &streamConn{m: m, id: id, in: make(chan []byte, 256), gone: make(chan struct{})}
}

func (s *streamConn) deliver(b []byte) {
	select {
	case s.in <- b:
	default: // a peer that does not read: drop the stream rather than buffer without bound
		s.Close()
	}
}

func (s *streamConn) remoteClose() { s.goneOnce.Do(func() { close(s.gone) }) }

func (s *streamConn) Read(p []byte) (int, error) {
	if len(s.buf) > 0 {
		n := copy(p, s.buf)
		s.buf = s.buf[n:]
		return n, nil
	}
	s.dmu.Lock()
	dl := s.rdl
	s.dmu.Unlock()
	var timer <-chan time.Time
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return 0, timeoutErr{}
		}
		t := time.NewTimer(d)
		defer t.Stop()
		timer = t.C
	}
	select {
	case b := <-s.in:
		n := copy(p, b)
		s.buf = b[n:]
		return n, nil
	case <-s.gone:
		select {
		case b := <-s.in:
			n := copy(p, b)
			s.buf = b[n:]
			return n, nil
		default:
		}
		return 0, io.EOF
	case <-timer:
		return 0, timeoutErr{}
	}
}

func (s *streamConn) Write(p []byte) (int, error) {
	select {
	case <-s.gone:
		return 0, net.ErrClosed
	default:
	}
	for off := 0; off < len(p); off += relayChunk {
		end := min(off+relayChunk, len(p))
		if err := s.m.write(map[string]any{"op": "data", "stream": s.id}, p[off:end]); err != nil {
			return off, err
		}
	}
	return len(p), nil
}

func (s *streamConn) Close() error {
	if !s.sentEnd.Swap(true) {
		_ = s.m.write(map[string]any{"op": "close", "stream": s.id}, nil)
	}
	s.remoteClose()
	s.m.drop(s.id)
	return nil
}

func (s *streamConn) SetReadDeadline(t time.Time) error {
	s.dmu.Lock()
	s.rdl = t
	s.dmu.Unlock()
	return nil
}
func (s *streamConn) SetDeadline(t time.Time) error    { return s.SetReadDeadline(t) }
func (s *streamConn) SetWriteDeadline(time.Time) error { return nil }
func (s *streamConn) LocalAddr() net.Addr              { return relayAddr("stream") }
func (s *streamConn) RemoteAddr() net.Addr             { return relayAddr("relay") }

type relayAddr string

func (a relayAddr) Network() string { return "rly0" }
func (a relayAddr) String() string  { return string(a) }

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func intField(h map[string]any, k string) (int64, bool) {
	switch v := h[k].(type) {
	case interface{ Int64() (int64, error) }:
		n, err := v.Int64()
		return n, err == nil
	case float64:
		return int64(v), true
	}
	return 0, false
}

// ---------- the relay server ----------

type relayServer struct {
	key      ed25519.PrivateKey
	mu       sync.Mutex
	attached map[string]*muxSession // provider id -> its session
	nextID   atomic.Int64
	allow    func(id string) bool // which providers may attach (nil: any)
}

func cmdRelay(args []string) error {
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	listen := fs.String("listen", ":9444", "address to accept providers and clients on")
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := relayKey()
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	log.Printf("INNERNET relay (RLY-0 over ST81) on %s, relay key %s", ln.Addr(), hex.EncodeToString(key.Public().(ed25519.PublicKey)))
	r := &relayServer{key: key, attached: map[string]*muxSession{}}
	return r.serve(ln)
}

// relayKey keeps the relay's own identity next to the provider files (relay.key).
func relayKey() (ed25519.PrivateKey, error) {
	p := filepath.Join(home(), "relay.key")
	if raw, err := os.ReadFile(p); err == nil && len(raw) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(raw), nil
	}
	_, k, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(home(), 0o700); err != nil {
		return nil, err
	}
	return k, os.WriteFile(p, k.Seed(), 0o600)
}

func (r *relayServer) serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go r.handle(c)
	}
}

func (r *relayServer) handle(c net.Conn) {
	sess, err := st81Accept(c, r.key, nil)
	if err != nil {
		c.Close()
		return
	}
	sess.Timeout = 30 * time.Second
	h, _, err := sess.Read()
	if err != nil {
		sess.Close()
		return
	}
	switch h["op"] {
	case "attach":
		r.attach(sess)
	case "open":
		to, _ := h["to"].(string)
		r.open(sess, to)
	default:
		sess.Close()
	}
}

func (r *relayServer) attach(sess *st81Session) {
	id := hex.EncodeToString(sess.Peer) // authenticated by ST81: nobody can attach as someone else
	if r.allow != nil && !r.allow(id) {
		_ = sess.Write(map[string]any{"ok": false, "error": "not an applied provider"}, nil)
		sess.Close()
		return
	}
	m := newMux(sess)
	r.mu.Lock()
	if old := r.attached[id]; old != nil {
		old.close()
	}
	r.attached[id] = m
	r.mu.Unlock()
	if err := m.write(map[string]any{"ok": true}, nil); err != nil {
		m.close()
		return
	}
	sess.Timeout = 90 * time.Second // providers ping every 30 s
	for {
		h, body, err := sess.Read()
		if err != nil {
			break
		}
		sid, _ := intField(h, "stream")
		switch h["op"] {
		case "data":
			if s := m.get(sid); s != nil {
				s.deliver(body)
			}
		case "close":
			if s := m.get(sid); s != nil {
				s.remoteClose()
				m.drop(sid)
			}
		case "ping":
			_ = m.write(map[string]any{"op": "pong"}, nil)
		}
	}
	r.mu.Lock()
	if r.attached[id] == m {
		delete(r.attached, id)
	}
	r.mu.Unlock()
	m.close()
}

func (r *relayServer) open(client *st81Session, to string) {
	defer client.Close()
	r.mu.Lock()
	m := r.attached[to]
	r.mu.Unlock()
	if m == nil {
		_ = client.Write(map[string]any{"ok": false, "error": "provider is not connected to this relay"}, nil)
		return
	}
	sid := r.nextID.Add(1)
	s := m.add(sid)
	defer s.Close()
	if err := m.write(map[string]any{"op": "open", "stream": sid}, nil); err != nil {
		_ = client.Write(map[string]any{"ok": false, "error": "provider went away"}, nil)
		return
	}
	if err := client.Write(map[string]any{"ok": true}, nil); err != nil {
		return
	}
	cm := &sync.Mutex{}
	// provider -> client
	go func() {
		buf := make([]byte, relayChunk)
		for {
			n, err := s.Read(buf)
			if n > 0 {
				cm.Lock()
				werr := client.Write(map[string]any{"op": "data"}, buf[:n])
				cm.Unlock()
				if werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		client.Close()
	}()
	// client -> provider
	client.Timeout = 10 * time.Minute
	for {
		h, body, err := client.Read()
		if err != nil || h["op"] != "data" {
			return
		}
		if _, err := s.Write(body); err != nil {
			return
		}
	}
}

// ---------- provider side: attach and serve streams ----------

type relayTarget struct {
	Addr string `json:"addr"` // host:port
	Key  string `json:"key"`  // relay ST81 key, hex
}

// attachLoop keeps this provider attached to its relay and serves every stream it opens.
func (s *server) attachLoop(t relayTarget, onState func(bool)) {
	pin, err := hex.DecodeString(t.Key)
	if err != nil || len(pin) != 32 {
		log.Printf("relay: bad relay key")
		return
	}
	backoff := time.Second
	for {
		err := s.attachOnce(t.Addr, ed25519.PublicKey(pin), onState)
		onState(false)
		log.Printf("relay %s: %v; reconnecting in %s", t.Addr, err, backoff)
		time.Sleep(backoff)
		backoff = min(backoff*2, time.Minute)
	}
}

func (s *server) attachOnce(addr string, pin ed25519.PublicKey, onState func(bool)) error {
	sess, err := st81Dial(addr, s.priv, pin, 10*time.Second)
	if err != nil {
		return err
	}
	m := newMux(sess)
	defer m.close()
	if err := m.write(map[string]any{"op": "attach"}, nil); err != nil {
		return err
	}
	h, _, err := sess.Read()
	if err != nil {
		return err
	}
	if h["ok"] != true {
		return fmt.Errorf("relay refused: %v", h["error"])
	}
	onState(true)
	go func() { // keepalive
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-m.closed:
				return
			case <-t.C:
				if m.write(map[string]any{"op": "ping"}, nil) != nil {
					m.close()
					return
				}
			}
		}
	}()
	sess.Timeout = 90 * time.Second
	for {
		h, body, err := sess.Read()
		if err != nil {
			return err
		}
		sid, _ := intField(h, "stream")
		switch h["op"] {
		case "open":
			st := m.add(sid)
			go func() {
				defer st.Close()
				s.serveST81(st) // the client's own ST81 handshake, end to end, pinned to our key
			}()
		case "data":
			if st := m.get(sid); st != nil {
				st.deliver(body)
			}
		case "close":
			if st := m.get(sid); st != nil {
				st.remoteClose()
				m.drop(sid)
			}
		}
	}
}

var errNoRelay = errors.New("no relay available")

// ---------- client side: a stream through a relay, as a net.Conn ----------

type relayClientConn struct {
	outer *st81Session
	buf   []byte
	rdl   time.Time
	wmu   sync.Mutex
}

// dialViaRelay opens a stream to provider `to` through the relay at addr (pinned relayKey).
// Run st81Client over the result, pinned to the provider's key, for end-to-end ST81.
func dialViaRelay(addr string, relayKey ed25519.PublicKey, to string, key ed25519.PrivateKey, timeout time.Duration) (net.Conn, error) {
	outer, err := st81Dial(addr, key, relayKey, timeout)
	if err != nil {
		return nil, err
	}
	if err := outer.Write(map[string]any{"op": "open", "to": to}, nil); err != nil {
		outer.Close()
		return nil, err
	}
	h, _, err := outer.Read()
	if err != nil || h["ok"] != true {
		outer.Close()
		if err == nil {
			err = fmt.Errorf("relay: %v", h["error"])
		}
		return nil, err
	}
	return &relayClientConn{outer: outer}, nil
}

func (c *relayClientConn) Read(p []byte) (int, error) {
	if len(c.buf) == 0 {
		dl := c.rdl
		if dl.IsZero() {
			dl = time.Now().Add(10 * time.Minute)
		}
		h, body, err := c.outer.readWithin(dl, st81MaxFrame)
		if err != nil {
			return 0, err
		}
		if h["op"] != "data" {
			return 0, io.EOF
		}
		c.buf = body
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *relayClientConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	for off := 0; off < len(p); off += relayChunk {
		if err := c.outer.Write(map[string]any{"op": "data"}, p[off:min(off+relayChunk, len(p))]); err != nil {
			return off, err
		}
	}
	return len(p), nil
}

func (c *relayClientConn) Close() error                       { return c.outer.Close() }
func (c *relayClientConn) SetReadDeadline(t time.Time) error  { c.rdl = t; return nil }
func (c *relayClientConn) SetDeadline(t time.Time) error      { c.rdl = t; return nil }
func (c *relayClientConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *relayClientConn) LocalAddr() net.Addr                { return relayAddr("client") }
func (c *relayClientConn) RemoteAddr() net.Addr               { return relayAddr("relay") }
