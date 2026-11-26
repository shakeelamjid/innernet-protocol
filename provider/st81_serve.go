package main

// One port, two ways in:
//   ST81 (INNERnet's own session protocol) - the client waits for the server to speak
//   HTTP (fallback)                        - the client speaks first
// Each accepted connection gets a short window: bytes from the client mean HTTP,
// silence means ST81, and the provider sends its ST81 challenge.
//
// STO-1 over ST81 (spec 5.9a): one request per frame, answered in order:
//   request  {"rid": n, "method": "PUT", "path": "/sto/v1/...", "headers": {...}} + body
//   response {"rid": n, "status": 200, "headers": {...}} + body
// Requests keep their per-request client signatures, so the same handler serves both
// transports and leases are owned by the same keys either way.

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

var sniffWindow = 300 * time.Millisecond

type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *peekConn) Read(b []byte) (int, error) { return p.r.Read(b) }

// chanListener hands HTTP connections to http.Server.
type chanListener struct {
	addr net.Addr
	ch   chan net.Conn
	once sync.Once
	done chan struct{}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *chanListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *chanListener) Addr() net.Addr { return l.addr }

// serveBoth accepts on ln and routes every connection to ST81 or HTTP.
func (s *server) serveBoth(ln net.Listener, srv *http.Server) error {
	httpLn := &chanListener{addr: ln.Addr(), ch: make(chan net.Conn), done: make(chan struct{})}
	go func() { _ = srv.Serve(httpLn) }()
	defer httpLn.Close()
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.route(c, httpLn)
	}
}

func (s *server) route(c net.Conn, httpLn *chanListener) {
	r := bufio.NewReader(c)
	_ = c.SetReadDeadline(time.Now().Add(sniffWindow))
	_, err := r.Peek(1)
	_ = c.SetReadDeadline(time.Time{})
	if err == nil {
		select {
		case httpLn.ch <- &peekConn{Conn: c, r: r}:
		case <-httpLn.done:
			c.Close()
		}
		return
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		c.Close()
		return
	}
	s.serveST81(c)
}

func (s *server) serveST81(c net.Conn) {
	defer c.Close()
	sess, err := st81Accept(c, s.priv, nil) // public provider: any client key, authenticated
	if err != nil {
		return
	}
	sess.Timeout = 120 * time.Second // idle limit between requests
	first := true
	for {
		h, body, err := sess.Read()
		if err != nil {
			return
		}
		if first && h["op"] == "vpn-connect" { // VPN-1: this session carries one exit connection
			s.serveVPN(sess, h)
			return
		}
		first = false
		status, hdrs, out := s.dispatchFrame(h, body)
		sess.Timeout = 60 * time.Second
		if err := sess.Write(map[string]any{"rid": h["rid"], "status": status, "headers": hdrs}, out); err != nil {
			return
		}
		sess.Timeout = 120 * time.Second
	}
}

// dispatchFrame runs one STO-1 request frame through the same handler HTTP uses.
func (s *server) dispatchFrame(h map[string]any, body []byte) (int, map[string]any, []byte) {
	method, _ := h["method"].(string)
	path, _ := h["path"].(string)
	if method == "" || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, " \r\n") {
		return 400, map[string]any{}, []byte(`{"error":"bad request frame"}`)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.RemoteAddr = "st81"
	if hs, ok := h["headers"].(map[string]any); ok {
		for k, v := range hs {
			if sv, ok := v.(string); ok && len(k) < 64 && len(sv) < 1024 {
				req.Header.Set(k, sv)
			}
		}
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	out := map[string]any{}
	for _, k := range []string{"Content-Type", "X-Innernet-Provider", "X-Innernet-Signature"} {
		if v := rec.Header().Get(k); v != "" {
			out[k] = v
		}
	}
	return rec.Code, out, rec.Body.Bytes()
}
