package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRelayEndToEndST81(t *testing.T) {
	_, relayKeyPriv, _ := ed25519.GenerateKey(nil)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	r := &relayServer{key: relayKeyPriv, attached: map[string]*muxSession{}}
	go func() { _ = r.serve(ln) }()

	_, provKey, _ := ed25519.GenerateKey(nil)
	dir := t.TempDir()
	cfg := &Config{Name: "p", Storage: 1, Prices: map[string]string{"STO-1": "0.001"}, Network: "base-sepolia"}
	s, err := newServer(cfg, provKey, dir, "http://127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	attached := make(chan bool, 4)
	relayPub := hex.EncodeToString(relayKeyPriv.Public().(ed25519.PublicKey))
	go s.attachLoop(relayTarget{Addr: ln.Addr().String(), Key: relayPub}, func(ok bool) { attached <- ok })
	select {
	case ok := <-attached:
		if !ok {
			t.Fatal("attach failed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no attach")
	}

	_, cliKey, _ := ed25519.GenerateKey(nil)
	provID := hex.EncodeToString(provKey.Public().(ed25519.PublicKey))
	for i := 0; i < 3; i++ { // several streams, one after another and reusing nothing
		conn, err := dialViaRelay(ln.Addr().String(), relayKeyPriv.Public().(ed25519.PublicKey), provID, cliKey, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		inner, err := st81Client(conn, cliKey, provKey.Public().(ed25519.PublicKey), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if err := inner.Write(map[string]any{"rid": 1, "method": "GET", "path": "/sto/v1/info", "headers": map[string]any{}}, nil); err != nil {
			t.Fatal(err)
		}
		h, body, err := inner.Read()
		if err != nil {
			t.Fatal(err)
		}
		var info map[string]any
		_ = json.Unmarshal(body, &info)
		if st, _ := intField(h, "status"); st != 200 || info["provider"] != provID {
			t.Fatalf("status %v info %v", h, info)
		}
		inner.Close()
	}
	// A wrong provider pin inside the stream is refused: the relay cannot impersonate the provider.
	conn, err := dialViaRelay(ln.Addr().String(), relayKeyPriv.Public().(ed25519.PublicKey), provID, cliKey, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, other, _ := ed25519.GenerateKey(nil)
	if _, err := st81Client(conn, cliKey, other.Public().(ed25519.PublicKey), 3*time.Second); err == nil {
		t.Fatal("wrong provider pin accepted")
	}
	// Unknown provider: the relay says so.
	_, err = dialViaRelay(ln.Addr().String(), relayKeyPriv.Public().(ed25519.PublicKey), strings.Repeat("ab", 32), cliKey, 3*time.Second)
	if err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("want not connected, got %v", err)
	}
}
