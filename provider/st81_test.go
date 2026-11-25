package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"innernetcorp.com/provider/internal/xcrypto/chacha20poly1305"
)

// RFC 8439 section 2.8.2 test vector for the copied AEAD.
func TestChaCha20Poly1305RFC8439(t *testing.T) {
	key, _ := hex.DecodeString("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	nonce, _ := hex.DecodeString("070000004041424344454647")
	aad, _ := hex.DecodeString("50515253c0c1c2c3c4c5c6c7")
	pt := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	a, _ := chacha20poly1305.New(key)
	ct := a.Seal(nil, nonce, pt, aad)
	if hex.EncodeToString(ct[len(ct)-16:]) != "1ae10b594f09e26a7e902ecbd0600691" {
		t.Fatalf("tag %x", ct[len(ct)-16:])
	}
	if hex.EncodeToString(ct[:16]) != "d31a8d34648e60db7b86afbc53ef7ec2" {
		t.Fatalf("ct %x", ct[:16])
	}
	back, err := a.Open(nil, nonce, ct, aad)
	if err != nil || !bytes.Equal(back, pt) {
		t.Fatal("open failed")
	}
}

func TestST81GoToGo(t *testing.T) {
	_, srvKey, _ := ed25519.GenerateKey(nil)
	_, cliKey, _ := ed25519.GenerateKey(nil)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		s, err := st81Accept(c, srvKey, nil)
		if err != nil {
			done <- err
			return
		}
		h, b, err := s.Read()
		if err == nil {
			err = s.Write(map[string]any{"echo": h["op"]}, append(b, '!'))
		}
		done <- err
	}()
	s, err := st81Dial(ln.Addr().String(), cliKey, srvKey.Public().(ed25519.PublicKey), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Write(map[string]any{"op": "ping"}, []byte("body")); err != nil {
		t.Fatal(err)
	}
	h, b, err := s.Read()
	if err != nil || h["echo"] != "ping" || string(b) != "body!" {
		t.Fatalf("%v %v %q", err, h, b)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// wrong pin is refused
	_, other, _ := ed25519.GenerateKey(nil)
	go func() {
		c, _ := ln.Accept()
		if c != nil {
			_, _ = st81Accept(c, srvKey, nil)
		}
	}()
	if _, err := st81Dial(ln.Addr().String(), cliKey, other.Public().(ed25519.PublicKey), 3*time.Second); err == nil {
		t.Fatal("wrong pin accepted")
	}
}

func TestStrictJSON(t *testing.T) {
	for _, bad := range []string{`{"a":1,"a":2}`, `{"a":1e400}`, `{"a":NaN}`, `{"a":99999999999999999999}`, `[1]`,
		`{"a":` + string(bytes.Repeat([]byte("["), 70)) + string(bytes.Repeat([]byte("]"), 70)) + `}`} {
		if _, err := strictJSONObject([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad[:min(len(bad), 40)])
		}
	}
	if _, err := strictJSONObject([]byte(`{"a":{"b":[1,2,{"c":-9223372036854775808}]},"d":"x"}`)); err != nil {
		t.Fatal(err)
	}
}
