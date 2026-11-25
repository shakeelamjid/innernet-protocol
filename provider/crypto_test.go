package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

// RFC 7914 section 11: PBKDF2-HMAC-SHA256 test vector.
func TestPBKDF2RFC7914(t *testing.T) {
	got := hex.EncodeToString(pbkdf2SHA256([]byte("passwd"), []byte("salt"), 1, 64))
	want := "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
	if got != want {
		t.Fatalf("pbkdf2 mismatch\n got %s\nwant %s", got, want)
	}
}

func TestBackupRoundTripAndWrongPassphrase(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 32)
	raw, err := sealBackup(seed, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	got, err := openBackup(raw, "correct horse battery")
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, err := openBackup(raw, "wrong horse battery!"); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	if _, err := sealBackup(seed, "short"); err == nil {
		t.Fatal("short passphrase accepted")
	}
	tampered := strings.Replace(string(raw), `"provider_id": "`, `"provider_id": "00`, 1)
	if _, err := openBackup([]byte(tampered), "correct horse battery"); err == nil {
		t.Fatal("tampered backup accepted")
	}
}

func TestCanonicalMatchesPythonRules(t *testing.T) {
	got, err := canonicalJSON(map[string]any{"b": 1, "a": []any{"x", "é", "\n"}, "c": map[string]any{"z": true, "y": nil}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":["x","` + "\\u00e9" + `","\n"],"b":1,"c":{"y":null,"z":true}}`
	if string(got) != want {
		t.Fatalf("got %s want %s", got, want)
	}
	if _, err := canonicalJSON(map[string]any{"f": 1.5}); err == nil {
		t.Fatal("float accepted in signed payload")
	}
}

func TestDescriptorNeedsPayout(t *testing.T) {
	c := &Config{Name: "p1", Region: "asia-south", Host: "node.example.test", Port: 9443, Network: "base-sepolia",
		Storage: 10, Prices: map[string]string{"STO-1": "0.0010"}}
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	if _, err := buildDescriptor(c, priv); err == nil {
		t.Fatal("descriptor built without payout contract")
	}
	c.Payout = "0x" + strings.Repeat("ab", 20)
	if _, err := buildDescriptor(c, priv); err != nil {
		t.Fatal(err)
	}
}

func TestSanitize(t *testing.T) {
	for in, want := range map[string]string{"My-PC.local": "my-pc.local", "!!!": "provider", "Shakeel's Mac": "shakeel-s-mac"} {
		if got := sanitize(in); got != want {
			t.Fatalf("sanitize(%q)=%q want %q", in, got, want)
		}
	}
}
