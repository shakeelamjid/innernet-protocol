package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// cborES256 encodes an ES256 COSE key the way authenticators do.
func cborES256(pub *ecdsa.PublicKey) []byte {
	x, y := make([]byte, 32), make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	out := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}
	out = append(out, x...)
	out = append(out, 0x22, 0x58, 0x20)
	return append(out, y...)
}

func cborEd25519(pub ed25519.PublicKey) []byte {
	out := []byte{0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20}
	return append(out, pub...)
}

func assertion(t *testing.T, sign func([]byte) []byte, challenge []byte, flags byte) *passkeyAuth {
	t.Helper()
	rp := sha256.Sum256([]byte("innernetcorp.com"))
	authData := append(append([]byte{}, rp[:]...), flags, 0, 0, 0, 7)
	client, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": b64u(challenge), "origin": "https://innernetcorp.com"})
	h := sha256.Sum256(client)
	return &passkeyAuth{CredID: "cred1", AuthData: b64u(authData), Client: b64u(client),
		Signature: b64u(sign(append(append([]byte{}, authData...), h[:]...)))}
}

func TestPasskeyAssertionES256AndEd25519(t *testing.T) {
	ch := sha256.Sum256([]byte("offer"))
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key, err := parseCOSE(cborES256(&ek.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	signEC := func(m []byte) []byte { h := sha256.Sum256(m); s, _ := ecdsa.SignASN1(rand.Reader, ek, h[:]); return s }
	if err := verifyAssertion(assertion(t, signEC, ch[:], 0x05), key, ch[:]); err != nil {
		t.Fatalf("valid ES256 assertion refused: %v", err)
	}
	other := sha256.Sum256([]byte("another offer"))
	if err := verifyAssertion(assertion(t, signEC, other[:], 0x05), key, ch[:]); err == nil || !strings.Contains(err.Error(), "different offer") {
		t.Fatalf("assertion for another offer accepted: %v", err)
	}
	if err := verifyAssertion(assertion(t, signEC, ch[:], 0x04), key, ch[:]); err == nil {
		t.Fatal("assertion without user presence accepted")
	}
	a := assertion(t, signEC, ch[:], 0x05)
	a.Signature = b64u(signEC([]byte("something else")))
	if verifyAssertion(a, key, ch[:]) == nil {
		t.Fatal("bad signature accepted")
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ed, err := parseCOSE(cborEd25519(pub))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAssertion(assertion(t, func(m []byte) []byte { return ed25519.Sign(priv, m) }, ch[:], 0x05), ed, ch[:]); err != nil {
		t.Fatalf("valid EdDSA assertion refused: %v", err)
	}
	for _, bad := range [][]byte{nil, {0xa0}, {0xa2, 0x01, 0x02, 0x03, 0x26}, {0xff}} {
		if _, err := parseCOSE(bad); err == nil {
			t.Fatalf("parsed bad COSE % x", bad)
		}
	}
}

func TestSealedPassphraseOpensOnlyHere(t *testing.T) {
	box, _ := newSealBox()
	s, err := sealTo(box.public(), "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := box.open(s); err != nil || got != "correct horse battery staple" {
		t.Fatalf("open: %q %v", got, err)
	}
	other, _ := newSealBox()
	s2, _ := sealTo(other.public(), "x")
	if _, err := box.open(s2); err == nil {
		t.Fatal("opened a passphrase sealed to another machine")
	}
	s2.To = box.public()
	if _, err := box.open(s2); err == nil {
		t.Fatal("opened a passphrase sealed to another key")
	}
}

func TestVerifySetupTrustsOnlyKnownPasskeysLater(t *testing.T) {
	t.Setenv("INNERNET_HOME", t.TempDir())
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	box, _ := newSealBox()
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose := b64u(cborES256(&ek.PublicKey))
	signEC := func(m []byte) []byte { h := sha256.Sum256(m); s, _ := ecdsa.SignASN1(rand.Reader, ek, h[:]); return s }
	make := func(nonce string, provider string) *setupStatus {
		setup := map[string]any{"version": "REG-1-SETUP", "provider": provider, "nonce": nonce, "issued_at": time.Now().Unix(),
			"service": true, "offer": map[string]any{"name": "box", "storage_gib": 10, "prices": map[string]any{"STO-1": "0.0010"}}}
		raw, _ := json.Marshal(setup)
		canon, _ := canonicalRaw(raw)
		sum := sha256.Sum256(append([]byte(setupDomain), canon...))
		a := assertion(t, signEC, sum[:], 0x05)
		a.PublicKey = cose
		return &setupStatus{Status: "submitted", Setup: raw, Auth: a}
	}
	if _, err := verifySetup(make("n0", providerID(priv)), priv, box, false); err != nil {
		t.Fatalf("first passkey (nothing trusted yet) refused: %v", err) // a machine upgraded from 0.6.1
	}
	ws, err := verifySetup(make("n1", providerID(priv)), priv, box, false)
	if err != nil || ws.Offer.StorageGB != 10 || !ws.Service {
		t.Fatalf("known passkey refused: %v", err)
	}
	if _, err := verifySetup(make("n2", strings.Repeat("ab", 32)), priv, box, true); err == nil {
		t.Fatal("setup for another machine accepted")
	}
	rememberSetupNonce("n1")
	if _, err := verifySetup(make("n1", providerID(priv)), priv, box, false); err == nil {
		t.Fatal("replayed setup accepted")
	}
	// A passkey the machine never saw cannot confirm changes through the background service.
	ek2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	st := make("n3", providerID(priv))
	st.Auth.PublicKey = b64u(cborES256(&ek2.PublicKey))
	st.Auth.CredID = "cred2"
	if _, err := verifySetup(st, priv, box, false); err == nil || !strings.Contains(err.Error(), "does not know") {
		t.Fatalf("unknown passkey accepted: %v", err)
	}
	// A registry that changes the offer after the passkey signed it is caught.
	st = make("n4", providerID(priv))
	st.Setup = []byte(strings.Replace(string(st.Setup), `"storage_gib":10`, `"storage_gib":99`, 1))
	if _, err := verifySetup(st, priv, box, false); err == nil {
		t.Fatal("changed offer accepted")
	}
	keepTrusted([]any{})
	if len(loadTrustedPasskeys()) != 0 {
		t.Fatal("removed passkey still trusted")
	}
}
