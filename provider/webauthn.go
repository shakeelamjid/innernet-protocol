package main

// The machine checks the owner's passkey itself before it signs an offer chosen on the website.
// The registry passes on what the passkey signed (a WebAuthn assertion); a registry that changed
// the offer, or a stolen web session without the passkey, cannot produce a valid one.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
)

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unb64u(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// ---- a small CBOR reader, enough for COSE public keys ----

type cborReader struct {
	b []byte
	i int
}

func (r *cborReader) head() (major byte, arg uint64, err error) {
	if r.i >= len(r.b) {
		return 0, 0, errors.New("cbor: short")
	}
	c := r.b[r.i]
	r.i++
	major, info := c>>5, c&0x1f
	switch {
	case info < 24:
		return major, uint64(info), nil
	case info <= 27:
		n := 1 << (info - 24)
		if r.i+n > len(r.b) {
			return 0, 0, errors.New("cbor: short")
		}
		for _, x := range r.b[r.i : r.i+n] {
			arg = arg<<8 | uint64(x)
		}
		r.i += n
		return major, arg, nil
	}
	return 0, 0, errors.New("cbor: unsupported")
}

// value reads one item: int64, []byte, string, map[int64]any, []any or bool.
func (r *cborReader) value(depth int) (any, error) {
	if depth > 4 {
		return nil, errors.New("cbor: too deep")
	}
	major, arg, err := r.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case 0:
		if arg > 1<<62 {
			return nil, errors.New("cbor: int too large")
		}
		return int64(arg), nil
	case 1:
		if arg > 1<<62 {
			return nil, errors.New("cbor: int too large")
		}
		return -1 - int64(arg), nil
	case 2, 3:
		if arg > uint64(len(r.b)-r.i) {
			return nil, errors.New("cbor: short")
		}
		v := r.b[r.i : r.i+int(arg)]
		r.i += int(arg)
		if major == 3 {
			return string(v), nil
		}
		return v, nil
	case 4:
		if arg > 64 {
			return nil, errors.New("cbor: array too long")
		}
		out := make([]any, 0, arg)
		for k := uint64(0); k < arg; k++ {
			v, err := r.value(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case 5:
		if arg > 32 {
			return nil, errors.New("cbor: map too long")
		}
		out := map[int64]any{}
		for k := uint64(0); k < arg; k++ {
			kv, err := r.value(depth + 1)
			if err != nil {
				return nil, err
			}
			v, err := r.value(depth + 1)
			if err != nil {
				return nil, err
			}
			if ki, ok := kv.(int64); ok {
				out[ki] = v
			}
		}
		return out, nil
	case 7:
		switch arg {
		case 20:
			return false, nil
		case 21:
			return true, nil
		}
	}
	return nil, errors.New("cbor: unsupported item")
}

// coseKey is a passkey's public key and the algorithm it signs with.
type coseKey struct {
	alg int64
	pub crypto.PublicKey
}

func parseCOSE(raw []byte) (*coseKey, error) {
	r := &cborReader{b: raw}
	v, err := r.value(0)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[int64]any)
	if !ok {
		return nil, errors.New("cose: not a map")
	}
	kty, _ := m[1].(int64)
	alg, _ := m[3].(int64)
	bytesAt := func(k int64) []byte { b, _ := m[k].([]byte); return b }
	switch {
	case kty == 2 && alg == -7: // EC2, ES256
		if crv, _ := m[-1].(int64); crv != 1 {
			return nil, errors.New("cose: only P-256")
		}
		x, y := bytesAt(-2), bytesAt(-3)
		if len(x) != 32 || len(y) != 32 {
			return nil, errors.New("cose: bad EC point")
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, errors.New("cose: point not on curve")
		}
		return &coseKey{alg, pub}, nil
	case kty == 1 && alg == -8: // OKP, EdDSA
		x := bytesAt(-2)
		if crv, _ := m[-1].(int64); crv != 6 || len(x) != 32 {
			return nil, errors.New("cose: only Ed25519")
		}
		return &coseKey{alg, ed25519.PublicKey(x)}, nil
	case kty == 3 && alg == -257: // RSA, RS256
		n, e := bytesAt(-1), bytesAt(-2)
		if len(n) < 256 || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("cose: bad RSA key")
		}
		return &coseKey{alg, &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}}, nil
	}
	return nil, fmt.Errorf("cose: unsupported key (kty %d, alg %d)", kty, alg)
}

func (k *coseKey) verify(msg, sig []byte) bool {
	switch pub := k.pub.(type) {
	case *ecdsa.PublicKey:
		h := sha256.Sum256(msg)
		return ecdsa.VerifyASN1(pub, h[:], sig)
	case ed25519.PublicKey:
		return ed25519.Verify(pub, msg, sig)
	case *rsa.PublicKey:
		h := sha256.Sum256(msg)
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig) == nil
	}
	return false
}

// passkeyAuth is a WebAuthn assertion as the registry passes it on.
type passkeyAuth struct {
	CredID    string `json:"cred_id"`
	PublicKey string `json:"public_key"` // COSE, base64url
	AuthData  string `json:"authenticator_data"`
	Client    string `json:"client_data"`
	Signature string `json:"signature"`
}

// verifyAssertion checks that the passkey signed challenge: the signature over
// authenticatorData || SHA-256(clientDataJSON), the challenge inside clientDataJSON, and that
// the person was present. The relying party is whatever the passkey was made for; a passkey
// only ever signs for its own website, so the challenge is what binds it to this offer.
func verifyAssertion(a *passkeyAuth, key *coseKey, challenge []byte) error {
	authData, err1 := unb64u(a.AuthData)
	client, err2 := unb64u(a.Client)
	sig, err3 := unb64u(a.Signature)
	if err1 != nil || err2 != nil || err3 != nil || len(authData) < 37 {
		return errors.New("passkey confirmation is malformed")
	}
	var cd struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}
	if err := json.Unmarshal(client, &cd); err != nil || cd.Type != "webauthn.get" {
		return errors.New("passkey confirmation is not a sign-in")
	}
	if cd.Challenge != b64u(challenge) {
		return errors.New("the passkey confirmed a different offer")
	}
	if authData[32]&0x01 == 0 {
		return errors.New("passkey confirmation without the person present")
	}
	_ = binary.BigEndian.Uint32(authData[33:37]) // sign counter: the registry tracks it
	h := sha256.Sum256(client)
	if !key.verify(append(append([]byte{}, authData...), h[:]...), sig) {
		return errors.New("the passkey signature does not verify")
	}
	return nil
}

// ---- passkeys this machine trusts ----
//
// The machine learns a passkey's public key when the person confirms a setup while its own
// terminal is open (they are at the machine), and keeps it. Changes that arrive later through the
// background service must be confirmed with one of these.

func trustedPasskeysPath() string { return filepath.Join(home(), "passkeys.json") }

func loadTrustedPasskeys() map[string]string {
	out := map[string]string{}
	if raw, err := os.ReadFile(trustedPasskeysPath()); err == nil {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}

func trustPasskey(credID, cose string) error {
	m := loadTrustedPasskeys()
	if m[credID] == cose {
		return nil
	}
	m[credID] = cose
	raw, _ := json.MarshalIndent(m, "", "  ")
	return os.WriteFile(trustedPasskeysPath(), append(raw, '\n'), 0o600)
}
