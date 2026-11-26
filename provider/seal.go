package main

// The key backup passphrase can be typed on the website. The browser seals it to a key that only
// this machine holds (P-256 ECDH, HKDF-SHA256, AES-256-GCM, all built into browsers), so the
// registry only ever carries ciphertext. The backup file itself is written here and never leaves.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
)

const (
	sealInfo = "INNERnet/REG-1/setup-seal"
	sealAAD  = "INNERnet backup passphrase"
)

type sealBox struct{ priv *ecdh.PrivateKey }

func newSealBox() (*sealBox, error) {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &sealBox{k}, nil
}

// public is the uncompressed point, base64url: what the browser seals to.
func (s *sealBox) public() string { return b64u(s.priv.PublicKey().Bytes()) }

type sealed struct {
	EPK string `json:"epk"`
	IV  string `json:"iv"`
	CT  string `json:"ct"`
	To  string `json:"to"`
}

func (s *sealBox) open(b *sealed) (string, error) {
	if b.To != s.public() {
		return "", errors.New("the passphrase was sealed to a different machine key")
	}
	epk, err1 := unb64u(b.EPK)
	iv, err2 := unb64u(b.IV)
	ct, err3 := unb64u(b.CT)
	if err1 != nil || err2 != nil || err3 != nil || len(iv) != 12 {
		return "", errors.New("sealed passphrase is malformed")
	}
	pub, err := ecdh.P256().NewPublicKey(epk)
	if err != nil {
		return "", errors.New("sealed passphrase: bad key")
	}
	shared, err := s.priv.ECDH(pub)
	if err != nil {
		return "", err
	}
	key := hkdfSHA256(shared, nil, []byte(sealInfo), 32)
	blk, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(blk)
	pt, err := gcm.Open(nil, iv, ct, []byte(sealAAD))
	if err != nil {
		return "", errors.New("sealed passphrase does not open")
	}
	return string(pt), nil
}

// sealTo is what the browser does; used by tests.
func sealTo(pubB64 string, msg string) (*sealed, error) {
	raw, err := unb64u(pubB64)
	if err != nil {
		return nil, err
	}
	pub, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		return nil, err
	}
	eph, _ := ecdh.P256().GenerateKey(rand.Reader)
	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, err
	}
	key := hkdfSHA256(shared, nil, []byte(sealInfo), 32)
	blk, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(blk)
	iv := make([]byte, 12)
	_, _ = rand.Read(iv)
	return &sealed{EPK: b64u(eph.PublicKey().Bytes()), IV: b64u(iv), CT: b64u(gcm.Seal(nil, iv, []byte(msg), []byte(sealAAD))),
		To: pubB64}, nil
}
