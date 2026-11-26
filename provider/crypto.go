package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	descriptorDomain = "INNERnet/REG-1/provider-descriptor\x00"
	loginDomain      = "INNERnet/REG-1/provider-login\x00"
	backupVersion    = "INNERNET-PROVIDER-BACKUP-1"
	backupIterations = 600000
)

// pbkdf2SHA256 is RFC 8018 PBKDF2 with HMAC-SHA-256 (standard library only).
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hLen := prf.Size()
	blocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, blocks*hLen)
	buf := make([]byte, 4)
	for block := 1; block <= blocks; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(buf, uint32(block))
		prf.Write(buf)
		u := prf.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for i := range t {
				t[i] ^= u[i]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

type backupFile struct {
	Version    string `json:"version"`
	ProviderID string `json:"provider_id"`
	KDF        string `json:"kdf"`
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func backupAAD(providerID string) []byte {
	return []byte(backupVersion + "\x00" + providerID)
}

func sealBackup(seed []byte, passphrase string) ([]byte, error) {
	if len(passphrase) < 12 {
		return nil, errors.New("passphrase must be at least 12 characters")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	id := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	salt, nonce := make([]byte, 16), make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	key := pbkdf2SHA256([]byte(passphrase), salt, backupIterations, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, seed, backupAAD(id))
	return json.MarshalIndent(backupFile{backupVersion, id, "pbkdf2-hmac-sha256", backupIterations,
		hex.EncodeToString(salt), hex.EncodeToString(nonce), hex.EncodeToString(ct)}, "", "  ")
}

func openBackup(raw []byte, passphrase string) ([]byte, error) {
	var b backupFile
	if err := json.Unmarshal(raw, &b); err != nil || b.Version != backupVersion || b.KDF != "pbkdf2-hmac-sha256" {
		return nil, errors.New("not an INNERNET provider backup file")
	}
	if b.Iterations < 100000 || b.Iterations > 10000000 {
		return nil, errors.New("backup file has an unsafe iteration count")
	}
	salt, err1 := hex.DecodeString(b.Salt)
	nonce, err2 := hex.DecodeString(b.Nonce)
	ct, err3 := hex.DecodeString(b.Ciphertext)
	if err1 != nil || err2 != nil || err3 != nil || len(nonce) != 12 {
		return nil, errors.New("backup file is damaged")
	}
	key := pbkdf2SHA256([]byte(passphrase), salt, b.Iterations, 32)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	seed, err := gcm.Open(nil, nonce, ct, backupAAD(b.ProviderID))
	if err != nil {
		return nil, errors.New("wrong passphrase or damaged backup file")
	}
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("backup holds an invalid key")
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if hex.EncodeToString(pub) != b.ProviderID {
		return nil, errors.New("backup key does not match its provider id")
	}
	return seed, nil
}

func signCanonical(priv ed25519.PrivateKey, domain string, payload any) (string, error) {
	msg, err := canonicalJSON(payload)
	if err != nil {
		return "", fmt.Errorf("canonical JSON: %w", err)
	}
	return hex.EncodeToString(ed25519.Sign(priv, append([]byte(domain), msg...))), nil
}
