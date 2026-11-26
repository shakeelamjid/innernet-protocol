package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUploadBackupSignsTheBlobHash(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw, err := sealBackup(priv.Seed(), "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Intent struct {
			Payload map[string]any `json:"payload"`
		} `json:"intent"`
		Backup string `json:"backup"`
	}
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&got)
	}))
	defer srv.Close()
	if err := uploadBackup(srv.URL+"/v1", priv, append(raw, '\n')); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(got.Backup))
	if path != "/v1/providers/"+providerID(priv)+"/backup" || got.Intent.Payload["action"] != "backup-store" ||
		got.Intent.Payload["target"] != hex.EncodeToString(sum[:]) || !strings.Contains(got.Backup, providerID(priv)) {
		t.Fatalf("unexpected upload %s %v", path, got.Intent.Payload)
	}
}
