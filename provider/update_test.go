package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		tag, cur string
		want     bool
	}{{"provider-v0.4.1", "0.4.0", true}, {"provider-v0.10.0", "0.9.9", true}, {"provider-v0.4.0", "0.4.0", false},
		{"provider-v0.3.9", "0.4.0", false}, {"v1.0.0", "0.1.0", false}, {"provider-v1.0.0", "0.3.0-draft", false}} {
		if newer(c.tag, c.cur) != c.want {
			t.Errorf("newer(%s, %s)", c.tag, c.cur)
		}
	}
}

func TestDownloadChecksAndReplace(t *testing.T) {
	bin := []byte("new program")
	sum := sha256.Sum256(bin)
	good := hex.EncodeToString(sum[:]) + "  " + assetName() + "\n"
	sums := good
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch filepath.Base(r.URL.Path) {
		case "LATEST":
			_, _ = w.Write([]byte("provider-v9.9.9\n"))
		case "SHA256SUMS":
			_, _ = w.Write([]byte(sums))
		case assetName():
			_, _ = w.Write(bin)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	latestURL, releaseURL = srv.URL+"/LATEST", srv.URL+"/"
	latestFallback, releaseFallback = srv.URL+"/none", srv.URL+"/none/"
	if tag := latestTag(); tag != "provider-v9.9.9" {
		t.Fatal(tag)
	}
	got, err := download("provider-v9.9.9")
	if err != nil || string(got) != "new program" {
		t.Fatal(err)
	}
	sums = "00" + good[2:]
	if _, err := download("provider-v9.9.9"); err == nil {
		t.Fatal("accepted a program that does not match SHA256SUMS")
	}
	exe := filepath.Join(t.TempDir(), "innernet-provider")
	_ = os.WriteFile(exe, []byte("old"), 0o755)
	if err := replaceFile(exe, bin); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "new program" {
		t.Fatal(string(b))
	}
}
