package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Terms: the provider agrees to the provider terms (its listing carries their SHA-256, signed);
// clients agree to the client terms with every payment (the signed request carries their SHA-256).

type termsDoc struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Text    string `json:"text"`
}

func fetchTerms(registry string) (map[string]termsDoc, error) {
	b, err := fetch(strings.TrimRight(registry, "/")+"/terms", 256<<10)
	if err != nil {
		return nil, err
	}
	var out map[string]termsDoc
	if err := json.Unmarshal(b, &out); err != nil || len(out["provider"].SHA256) != 64 || len(out["client"].SHA256) != 64 {
		return nil, errors.New("the registry returned no terms")
	}
	return out, nil
}

func termsPage(registry string) string {
	return strings.TrimSuffix(strings.TrimRight(registry, "/"), "/v1") + "/terms"
}

// clientTerms keeps the current client-terms fingerprint, refreshed hourly and kept on disk.
type clientTerms struct {
	mu  sync.Mutex
	sha string
}

func (t *clientTerms) get() string {
	if v := os.Getenv("INNERNET_CLIENT_TERMS"); v != "" {
		return v
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sha
}

func (t *clientTerms) keepFresh(registry string) {
	p := filepath.Join(home(), "client-terms.sha256")
	if b, err := os.ReadFile(p); err == nil {
		t.mu.Lock()
		t.sha = strings.TrimSpace(string(b))
		t.mu.Unlock()
	}
	for {
		if docs, err := fetchTerms(registry); err == nil {
			t.mu.Lock()
			t.sha = docs["client"].SHA256
			t.mu.Unlock()
			_ = os.WriteFile(p, []byte(t.sha+"\n"), 0o600)
		}
		time.Sleep(time.Hour)
	}
}

// checkClientTerms is called before taking any payment.
func (s *server) checkClientTerms(got string) error {
	want := s.terms.get()
	if want == "" {
		return errors.New("this provider cannot confirm the current client terms yet; try again shortly")
	}
	if got != want {
		return fmt.Errorf("agree to the current client terms (%s) and send their fingerprint as terms", termsPage(registryURL(s.cfg)))
	}
	return nil
}

// askTerms shows where the provider terms are and asks to agree; it returns their fingerprint.
func askTerms(registry string, yes bool) (string, error) {
	docs, err := fetchTerms(registry)
	if err != nil {
		return "", fmt.Errorf("could not read the provider terms: %v", err)
	}
	t := docs["provider"]
	fmt.Printf("  Provider terms, version %s: %s\n", t.Version, termsPage(registry))
	if yes {
		fmt.Println(dim("  Agreed with --accept-terms."))
		return t.SHA256, nil
	}
	if !askYes("  Do you agree to the provider terms", false) {
		return "", errors.New("you must agree to the provider terms to list this machine")
	}
	return t.SHA256, nil
}

// cmdTerms: show the terms, or agree to the current provider terms and re-sign the listing.
func cmdTerms(args []string) error {
	fs := flag.NewFlagSet("terms", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	if fs.Arg(0) != "accept" {
		docs, err := fetchTerms(registryURL(c))
		if err != nil {
			return err
		}
		fmt.Printf("Provider terms %s (%s)\nClient terms   %s\nRead them at   %s\n", docs["provider"].Version,
			map[bool]string{true: "you agreed to this version", false: "not agreed yet: innernet-provider terms accept"}[c.TermsSHA == docs["provider"].SHA256],
			docs["client"].Version, termsPage(registryURL(c)))
		return nil
	}
	sha, err := askTerms(registryURL(c), false)
	if err != nil {
		return err
	}
	c.TermsSHA = sha
	if err := saveConfig(c); err != nil {
		return err
	}
	fmt.Println("Agreed. Send your listing again with: innernet-provider apply")
	return nil
}
