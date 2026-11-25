package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPrintStatusFullReply(t *testing.T) {
	var s statusReply
	raw := `{"state":"listed","checked_at":1764000000,"health":{"uptime_7d":"99.8%","challenge_pass_7d":"100%"},
	"activity":{"STO-1":"41 leases, 120 GiB","CMP-1":"12 jobs"},
	"earnings":{"asset":"USDC","gross_30d":"10.00","fee_30d":"0.10","net_30d":"9.90"}}`
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	printStatus(&b, &s)
	for _, want := range []string{"Status: listed", "uptime 99.8%", "Activity CMP-1: 12 jobs", "0.10 network fee, 9.90 to you"} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("missing %q in\n%s", want, b.String())
		}
	}
}

func TestOwedRoundsUp(t *testing.T) {
	for _, c := range []struct{ units, price, want string }{
		{"1", "0.0010", "1000"}, {"2.5", "0.0010", "2500"}, {"1", "0.0000001", "1"}, {"0.5", "0.003", "1500"},
	} {
		got, err := owed(c.units, c.price)
		if err != nil || got.String() != c.want {
			t.Fatalf("owed(%s,%s)=%v %v want %s", c.units, c.price, got, err, c.want)
		}
	}
}

func TestRegionFor(t *testing.T) {
	for tz, want := range map[string]string{"Asia/Karachi": "asia-south", "Europe/Berlin": "eu-central",
		"America/Chicago": "us-central", "UTC": "global", "": "global"} {
		if got := regionFor(tz); got != want {
			t.Fatalf("regionFor(%q)=%q want %q", tz, got, want)
		}
	}
}
