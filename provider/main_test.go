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
