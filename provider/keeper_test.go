package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// A fake registry: /reachability answers what the test says, /config offers the HTTPS tunnel.
func fakeRegistry(t *testing.T, open *atomic.Bool) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/reachability"):
			_ = json.NewEncoder(w).Encode(map[string]bool{"reachable": open.Load()})
		case strings.HasSuffix(r.URL.Path, "/config"):
			_, _ = w.Write([]byte(`{"tunnel":{"url":"https://innernetcorp.test/registry","endpoint":{"host":"innernetcorp.test","port":443}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/registry/v1"
}

func freePort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestPortKeeperFallsBackAndComesBack(t *testing.T) {
	t.Setenv("INNERNET_HOME", t.TempDir())
	t.Setenv("INNERNET_NO_PORTMAP", "1")
	var open atomic.Bool
	reg := fakeRegistry(t, &open)
	s := &server{cfg: &Config{Version: "1", Port: freePort(t), Registry: reg}}
	open.Store(true)
	if s.keepPortOnce(reg) || s.cfg.Tunnel {
		t.Fatal("reachable port: nothing should change")
	}
	open.Store(false) // network changed, port closed
	if !s.keepPortOnce(reg) || !s.cfg.Tunnel || s.cfg.TunnelHost != "innernetcorp.test" {
		t.Fatalf("closed port: should fall back to the tunnel, got %+v", s.cfg)
	}
	saved, err := loadConfig()
	if err != nil || !saved.Tunnel {
		t.Fatalf("tunnel not saved: %v", err)
	}
	if s.keepPortOnce(reg) {
		t.Fatal("still closed on the tunnel: nothing should change")
	}
	open.Store(true) // port works again
	if !s.keepPortOnce(reg) || s.cfg.Tunnel || s.cfg.TunnelHost != "" {
		t.Fatalf("open port: should go back to direct, got %+v", s.cfg)
	}
}

func TestFirewallRulesAreRecordedAndRolledBack(t *testing.T) {
	t.Setenv("INNERNET_HOME", t.TempDir())
	marker := filepath.Join(t.TempDir(), "removed")
	recordFirewallRule(firewallPlan{Name: "test firewall", Undo: "touch " + marker,
		UndoCmd: [][]string{{"sh", "-c", "touch " + marker}}})
	recordFirewallRule(firewallPlan{Name: "test firewall", Undo: "touch " + marker,
		UndoCmd: [][]string{{"sh", "-c", "touch " + marker}}}) // the same rule once
	recordFirewallRule(firewallPlan{Name: "stubborn", Undo: "false", UndoCmd: [][]string{{"false"}}})
	if n := len(loadFirewallRecords()); n != 2 {
		t.Fatalf("records: %d", n)
	}
	rollbackFirewall()
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("undo command did not run")
	}
	left := loadFirewallRecords()
	if len(left) != 1 || left[0].Name != "stubborn" {
		t.Fatalf("a rule that could not be removed must stay recorded: %+v", left)
	}
}
