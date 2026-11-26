package main

import (
	"net/netip"
	"testing"
)

func TestExitRefusesPrivateNetworks(t *testing.T) {
	for _, s := range []string{"10.1.2.3", "192.168.1.1", "172.20.0.5", "127.0.0.1", "169.254.169.254", "100.64.0.1",
		"::1", "fd00::1", "fe80::1", "::ffff:192.168.1.1", "0.0.0.0", "224.0.0.1"} {
		if exitAllowed(netip.MustParseAddr(s)) {
			t.Errorf("%s must be refused", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "142.250.80.46", "2606:4700:4700::1111"} {
		if !exitAllowed(netip.MustParseAddr(s)) {
			t.Errorf("%s must be allowed", s)
		}
	}
}

func TestVPNPortsAndMeter(t *testing.T) {
	c := &Config{}
	if !c.vpnPortAllowed(443) || c.vpnPortAllowed(22) || c.vpnPortAllowed(25) {
		t.Fatal("web only")
	}
	c.VPNAllPorts = true
	if !c.vpnPortAllowed(22) || c.vpnPortAllowed(25) || c.vpnPortAllowed(0) {
		t.Fatal("all ports but 25")
	}
	m := openMeter(t.TempDir())
	if !m.add(1<<29, 1) || m.add(1<<30, 1) || m.left(1) != 0 {
		t.Fatal("monthly cap")
	}
	if ratDecimal("1610612736/1073741824") != "1.500000" {
		t.Fatal(ratDecimal("1610612736/1073741824"))
	}
}
