package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeNATPMP answers like a router: external address 203.0.113.7, maps the asked port.
func fakeNATPMP(t *testing.T, offer func(asked uint16) uint16) (gw string) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	natpmpPort = pc.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buf := make([]byte, 64)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			switch {
			case n == 2 && buf[1] == 0:
				r := []byte{0, 128, 0, 0, 0, 0, 0, 1, 203, 0, 113, 7}
				pc.WriteTo(r, addr)
			case n == 12 && buf[1] == 2:
				r := make([]byte, 16)
				r[1] = 130
				copy(r[8:10], buf[4:6])
				binary.BigEndian.PutUint16(r[10:12], offer(binary.BigEndian.Uint16(buf[6:8])))
				copy(r[12:16], buf[8:12])
				pc.WriteTo(r, addr)
			}
		}
	}()
	return "127.0.0.1"
}

func TestNATPMPMapsSamePort(t *testing.T) {
	gw := fakeNATPMP(t, func(a uint16) uint16 { return a })
	m, err := natpmpMap(gw, 9443)
	if err != nil {
		t.Fatal(err)
	}
	if m.Method != "natpmp" || m.Port != 9443 || m.ExternalIP != "203.0.113.7" || sharedAddress(m.ExternalIP) {
		t.Fatalf("bad mapping %+v", m)
	}
	if err := m.renew(); err != nil {
		t.Fatal(err)
	}
}

func TestNATPMPRefusesADifferentOutsidePort(t *testing.T) {
	gw := fakeNATPMP(t, func(a uint16) uint16 { return a + 1 })
	if _, err := natpmpMap(gw, 9443); err == nil || !strings.Contains(err.Error(), "instead of") {
		t.Fatalf("want refusal, got %v", err)
	}
}

func TestUPnPAddPortMapping(t *testing.T) {
	var calls []string
	var body string
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/desc.xml", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<?xml version="1.0"?><root><device><deviceList><device><deviceList><device><serviceList><service>
<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl/IPConn</controlURL>
</service></serviceList></device></deviceList></device></deviceList></device></root>`)
	})
	mux.HandleFunc("/ctl/IPConn", func(w http.ResponseWriter, r *http.Request) {
		action := r.Header.Get("SOAPAction")
		calls = append(calls, action)
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(action, "AddPortMapping") {
			body = string(b)
			if strings.Contains(body, "<NewLeaseDuration>3600<") {
				w.WriteHeader(500) // this router only takes permanent leases
				fmt.Fprint(w, `<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>725</errorCode></UPnPError></detail></s:Fault></s:Body></s:Envelope>`)
				return
			}
		}
		fmt.Fprint(w, `<s:Envelope><s:Body><u:R><NewExternalIPAddress>100.70.1.2</NewExternalIPAddress></u:R></s:Body></s:Envelope>`)
	})
	m, err := upnpMap(srv.URL+"/desc.xml", 9443)
	if err != nil {
		t.Fatal(err)
	}
	if m.Method != "upnp" || m.ExternalIP != "100.70.1.2" || !sharedAddress(m.ExternalIP) {
		t.Fatalf("bad mapping %+v", m) // 100.64/10 is carrier-grade NAT: reported as shared
	}
	for _, want := range []string{"<NewExternalPort>9443<", "<NewInternalPort>9443<", "<NewInternalClient>127.0.0.1<",
		"<NewProtocol>TCP<", "<NewLeaseDuration>0<"} {
		if !strings.Contains(body, want) {
			t.Fatalf("request missing %s:\n%s", want, body)
		}
	}
	if len(calls) != 3 || !strings.Contains(calls[2], "GetExternalIPAddress") {
		t.Fatalf("calls %v", calls)
	}
}

func TestGatewayFromProcRoute(t *testing.T) {
	raw := "Iface\tDestination\tGateway \tFlags\nwlan0\t0001A8C0\t00000000\t0001\nwlan0\t00000000\t0101A8C0\t0003\n"
	if gw := gatewayFromProcRoute(raw); gw != "192.168.1.1" {
		t.Fatalf("got %q", gw)
	}
	for ip, shared := range map[string]bool{"192.168.1.5": true, "100.64.0.1": true, "100.128.0.1": false, "8.8.8.8": false} {
		if sharedAddress(ip) != shared {
			t.Fatalf("%s shared=%v", ip, !shared)
		}
	}
}
