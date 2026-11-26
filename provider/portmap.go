package main

// Automatic port opening on home routers, so a home PC can be a provider without
// touching the router's settings. Two widely supported protocols, standard library only:
//
//   NAT-PMP (RFC 6886)  Apple routers and many others; UDP to the gateway, port 5351
//   UPnP IGD            most consumer routers; SSDP discovery, then a SOAP AddPortMapping
//
// The mapping keeps the same port outside and inside, so the address in the signed
// descriptor is the one clients use. `serve` renews it while it runs.
//
// It cannot help behind carrier-grade NAT (the ISP shares one public address between
// customers). That is detected and reported instead of pretending.

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const mapLifetime = 3600 // seconds asked for; renewed by serve well before it ends

var (
	natpmpPort  = 5351            // replaced in tests
	mapTimeout  = 2 * time.Second // per attempt
	ssdpAddr    = "239.255.255.250:1900"
	mapDescribe = "INNERnet provider"
)

type mapping struct {
	Method     string // "natpmp" or "upnp"
	Gateway    string
	Port       int
	ExternalIP string
	ctrlURL    string
	service    string
	localIP    string
}

// openPort tries NAT-PMP, then UPnP. It never changes anything but a port mapping.
func openPort(port int) (*mapping, error) {
	gw := os.Getenv("INNERNET_GATEWAY")
	if gw == "" {
		gw = defaultGateway()
	}
	var errs []string
	if gw != "" {
		if m, err := natpmpMap(gw, port); err == nil {
			return m, nil
		} else {
			errs = append(errs, "NAT-PMP: "+err.Error())
		}
	}
	loc := os.Getenv("INNERNET_UPNP_LOCATION")
	if loc == "" {
		var err error
		if loc, err = ssdpDiscover(); err != nil {
			errs = append(errs, "UPnP: "+err.Error())
		}
	}
	if loc != "" {
		if m, err := upnpMap(loc, port); err == nil {
			return m, nil
		} else {
			errs = append(errs, "UPnP: "+err.Error())
		}
	}
	if len(errs) == 0 {
		errs = append(errs, "no router found")
	}
	return nil, errors.New(strings.Join(errs, "; "))
}

// renew re-adds the same mapping (both protocols treat that as a refresh).
func (m *mapping) renew() error {
	switch m.Method {
	case "natpmp":
		_, err := natpmpMap(m.Gateway, m.Port)
		return err
	case "upnp":
		return upnpAdd(m.ctrlURL, m.service, m.localIP, m.Port)
	}
	return errors.New("unknown mapping")
}

// sharedAddress reports addresses that cannot be reached from the internet: private
// ranges and the carrier-grade NAT range 100.64.0.0/10.
func sharedAddress(ip string) bool {
	a := net.ParseIP(ip)
	if a == nil {
		return false
	}
	_, cgnat, _ := net.ParseCIDR("100.64.0.0/10")
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || cgnat.Contains(a)
}

// ---------- NAT-PMP ----------

func natpmpCall(gw string, req []byte, want byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(gw, strconv.Itoa(natpmpPort)), mapTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	buf := make([]byte, 16)
	// RFC 6886: retry with doubling waits; three tries keep setup quick.
	for wait := 250 * time.Millisecond; wait <= time.Second; wait *= 2 {
		if _, err := conn.Write(req); err != nil {
			return nil, err
		}
		_ = conn.SetReadDeadline(time.Now().Add(wait))
		n, err := conn.Read(buf)
		if err != nil {
			continue
		}
		if n < 8 || buf[0] != 0 || buf[1] != want {
			return nil, errors.New("unexpected reply")
		}
		if code := binary.BigEndian.Uint16(buf[2:4]); code != 0 {
			return nil, fmt.Errorf("router refused (result %d)", code)
		}
		return buf[:n], nil
	}
	return nil, errors.New("no reply")
}

func natpmpMap(gw string, port int) (*mapping, error) {
	ext, err := natpmpCall(gw, []byte{0, 0}, 128)
	if err != nil {
		return nil, err
	}
	if len(ext) < 12 {
		return nil, errors.New("short reply")
	}
	extIP := net.IP(ext[8:12]).String()
	req := make([]byte, 12)
	req[1] = 2 // map TCP
	binary.BigEndian.PutUint16(req[4:6], uint16(port))
	binary.BigEndian.PutUint16(req[6:8], uint16(port))
	binary.BigEndian.PutUint32(req[8:12], mapLifetime)
	r, err := natpmpCall(gw, req, 130)
	if err != nil {
		return nil, err
	}
	if len(r) < 16 {
		return nil, errors.New("short reply")
	}
	if got := int(binary.BigEndian.Uint16(r[10:12])); got != port {
		// Undo: a different outside port would not match the signed address.
		binary.BigEndian.PutUint32(req[8:12], 0)
		_, _ = natpmpCall(gw, req, 130)
		return nil, fmt.Errorf("router offered port %d instead of %d", got, port)
	}
	return &mapping{Method: "natpmp", Gateway: gw, Port: port, ExternalIP: extIP}, nil
}

// ---------- UPnP IGD ----------

func ssdpDiscover() (string, error) {
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	dst, err := net.ResolveUDPAddr("udp4", ssdpAddr)
	if err != nil {
		return "", err
	}
	for _, st := range []string{"urn:schemas-upnp-org:device:InternetGatewayDevice:2",
		"urn:schemas-upnp-org:device:InternetGatewayDevice:1"} {
		msg := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: " + st + "\r\n\r\n"
		if _, err := conn.WriteTo([]byte(msg), dst); err != nil {
			return "", err
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(mapTimeout + time.Second))
	buf := make([]byte, 2048)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return "", errors.New("no UPnP router answered")
		}
		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(buf[:n])), nil)
		if err != nil {
			continue
		}
		if loc := resp.Header.Get("Location"); loc != "" {
			return loc, nil
		}
	}
}

type upnpService struct {
	Type string `xml:"serviceType"`
	Ctrl string `xml:"controlURL"`
}

type upnpDevice struct {
	Services []upnpService `xml:"serviceList>service"`
	Devices  []upnpDevice  `xml:"deviceList>device"`
}

func (d upnpDevice) find() (upnpService, bool) {
	for _, s := range d.Services {
		if strings.Contains(s.Type, ":WANIPConnection:") || strings.Contains(s.Type, ":WANPPPConnection:") {
			return s, true
		}
	}
	for _, c := range d.Devices {
		if s, ok := c.find(); ok {
			return s, true
		}
	}
	return upnpService{}, false
}

func upnpMap(location string, port int) (*mapping, error) {
	client := &http.Client{Timeout: mapTimeout}
	resp, err := client.Get(location)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var desc struct {
		URLBase string     `xml:"URLBase"`
		Device  upnpDevice `xml:"device"`
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&desc); err != nil {
		return nil, fmt.Errorf("router description: %v", err)
	}
	svc, ok := desc.Device.find()
	if !ok {
		return nil, errors.New("router has no internet connection service")
	}
	base, err := url.Parse(location)
	if err != nil {
		return nil, err
	}
	if desc.URLBase != "" {
		if b, err := url.Parse(desc.URLBase); err == nil {
			base = b
		}
	}
	ctrl, err := base.Parse(svc.Ctrl)
	if err != nil {
		return nil, err
	}
	local, err := localIPFor(base.Host)
	if err != nil {
		return nil, err
	}
	if err := upnpAdd(ctrl.String(), svc.Type, local, port); err != nil {
		return nil, err
	}
	m := &mapping{Method: "upnp", Gateway: base.Hostname(), Port: port, ctrlURL: ctrl.String(), service: svc.Type, localIP: local}
	if out, err := soap(ctrl.String(), svc.Type, "GetExternalIPAddress", ""); err == nil {
		m.ExternalIP = xmlValue(out, "NewExternalIPAddress")
	}
	return m, nil
}

func upnpAdd(ctrl, service, local string, port int) error {
	args := func(lease int) string {
		return fmt.Sprintf("<NewRemoteHost></NewRemoteHost><NewExternalPort>%d</NewExternalPort><NewProtocol>TCP</NewProtocol>"+
			"<NewInternalPort>%d</NewInternalPort><NewInternalClient>%s</NewInternalClient><NewEnabled>1</NewEnabled>"+
			"<NewPortMappingDescription>%s</NewPortMappingDescription><NewLeaseDuration>%d</NewLeaseDuration>",
			port, port, local, mapDescribe, lease)
	}
	_, err := soap(ctrl, service, "AddPortMapping", args(mapLifetime))
	if err != nil && strings.Contains(err.Error(), "725") { // OnlyPermanentLeasesSupported
		_, err = soap(ctrl, service, "AddPortMapping", args(0))
	}
	return err
}

func soap(ctrl, service, action, args string) (string, error) {
	body := `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ` +
		`s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:` + action + ` xmlns:u="` + service + `">` +
		args + `</u:` + action + `></s:Body></s:Envelope>`
	req, err := http.NewRequest("POST", ctrl, strings.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"`+service+"#"+action+`"`)
	resp, err := (&http.Client{Timeout: mapTimeout}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != 200 {
		code := xmlValue(string(raw), "errorCode")
		return "", fmt.Errorf("router refused %s (%s %s)", action, resp.Status, code)
	}
	return string(raw), nil
}

func xmlValue(doc, tag string) string {
	i := strings.Index(doc, "<"+tag+">")
	if i < 0 {
		return ""
	}
	rest := doc[i+len(tag)+2:]
	j := strings.Index(rest, "</"+tag+">")
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:j])
}

// localIPFor is this machine's address on the route to the router.
func localIPFor(hostport string) (string, error) {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	conn, err := net.Dial("udp", net.JoinHostPort(host, "1900"))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String(), nil
}

// ---------- default gateway ----------

func defaultGateway() string {
	switch runtime.GOOS {
	case "linux":
		raw, err := os.ReadFile("/proc/net/route")
		if err != nil {
			return ""
		}
		return gatewayFromProcRoute(string(raw))
	case "darwin", "freebsd", "openbsd", "netbsd":
		out, err := exec.Command("route", "-n", "get", "default").Output()
		if err != nil {
			return ""
		}
		for _, l := range strings.Split(string(out), "\n") {
			if f := strings.Fields(l); len(f) == 2 && f[0] == "gateway:" && net.ParseIP(f[1]) != nil {
				return f[1]
			}
		}
	case "windows":
		out, err := exec.Command("route", "print", "-4", "0.0.0.0").Output()
		if err != nil {
			return ""
		}
		for _, l := range strings.Split(string(out), "\n") {
			if f := strings.Fields(l); len(f) >= 3 && f[0] == "0.0.0.0" && f[1] == "0.0.0.0" && net.ParseIP(f[2]) != nil {
				return f[2]
			}
		}
	}
	return ""
}

func gatewayFromProcRoute(raw string) string {
	for _, l := range strings.Split(raw, "\n")[1:] {
		f := strings.Fields(l)
		if len(f) < 3 || f[1] != "00000000" {
			continue
		}
		v, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil || v == 0 {
			continue
		}
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(v))
		return net.IP(b).String()
	}
	return ""
}

// closePort removes the router mapping this program asked for (uninstall). Best effort.
func closePort(port int) string {
	gw := os.Getenv("INNERNET_GATEWAY")
	if gw == "" {
		gw = defaultGateway()
	}
	if gw != "" {
		req := make([]byte, 12)
		req[1] = 2 // TCP; lifetime 0 removes the mapping
		binary.BigEndian.PutUint16(req[4:6], uint16(port))
		if _, err := natpmpCall(gw, req, 130); err == nil {
			return "NAT-PMP"
		}
	}
	loc := os.Getenv("INNERNET_UPNP_LOCATION")
	if loc == "" {
		loc, _ = ssdpDiscover()
	}
	if loc == "" {
		return ""
	}
	client := &http.Client{Timeout: mapTimeout}
	resp, err := client.Get(loc)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var desc struct {
		URLBase string     `xml:"URLBase"`
		Device  upnpDevice `xml:"device"`
	}
	if xml.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&desc) != nil {
		return ""
	}
	svc, ok := desc.Device.find()
	if !ok {
		return ""
	}
	base, err := url.Parse(loc)
	if err != nil {
		return ""
	}
	if desc.URLBase != "" {
		if b, err := url.Parse(desc.URLBase); err == nil {
			base = b
		}
	}
	ctrl, err := base.Parse(svc.Ctrl)
	if err != nil {
		return ""
	}
	args := fmt.Sprintf("<NewRemoteHost></NewRemoteHost><NewExternalPort>%d</NewExternalPort><NewProtocol>TCP</NewProtocol>", port)
	if _, err := soap(ctrl.String(), svc.Type, "DeletePortMapping", args); err == nil {
		return "UPnP"
	}
	return ""
}
