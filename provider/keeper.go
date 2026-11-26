package main

// The port keeper keeps this machine directly reachable whenever the network allows it.
//
// While serving it checks, every few minutes, after every network change and whenever the
// registry reports that it could not reach the machine:
//   - reached directly: the registry dials the port back. If that fails, it asks the router to
//     open the port again (NAT-PMP, UPnP) and tests once more; if the port stays closed it falls
//     back to the HTTPS tunnel by itself, so the machine stays online.
//   - on the HTTPS tunnel: it tries to open the port again; as soon as the registry reaches the
//     port, it goes back to the direct connection.
// A switch restarts the service with the new path (same process id; nothing is lost).
// Some networks can never be opened from the machine: a router without NAT-PMP/UPnP, an address
// shared by the internet provider (CGNAT), or a VPN. There the tunnel stays.

import (
	"log"
	"os"
	"strconv"
	"time"
)

func keeperEvery() time.Duration {
	if sec, err := strconv.Atoi(os.Getenv("INNERNET_PORT_CHECK_SEC")); err == nil && sec > 0 {
		return time.Duration(sec) * time.Second
	}
	return 10 * time.Minute
}

// portKeeper runs inside serve. nudge wakes it early (network change, registry could not reach us).
func (s *server) portKeeper(registry string, nudge <-chan struct{}, restart func()) {
	if s.cfg.Relay != nil || os.Getenv("INNERNET_NO_KEEPER") == "1" {
		return // a relay was chosen explicitly
	}
	time.Sleep(5 * time.Second) // let the listener start first
	for {
		if s.keepPortOnce(registry) {
			restart()
			return
		}
		select {
		case <-nudge:
		case <-time.After(keeperEvery()):
		}
	}
}

// keepPortOnce returns true when the path changed and the service must restart with it.
func (s *server) keepPortOnce(registry string) bool {
	port := s.cfg.Port
	noMap := os.Getenv("INNERNET_NO_PORTMAP") == "1"
	if !s.cfg.Tunnel {
		if ok, _ := reachable(registry, port); ok {
			return false
		}
		if !noMap {
			if m, err := openPort(port); err == nil {
				if ok, _ := reachable(registry, port); ok {
					log.Printf("port %d: reopened on the router (%s)", port, m.Method)
					if s.cfg.PortMap != m.Method {
						s.cfg.PortMap = m.Method
						_ = saveConfig(s.cfg)
					}
					return false
				}
			} else {
				log.Printf("port %d: router did not reopen it (%v)", port, err)
			}
		}
		nc, err := fetchNetConfig(registry)
		if err != nil || nc.Tunnel.Endpoint.Host == "" {
			log.Printf("port %d is closed and the HTTPS tunnel is not available; trying again later", port)
			return false
		}
		log.Printf("port %d is closed on this network: switching to the HTTPS tunnel (%s)", port, nc.Tunnel.Endpoint.Host)
		s.cfg.Tunnel, s.cfg.TunnelHost = true, nc.Tunnel.Endpoint.Host
		_ = saveConfig(s.cfg)
		return true
	}
	// On the tunnel: try to get the direct connection back.
	method := ""
	if !noMap {
		if m, err := openPort(port); err == nil {
			method = m.Method
		}
	}
	if ok, _ := reachable(registry, port); !ok {
		return false
	}
	log.Printf("port %d is reachable again: back to the direct connection", port)
	s.cfg.Tunnel, s.cfg.TunnelHost, s.cfg.PortMap = false, "", method
	_ = saveConfig(s.cfg)
	return true
}
