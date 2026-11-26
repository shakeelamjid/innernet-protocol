package main

// How clients reach this machine when nobody can connect to it directly, in order:
//   1. RLY-0 relay over ST81 (INNERNET's own protocol, end-to-end ST81 inside)
//   2. HTTPS tunnel through the registry (fallback for networks that block everything
//      but web traffic; requests and answers stay signed end to end)
// Both are outgoing connections, so no router or ISP setting matters.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const tunnelDomain = "INNERnet/REG-1/provider-tunnel\x00"

type netConfig struct {
	Relays []relayTarget `json:"relays"`
	Tunnel struct {
		URL      string `json:"url"`
		Endpoint struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		} `json:"endpoint"`
	} `json:"tunnel"`
}

func fetchNetConfig(registry string) (*netConfig, error) {
	resp, err := httpClient.Get(registry + "/config")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var nc netConfig
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&nc) != nil {
		return nil, fmt.Errorf("registry config: %s", resp.Status)
	}
	return &nc, nil
}

// tryRelays attaches to the first relay that accepts this machine (a short test attach).
func tryRelays(registry string, priv ed25519.PrivateKey) (*relayTarget, error) {
	nc, err := fetchNetConfig(registry)
	if err != nil {
		return nil, err
	}
	for _, r := range nc.Relays {
		pin, err := hex.DecodeString(r.Key)
		if err != nil || len(pin) != 32 {
			continue
		}
		sess, err := st81Dial(r.Addr, priv, ed25519.PublicKey(pin), 8*time.Second)
		if err != nil {
			continue
		}
		ok := sess.Write(map[string]any{"op": "attach"}, nil) == nil
		h, _, err := sess.Read()
		sess.Close()
		if ok && err == nil && h["ok"] == true {
			t := r
			return &t, nil
		}
	}
	if len(nc.Relays) == 0 {
		return nil, errNoRelay
	}
	return nil, errors.New("no relay accepted the connection (an outgoing port may be blocked)")
}

// tunnelWorks checks the HTTPS tunnel answers a signed poll for this machine.
func tunnelWorks(registry string, priv ed25519.PrivateKey) bool {
	req, err := tunnelRequest(registry, priv, "poll", "/poll?wait=0", nil)
	if err != nil {
		return false
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200 || resp.StatusCode == 204
}

func tunnelRequest(registry string, priv ed25519.PrivateKey, kind, suffix string, body []byte) (*http.Request, error) {
	id := providerID(priv)
	nb := make([]byte, 16)
	_, _ = rand.Read(nb)
	ts, nonce := strconv.FormatInt(time.Now().Unix(), 10), hex.EncodeToString(nb)
	sig := ed25519.Sign(priv, []byte(tunnelDomain+kind+"\n"+id+"\n"+ts+"\n"+nonce))
	req, err := http.NewRequest("POST", registry+"/tunnel/"+id+suffix, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Innernet-Time", ts)
	req.Header.Set("X-Innernet-Nonce", nonce)
	req.Header.Set("X-Innernet-Signature", hex.EncodeToString(sig))
	return req, nil
}

// tunnelLoop keeps a few long-polls open to the registry and answers each request locally.
func (s *server) tunnelLoop(registry string, onState func(bool)) {
	var live atomic.Int32
	poller := func() {
		backoff := time.Second
		client := &http.Client{Timeout: 40 * time.Second}
		for {
			req, err := tunnelRequest(registry, s.priv, "poll", "/poll", nil)
			if err != nil {
				return
			}
			resp, err := client.Do(req)
			if err != nil || (resp.StatusCode != 200 && resp.StatusCode != 204) {
				if resp != nil {
					resp.Body.Close()
				}
				if live.Add(-1) == 0 {
					onState(false)
				}
				live.Add(1)
				time.Sleep(backoff)
				backoff = min(backoff*2, time.Minute)
				continue
			}
			backoff = time.Second
			onState(true)
			if resp.StatusCode == 204 {
				resp.Body.Close()
				continue
			}
			var item struct {
				ID, Method, Path string
				Headers          map[string]string
				Body             string
			}
			err = json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&item)
			resp.Body.Close()
			if err != nil {
				continue
			}
			// Answer in the background, so a long CPU or GPU request does not hold up this poll.
			go func() {
				body, _ := base64.StdEncoding.DecodeString(item.Body)
				r := httptest.NewRequest(item.Method, item.Path, bytes.NewReader(body))
				for k, v := range item.Headers {
					r.Header.Set(k, v)
				}
				rec := httptest.NewRecorder()
				s.ServeHTTP(rec, r)
				hdr := map[string]string{}
				for _, k := range []string{"Content-Type", "X-Innernet-Provider", "X-Innernet-Signature"} {
					if v := rec.Header().Get(k); v != "" {
						hdr[k] = v
					}
				}
				ans, _ := json.Marshal(map[string]any{"status": rec.Code, "headers": hdr,
					"body": base64.StdEncoding.EncodeToString(rec.Body.Bytes())})
				if rr, err := tunnelRequest(registry, s.priv, "reply", "/reply/"+url.PathEscape(item.ID), ans); err == nil {
					if resp, err := client.Do(rr); err == nil {
						resp.Body.Close()
					}
				}
			}()
		}
	}
	live.Store(4)
	for i := 0; i < 4; i++ {
		go poller()
	}
	select {}
}

// startReachability runs whichever outgoing path this machine uses and reports its state
// to the presence loop.
func (s *server) startReachability(registry string) {
	switch {
	case s.cfg.Relay != nil:
		go s.attachLoop(*s.cfg.Relay, func(ok bool) { s.pathUp.Store(ok) })
	case s.cfg.Tunnel:
		go s.tunnelLoop(registry, func(ok bool) { s.pathUp.Store(ok) })
	}
}

// pathEndpoint is what presence announces: where clients connect, and how.
func (s *server) pathEndpoint(publicIP string) (path, host string, port int, relayKey string) {
	switch {
	case s.cfg.Relay != nil:
		h, p, _ := strings.Cut(s.cfg.Relay.Addr, ":")
		if i := strings.LastIndex(s.cfg.Relay.Addr, ":"); i > 0 {
			h, p = s.cfg.Relay.Addr[:i], s.cfg.Relay.Addr[i+1:]
		}
		n, _ := strconv.Atoi(p)
		return "relay", h, n, s.cfg.Relay.Key
	case s.cfg.Tunnel:
		u, _ := url.Parse(s.cfg.TunnelHost)
		host := s.cfg.TunnelHost
		if u != nil && u.Host != "" {
			host = u.Host
		}
		return "tunnel", host, 443, ""
	case s.cfg.PortMap != "":
		return "router", publicIP, s.cfg.Port, ""
	}
	return "direct", publicIP, s.cfg.Port, ""
}
