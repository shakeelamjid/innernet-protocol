package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// x402 jobs: the INNERNET gateway sells CPU jobs to agents over x402. The agent's payment is checked
// by the facilitator before the job, and collected (straight into this provider's payout contract)
// only after this provider has run the job and signed its receipt; if the job cannot run, nothing is
// collected. Such jobs come from the gateway's client key, which the registry publishes in its
// config, with X-Innernet-X402 carrying the authorized amount. They need no prepaid credit.

var x402GW struct {
	sync.Mutex
	key string
	at  time.Time
}

// x402Gateway returns the gateway client key the registry publishes (cached 10 minutes), or "".
func (s *server) x402Gateway() string {
	x402GW.Lock()
	defer x402GW.Unlock()
	if time.Since(x402GW.at) < 10*time.Minute {
		return x402GW.key
	}
	x402GW.at = time.Now()
	resp, err := httpClient.Get(strings.TrimRight(registryURL(s.cfg), "/") + "/config")
	if err != nil {
		return x402GW.key
	}
	defer resp.Body.Close()
	var cfg struct {
		X402 *struct {
			GatewayClient string `json:"gateway_client"`
		} `json:"x402"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&cfg) != nil {
		return x402GW.key
	}
	x402GW.key = ""
	if cfg.X402 != nil && reHex64.MatchString(cfg.X402.GatewayClient) {
		x402GW.key = strings.ToLower(cfg.X402.GatewayClient)
	}
	return x402GW.key
}

// x402Amount: the authorized amount (USDC base units) of an x402 job from the gateway, 0 if the
// request is not one.
func (s *server) x402Amount(r *http.Request, client string) int64 {
	v := r.Header.Get("X-Innernet-X402")
	if v == "" {
		return 0
	}
	gw := s.x402Gateway()
	if gw == "" || !strings.EqualFold(client, gw) {
		return 0
	}
	n, ok := new(big.Int).SetString(v, 10)
	if !ok || n.Sign() <= 0 || !n.IsInt64() {
		return 0
	}
	return n.Int64()
}

func x402Short(amount, need int64) string {
	return fmt.Sprintf("the x402 payment (%s USDC) is below this provider's price for that time limit (%s USDC)",
		usdc(amount), usdc(need))
}
