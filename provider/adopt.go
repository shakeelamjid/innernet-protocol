package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// A machine may apply with a plain wallet as its payout (when the operator creates payout contracts
// for providers). It is not listed until it is paid through a contract from the INNERNET factory.
// adoptPayout looks for that contract (factory.splitOf(wallet)); once it exists, the machine switches
// its payout to it, saves the config and applies again with its own signature.

const selSplitOf = "41890891" // splitOf(address)

func ethRPC(url, method string, params []any) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Error != nil {
		return nil, errors.New(out.Error.Message)
	}
	return out.Result, nil
}

// factoryFor reads the payout factory for a network from the registry's public config.
func factoryFor(registry, caip2 string) string {
	resp, err := httpClient.Get(strings.TrimRight(registry, "/") + "/config")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var cfg struct {
		Networks []struct {
			CAIP2   string `json:"caip2"`
			Factory string `json:"factory"`
		} `json:"networks"`
	}
	if json.NewDecoder(resp.Body).Decode(&cfg) != nil {
		return ""
	}
	for _, n := range cfg.Networks {
		if n.CAIP2 == caip2 && reEVM.MatchString(n.Factory) {
			return n.Factory
		}
	}
	return ""
}

// payoutContractFor returns the payout contract created for wallet, or "" if there is none (or the
// payout is already a contract).
func payoutContractFor(rpc, registry, caip2, wallet string) (string, error) {
	var code string
	raw, err := ethRPC(rpc, "eth_getCode", []any{wallet, "latest"})
	if err != nil {
		return "", err
	}
	if json.Unmarshal(raw, &code) != nil || !isWalletCode(code) {
		return "", nil // already a contract
	}
	factory := factoryFor(registry, caip2)
	if factory == "" {
		return "", nil
	}
	data := "0x" + selSplitOf + strings.Repeat("0", 24) + strings.ToLower(strings.TrimPrefix(wallet, "0x"))
	raw, err = ethRPC(rpc, "eth_call", []any{map[string]any{"to": factory, "data": data}, "latest"})
	if err != nil {
		return "", err
	}
	var word string
	if json.Unmarshal(raw, &word) != nil || len(word) != 66 {
		return "", nil
	}
	addr := "0x" + word[26:]
	if strings.Trim(addr[2:], "0") == "" {
		return "", nil
	}
	return addr, nil
}

// isWalletCode: no code, or only an EIP-7702 delegation (0xef0100 + address) that "smart" wallets
// set on an ordinary account.
func isWalletCode(code string) bool {
	c := strings.ToLower(code)
	return c == "" || c == "0x" || (strings.HasPrefix(c, "0xef0100") && len(c) == 2+2*23)
}

// adoptPayout switches a plain-wallet payout to its payout contract once one exists.
func (s *server) adoptPayout(registry string) {
	if !reEVM.MatchString(s.cfg.Payout) {
		return
	}
	split, err := payoutContractFor(s.rpc, registry, networks[s.cfg.Network], s.cfg.Payout)
	if err != nil || split == "" {
		return
	}
	c := *s.cfg
	c.Payout = split
	desc, err := buildDescriptor(&c, s.priv)
	if err != nil {
		return
	}
	raw, _ := json.Marshal(desc)
	prev := quietApply
	quietApply = true
	err = postApplication(&c, raw)
	quietApply = prev
	if err != nil {
		return
	}
	if saveConfig(&c) == nil {
		s.cfg.Payout = split
	}
}

// adoptLoop checks every 10 minutes while the payout is a plain wallet.
func (s *server) adoptLoop(registry string) {
	for {
		s.adoptPayout(registry)
		time.Sleep(10 * time.Minute)
	}
}
