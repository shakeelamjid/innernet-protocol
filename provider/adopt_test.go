package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPayoutContractForFindsTheSplitOfAWallet(t *testing.T) {
	const wallet = "0xdea94ef76afa86bf1638b645f76108df65890c0b"
	const factory = "0x8d2d3b75e4bc887842bd4298fed5c9d2ed443064"
	const split = "0x1111111111111111111111111111111111111111"
	code := "0xef0100d2e28229f6f2c235e57de2ebc727025a1d0530fb" // EIP-7702 delegation: still a wallet
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		res := ""
		switch req.Method {
		case "eth_getCode":
			res = code
		case "eth_call":
			call := req.Params[0].(map[string]any)
			if call["to"] != factory || !strings.HasSuffix(call["data"].(string), wallet[2:]) {
				t.Errorf("unexpected call %v", call)
			}
			res = "0x" + strings.Repeat("0", 24) + split[2:]
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": res})
	}))
	defer rpc.Close()
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"networks": []any{map[string]any{"caip2": "eip155:8453", "factory": factory}}})
	}))
	defer reg.Close()
	got, err := payoutContractFor(rpc.URL, reg.URL, "eip155:8453", wallet)
	if err != nil || got != split {
		t.Fatalf("got %q, %v", got, err)
	}
	code = "0x6080604052" // a real contract: nothing to adopt
	if got, _ := payoutContractFor(rpc.URL, reg.URL, "eip155:8453", wallet); got != "" {
		t.Fatalf("adopted for a contract: %q", got)
	}
	if !isWalletCode("0x") || isWalletCode("0x6080") {
		t.Fatal("isWalletCode")
	}
}
