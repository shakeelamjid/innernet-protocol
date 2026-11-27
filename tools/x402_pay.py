#!/usr/bin/env python3
"""Pay for one INNERNET CPU job over x402 from the terminal, the way an agent does.

The wallet key never leaves this computer: it is read from a keystore file (with its password) or
typed in hidden, used here to sign one EIP-3009 USDC authorization, and forgotten. Only the
signature is sent. You pay no gas; the facilitator does.

    python tools/x402_pay.py                       # asks for the private key (hidden)
    python tools/x402_pay.py --wallet wallet.json  # or a wallet file: an encrypted keystore (asks for its
                                                   # password) or a JSON file holding the key (read, never shown)
    python tools/x402_pay.py --dotenv ~/proj/.env --var BURNER_PRIVATE_KEY
                                                   # or a key already kept in a project's .env (read, never shown)
    python tools/x402_pay.py --text "hello" --yes  # skip the confirmation

Needs: pip install eth-account httpx
"""
from __future__ import annotations

import argparse
import base64
import getpass
import json
import secrets
import sys
import time
from decimal import Decimal
from pathlib import Path

import httpx
from eth_account import Account

URL = "https://innernetcorp.com/registry/x402/cpu"
# A 252-byte WebAssembly (WASI) program that writes its standard input back (provider/testdata/echo.wasm).
ECHO_WASM = "AGFzbQEAAAABDAJgBH9/f38Bf2AAAAJEAhZ3YXNpX3NuYXBzaG90X3ByZXZpZXcxB2ZkX3JlYWQAABZ3YXNpX3NuYXBzaG90X3ByZXZpZXcxCGZkX3dyaXRlAAADAgEBBQMBAAIHEwIGbWVtb3J5AgAGX3N0YXJ0AAIKSQFHAQF/AkADQEEAQYAINgIAQQRBgIAENgIAQQBBAEEBQRAQAA0BQRAoAgAhACAARQ0BQQQgADYCAEEBQQBBAUEUEAEaDAALCwsANQRuYW1lARQCAAdmZF9yZWFkAQhmZF93cml0ZQIGAQIBAAFuAxABAgIABGRvbmUBBWFnYWlu"


def b64json(obj) -> str:
    return base64.b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode()


def typed_data(acc: dict, auth: dict) -> dict:
    return {
        "types": {
            "EIP712Domain": [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
                             {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}],
            "TransferWithAuthorization": [
                {"name": "from", "type": "address"}, {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"}, {"name": "validAfter", "type": "uint256"},
                {"name": "validBefore", "type": "uint256"}, {"name": "nonce", "type": "bytes32"}]},
        "primaryType": "TransferWithAuthorization",
        "domain": {"name": acc["extra"]["name"], "version": acc["extra"]["version"],
                   "chainId": int(acc["network"].split(":")[1]), "verifyingContract": acc["asset"]},
        "message": {"from": auth["from"], "to": auth["to"], "value": int(auth["value"]),
                    "validAfter": int(auth["validAfter"]), "validBefore": int(auth["validBefore"]),
                    "nonce": auth["nonce"]},
    }


def sign_payment(account, acc: dict, resource: dict) -> dict:
    """The x402 v2 PaymentPayload for the exact scheme (EIP-3009) on an EVM network."""
    auth = {"from": account.address, "to": acc["payTo"], "value": str(acc["amount"]), "validAfter": "0",
            "validBefore": str(int(time.time()) + int(acc["maxTimeoutSeconds"])), "nonce": "0x" + secrets.token_hex(32)}
    sig = account.sign_typed_data(full_message=typed_data(acc, auth)).signature.hex()
    return {"x402Version": 2, "resource": resource, "accepted": acc,
            "payload": {"signature": sig if sig.startswith("0x") else "0x" + sig, "authorization": auth}}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--wallet", "--keystore", dest="wallet",
                    help="wallet file: encrypted keystore (asks for its password) or JSON with the key")
    ap.add_argument("--dotenv", help="a .env file that already holds the wallet key (it is read, never printed)")
    ap.add_argument("--var", help="the variable in --dotenv that holds the key, e.g. BURNER_PRIVATE_KEY")
    ap.add_argument("--text", default="hello from x402", help="what the job should echo back")
    ap.add_argument("--url", default=URL)
    ap.add_argument("--yes", action="store_true", help="do not ask before paying")
    a = ap.parse_args()

    job = {"wasm": ECHO_WASM, "input": base64.b64encode(a.text.encode()).decode(),
           "max_seconds": 10}
    r = httpx.post(a.url, json=job, timeout=30)
    if r.status_code != 402:
        print(f"expected a price (402), got {r.status_code}: {r.text[:300]}")
        return 1
    required = json.loads(base64.b64decode(r.headers["payment-required"]))
    acc = required["accepts"][0]
    price = Decimal(acc["amount"]) / 1_000_000
    print(f"Price: {price} USDC on {acc['network']} to {acc['payTo']} (the provider's payout contract)")

    if a.wallet:
        data = json.loads(Path(a.wallet).expanduser().read_text())
        if isinstance(data, dict) and ("crypto" in data or "Crypto" in data):
            key = Account.decrypt(data, getpass.getpass("Keystore password: "))
        else:
            key = next((str(data[k]) for k in ("privateKey", "private_key", "privatekey", "key", "secretKey", "secret")
                        if isinstance(data, dict) and data.get(k)), "")
            if not key:
                fields = sorted(data) if isinstance(data, dict) else type(data).__name__
                print(f"no private key field in {a.wallet} (fields: {fields})")
                return 1
    elif a.dotenv:
        if not a.var:
            print("--dotenv needs --var (the name of the key variable)")
            return 1
        key = ""
        for line in Path(a.dotenv).expanduser().read_text().splitlines():
            name, _, value = line.strip().removeprefix("export ").partition("=")
            if name.strip() == a.var:
                key = value.strip().strip("'\"")
        if not key:
            print(f"{a.var} is not set in {a.dotenv}")
            return 1
    else:
        key = getpass.getpass("Private key (hidden, 0x...): ").strip()
    account = Account.from_key(key)
    del key
    print(f"Paying from {account.address}")
    if not a.yes and input(f"Sign {price} USDC to {acc['payTo']}? [y/N] ").strip().lower() != "y":
        print("Not paid.")
        return 1

    payment = sign_payment(account, acc, required["resource"])
    r = httpx.post(a.url, json=job, headers={"PAYMENT-SIGNATURE": b64json(payment)}, timeout=180)
    settle = json.loads(base64.b64decode(r.headers["payment-response"])) if "payment-response" in r.headers else None
    if r.status_code != 200:
        body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {"error": r.text}
        print(f"Not done ({r.status_code}): {body.get('error') or body}")
        if settle:
            print("Settlement:", settle)
        return 1
    out = r.json()
    print("Output:     ", base64.b64decode(out["output"]).decode(errors="replace"))
    print("Provider:   ", out["provider"]["name"], out["provider"]["id"][:16] + "…")
    print("Paid:       ", out["paid"]["usdc"], "USDC to", out["paid"]["pay_to"])
    print("Transaction:", "https://basescan.org/tx/" + out["paid"]["transaction"])
    print("Receipt:    ", json.dumps(out["receipt"]["payload"] if "payload" in out["receipt"] else out["receipt"])[:300])
    return 0


if __name__ == "__main__":
    sys.exit(main())
