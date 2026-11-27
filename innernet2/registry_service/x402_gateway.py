"""x402 gateway: one INNERNET listing in x402 directories (Coinbase Bazaar, x402scan) in front of
every compute provider.

An agent POSTs a CPU job to /x402/cpu. Without payment it gets HTTP 402 with a price and a recipient:
the payout contract of the provider the gateway picked. That contract pays the provider 97.5% and the
network 2.5% on chain, so INNERNET never receives, holds or forwards money. With a payment
(PAYMENT-SIGNATURE, x402 v2, scheme "exact", USDC on Base) the gateway:

  1. checks the payment names a listed compute provider's payout contract and its price,
  2. asks the facilitator to verify it, then to settle it (the USDC moves to that contract),
  3. hands the settlement transaction to the provider as credit (the provider confirms it on chain
     itself) and runs the job there, paid from that credit,
  4. returns the output, the provider's signed receipt and PAYMENT-RESPONSE.

You pay for the time limit you choose (max_seconds), at that provider's CPU-hour price, at least
0.001 USDC. The gateway signs its provider requests with its own client key (not a wallet key).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import math
import os
import re
import secrets
import time
from decimal import Decimal
from fractions import Fraction

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

log = logging.getLogger("innernet.registry.x402")

BASE = "eip155:8453"
USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
USDC_EXTRA = {"name": "USD Coin", "version": "2"}         # EIP-712 domain of USDC on Base
CDP_FACILITATOR = "https://api.cdp.coinbase.com/platform/v2/x402"
MIN_PRICE = 1000                                          # 0.001 USDC, in base units
MAX_SECONDS = 120
MAX_BODY = 3 << 20                                        # a 1.5 MiB module, base64, with input
ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")

EXAMPLE_JOB = {"wasm": "<base64 WebAssembly (WASI) module>", "input": "<base64 standard input>",
               "args": [], "seed": 0, "max_seconds": 10}


# ---- Coinbase (CDP) facilitator --------------------------------------------------------------

def cdp_jwt(key_id: str, secret_b64: str, method: str, url: str, now: int | None = None) -> str:
    """Bearer token for one CDP REST call: EdDSA JWT over the key's 32-byte seed, valid 2 minutes."""
    now = int(time.time()) if now is None else now
    raw = base64.b64decode(secret_b64)
    if len(raw) not in (32, 64):
        raise ValueError("CDP_API_KEY_SECRET must be the base64 Ed25519 secret from the CDP portal")
    key = Ed25519PrivateKey.from_private_bytes(raw[:32])
    host_path = url.split("://", 1)[1]
    header = {"alg": "EdDSA", "kid": key_id, "typ": "JWT", "nonce": secrets.token_hex(16)}
    claims = {"sub": key_id, "iss": "cdp", "aud": ["cdp_service"], "nbf": now, "exp": now + 120,
              "uri": f"{method.upper()} {host_path}"}

    def b64(obj) -> str:
        data = obj if isinstance(obj, bytes) else json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    signing = b64(header) + "." + b64(claims)
    return signing + "." + b64(key.sign(signing.encode()))


class Facilitator:
    """verify / settle against an x402 v2 facilitator (CDP by default)."""

    def __init__(self, url: str = CDP_FACILITATOR, key_id: str = "", secret: str = "", timeout: float = 30):
        self.url, self.key_id, self.secret, self.timeout = url.rstrip("/"), key_id, secret, timeout

    def _post(self, op: str, payload: dict, requirements: dict) -> dict:
        url = f"{self.url}/{op}"
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                   "User-Agent": "innernet-registry/1.0 (+https://innernetcorp.com)"}
        if self.key_id:
            headers["Authorization"] = "Bearer " + cdp_jwt(self.key_id, self.secret, "POST", url)
        body = {"x402Version": 2, "paymentPayload": payload, "paymentRequirements": requirements}
        r = httpx.post(url, json=body, headers=headers, timeout=self.timeout)
        try:
            out = r.json()
        except ValueError:
            out = {}
        if r.status_code >= 500 or not isinstance(out, dict):
            raise RuntimeError(f"facilitator {op} failed ({r.status_code})")
        if r.status_code >= 400 and not out:
            raise RuntimeError(f"facilitator {op} refused ({r.status_code}): {r.text[:200]}")
        return out

    def verify(self, payload: dict, requirements: dict) -> dict:
        return self._post("verify", payload, requirements)

    def settle(self, payload: dict, requirements: dict) -> dict:
        return self._post("settle", payload, requirements)


# ---- the gateway -----------------------------------------------------------------------------

def b64json(obj) -> str:
    return base64.b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode()


def cpu_hour(entry: dict) -> str | None:
    """The provider's signed CMP-1 price per CPU-hour in USDC, or None if it is not priced that way."""
    p = (entry.get("prices") or {}).get("CMP-1")
    if isinstance(p, dict) and p.get("asset") == "USDC" and p.get("unit") == "CPU-hour":
        return str(p["amount"])
    return None


def price_for(cpu_hour_price: str, seconds: int) -> int:
    """USDC base units for `seconds` at a CPU-hour price, rounded up, at least MIN_PRICE."""
    per_hour = Fraction(Decimal(str(cpu_hour_price))) * 1_000_000
    return max(MIN_PRICE, math.ceil(per_hour * seconds / 3600))


def load_client_key(path: str) -> Ed25519PrivateKey:
    """The gateway's own Ed25519 client key for provider requests (identity only; it holds no money)."""
    if os.path.exists(path):
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    key = Ed25519PrivateKey.generate()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return key


def register(app, *, store, settings, P: str, terms, facilitator: Facilitator | None = None, run=None,
             candidates=None) -> None:
    """Mount /x402 on the registry app.

    candidates() -> [{"entry": provider entry, "route": route}] of listed, online compute providers on Base.
    run(entry, route, tx, job) -> provider job result (credit with tx, then run).
    Both are replaceable for tests."""
    from . import presence

    if facilitator is None:
        key_id, secret = os.environ.get("CDP_API_KEY_ID", "").strip(), os.environ.get("CDP_API_KEY_SECRET", "").strip()
        facilitator = Facilitator(os.environ.get("INNERNET_X402_FACILITATOR", CDP_FACILITATOR), key_id, secret) \
            if key_id and secret else None
    resource_url = settings.origin + P + "/x402/cpu"

    def default_candidates() -> list[dict]:
        out = []
        now = int(time.time())
        for p in store.providers():
            e = p["entry"]
            if (p["state"] != "listed" or "CMP-1" not in e.get("services", []) or cpu_hour(e) is None
                    or not ADDR.match(e.get("payto", {}).get(BASE, ""))):
                continue
            live = presence.live(store, p["id"], now)
            if not live or not live["online"]:
                continue
            rec = live["record"]["payload"]
            route = {"path": rec["path"], "host": rec["endpoint"]["host"], "port": rec["endpoint"]["port"]}
            if rec["path"] == "relay":
                route["relay_key"] = rec.get("relay_key")
            if rec["path"] == "tunnel":
                route["http_base"] = settings.origin + P + f"/t/{p['id']}"
            out.append({"entry": e, "route": route})
        return out

    candidates = candidates or default_candidates
    key_path = os.path.join(os.path.dirname(settings.db_path) or ".", "x402-client.key")
    client_key: list = []

    def default_run(entry: dict, route: dict, tx: str, job: dict) -> dict:
        from ..irm_client import Provider
        if not client_key:
            client_key.append(load_client_key(key_path))
        prov = Provider(entry, client_key[0], route=route, terms=terms.summary()["client"]["sha256"], timeout=30)
        for attempt in range(6):                     # the provider may not see the transaction for a few seconds
            try:
                prov.credit(tx)
                break
            except Exception as exc:  # noqa: BLE001 - provider says why
                if attempt == 5 or "not found" not in str(exc):
                    raise
                time.sleep(2)
        wasm = base64.b64decode(job["wasm"]) if job.get("wasm") else None
        res = prov.run_job(wasm, stdin=base64.b64decode(job.get("input") or ""), args=tuple(job.get("args") or ()),
                           seed=int(job.get("seed") or 0), max_seconds=job["max_seconds"],
                           wasm_url=job.get("wasm_url"), wasm_sha256=job.get("wasm_sha256"), queue_seconds=20)
        return {"output": base64.b64encode(res["output"]).decode(), "exit_code": res["exit_code"],
                "stderr": res["stderr"], "seconds": res["seconds"], "error": res["error"], "receipt": res["receipt"]}

    run = run or default_run

    def requirements(entry: dict, seconds: int) -> dict:
        return {"scheme": "exact", "network": BASE, "amount": str(price_for(cpu_hour(entry), seconds)),
                "asset": USDC_BASE, "payTo": entry["payto"][BASE], "maxTimeoutSeconds": 120, "extra": dict(USDC_EXTRA)}

    def resource() -> dict:
        return {"url": resource_url, "mimeType": "application/json", "serviceName": "INNERNET compute",
                "description": "Run a WebAssembly (WASI) program on an INNERNET compute provider: standard input in, "
                               "standard output out, with the provider's signed receipt. Sealed off from files and "
                               "network; the same program, input and seed give the same output. Price: your time "
                               "limit at the provider's CPU-hour rate. Paid straight to the provider's payout contract.",
                "tags": ["compute", "wasm", "serverless", "cpu", "depin"],
                "iconUrl": settings.origin + P + "/static/favicon.svg"}

    def bazaar() -> dict:
        return {"info": {"input": {"type": "http", "method": "POST", "bodyType": "json", "body": EXAMPLE_JOB},
                         "output": {"type": "json", "example": {
                             "output": "<base64 standard output>", "exit_code": 0, "seconds": 0.05,
                             "provider": {"id": "<provider id>", "name": "<name>"},
                             "receipt": {"payload": {"version": "PAY-1-USAGE"}, "signature": "<ed25519>"}}}},
                "schema": {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object",
                           "properties": {"input": {"type": "object", "properties": {
                               "type": {"type": "string", "const": "http"},
                               "method": {"type": "string", "enum": ["POST"]},
                               "bodyType": {"type": "string", "enum": ["json"]},
                               "body": {"type": "object", "properties": {
                                   "wasm": {"type": "string", "description": "base64 WebAssembly module (WASI command)"},
                                   "wasm_url": {"type": "string"}, "wasm_sha256": {"type": "string"},
                                   "input": {"type": "string", "description": "base64 standard input"},
                                   "args": {"type": "array", "items": {"type": "string"}},
                                   "seed": {"type": "integer"},
                                   "max_seconds": {"type": "integer", "minimum": 1, "maximum": MAX_SECONDS}}}},
                               "required": ["type", "method", "bodyType", "body"]},
                               "output": {"type": "object", "properties": {"type": {"type": "string"},
                                                                          "example": {"type": "object"}},
                                          "required": ["type"]}},
                           "required": ["input"]}}

    def payment_required(entry: dict, seconds: int, error: str) -> JSONResponse:
        body = {"x402Version": 2, "error": error, "resource": resource(), "accepts": [requirements(entry, seconds)],
                "extensions": {"bazaar": bazaar()}}
        return JSONResponse(body, status_code=402, headers={"PAYMENT-REQUIRED": b64json(body), **CORS})

    def parse_job(raw: bytes) -> dict:
        try:
            job = json.loads(raw or b"{}")
        except ValueError:
            raise HTTPException(400, "the body must be JSON: " + json.dumps(EXAMPLE_JOB))
        if not isinstance(job, dict) or (not job.get("wasm")) == (not job.get("wasm_url")):
            raise HTTPException(400, "the job needs wasm (base64 module) or wasm_url with wasm_sha256")
        try:
            seconds = int(job.get("max_seconds") or 10)
            if job.get("wasm"):
                base64.b64decode(job["wasm"], validate=True)
            base64.b64decode(job.get("input") or "", validate=True)
        except (ValueError, TypeError, binascii.Error):
            raise HTTPException(400, "wasm and input must be base64; max_seconds a whole number")
        if not 1 <= seconds <= MAX_SECONDS:
            raise HTTPException(400, f"max_seconds must be 1 to {MAX_SECONDS}")
        if job.get("wasm_url") and not re.fullmatch(r"[0-9a-f]{64}", str(job.get("wasm_sha256", ""))):
            raise HTTPException(400, "wasm_url needs wasm_sha256 (64 hex)")
        job["max_seconds"] = seconds
        return job

    def cheapest(cands: list[dict]) -> dict:
        """The entry of the provider with the lowest CPU-hour price (ties: by id, so it stays put)."""
        return min(cands, key=lambda c: (Decimal(str(cpu_hour(c["entry"]))), c["entry"]["id"]))["entry"]

    CORS = {"Access-Control-Allow-Origin": "*",
            "Access-Control-Expose-Headers": "PAYMENT-REQUIRED, PAYMENT-RESPONSE"}

    @app.options(P + "/x402/cpu")
    def x402_preflight():
        return JSONResponse({}, headers={**CORS, "Access-Control-Allow-Methods": "POST, OPTIONS",
                                         "Access-Control-Allow-Headers": "Content-Type, PAYMENT-SIGNATURE"})

    @app.get(P + "/x402")
    def x402_info():
        """What the gateway sells, at today's prices (no payment needed)."""
        cands = candidates()
        best = cheapest(cands) if cands else None
        return {"x402Version": 2, "services": [{
            "resource": resource_url, "method": "POST", "network": BASE, "asset": USDC_BASE,
            "description": resource()["description"], "example_body": EXAMPLE_JOB,
            "providers_online": len(cands),
            "price_10s_usdc": str(Decimal(price_for(cpu_hour(best), 10)) / 1_000_000) if best else None,
            "facilitator": "on" if facilitator else "not configured"}]}

    @app.post(P + "/x402/cpu")
    async def x402_cpu(request: Request):
        raw = await request.body()
        if len(raw) > MAX_BODY:
            raise HTTPException(413, "job too large (module up to 1.5 MiB; larger: wasm_url + wasm_sha256)")
        job = parse_job(raw)
        cands = await run_in_threadpool(candidates)
        if not cands:
            raise HTTPException(503, "no compute provider is online right now; try again in a few minutes",
                                headers=CORS)
        sig = request.headers.get("payment-signature", "")
        if not sig:
            return payment_required(cheapest(cands), job["max_seconds"], "PAYMENT-SIGNATURE header is required")
        if facilitator is None:
            raise HTTPException(503, "payments are not switched on yet (no facilitator configured)", headers=CORS)
        try:
            payload = json.loads(base64.b64decode(sig))
            accepted = payload["accepted"]
            pay_to = str(accepted["payTo"]).lower()
        except (ValueError, KeyError, TypeError, binascii.Error):
            return payment_required(cheapest(cands), job["max_seconds"], "PAYMENT-SIGNATURE is not a valid x402 v2 payload")
        chosen = next((c for c in cands if c["entry"]["payto"][BASE].lower() == pay_to), None)
        if chosen is None:
            return payment_required(cheapest(cands), job["max_seconds"],
                                    "that provider is no longer available; pay the provider named here")
        req = requirements(chosen["entry"], job["max_seconds"])
        if (payload.get("x402Version") != 2 or accepted.get("scheme") != "exact" or accepted.get("network") != BASE
                or str(accepted.get("asset", "")).lower() != USDC_BASE.lower()
                or int(accepted.get("amount", 0)) < int(req["amount"])):
            return payment_required(chosen["entry"], job["max_seconds"], "payment does not match the price for this job")
        req["amount"] = str(accepted["amount"])   # what the client signed (never less than the price)
        try:
            v = await run_in_threadpool(facilitator.verify, payload, req)
        except Exception as exc:  # noqa: BLE001
            log.warning("x402 verify: %s", exc)
            raise HTTPException(502, "the payment service could not check the payment; nothing was charged", headers=CORS)
        if not v.get("isValid"):
            return payment_required(chosen["entry"], job["max_seconds"],
                                    "payment refused: " + str(v.get("invalidMessage") or v.get("invalidReason") or "invalid"))
        try:
            s = await run_in_threadpool(facilitator.settle, payload, req)
        except Exception as exc:  # noqa: BLE001
            log.warning("x402 settle: %s", exc)
            raise HTTPException(502, "the payment service could not settle the payment; nothing was charged", headers=CORS)
        if not s.get("success") or not re.fullmatch(r"0x[0-9a-fA-F]{64}", str(s.get("transaction", ""))):
            resp = payment_required(chosen["entry"], job["max_seconds"],
                                    "payment not settled: " + str(s.get("errorMessage") or s.get("errorReason") or "failed"))
            resp.headers["PAYMENT-RESPONSE"] = b64json(s)
            return resp
        store.audit(chosen["entry"]["id"], "x402-paid",
                    f"{Decimal(int(req['amount'])) / 1_000_000} USDC from {s.get('payer') or v.get('payer')}, tx {s['transaction']}",
                    None)
        try:
            out = await run_in_threadpool(run, chosen["entry"], chosen["route"], s["transaction"], job)
        except Exception as exc:  # noqa: BLE001
            log.warning("x402 job on %s: %s", chosen["entry"]["id"][:12], exc)
            return JSONResponse({"error": "paid, but the provider could not run the job: " + str(exc)[:300] +
                                 ". The payment stays as credit at this provider for the INNERNET gateway; "
                                 "contact support with the transaction to have the job run again.",
                                 "transaction": s["transaction"], "provider": {"id": chosen["entry"]["id"]}},
                                status_code=502, headers={"PAYMENT-RESPONSE": b64json(s), **CORS})
        out["provider"] = {"id": chosen["entry"]["id"], "name": chosen["entry"].get("name", "")}
        out["paid"] = {"usdc": str(Decimal(int(req["amount"])) / 1_000_000), "transaction": s["transaction"],
                       "pay_to": chosen["entry"]["payto"][BASE]}
        return JSONResponse(out, headers={"PAYMENT-RESPONSE": b64json(s), **CORS})
