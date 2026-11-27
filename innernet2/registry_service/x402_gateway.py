"""x402 gateway: one INNERNET listing in x402 directories (Coinbase Bazaar, x402scan) in front of
every compute provider.

An agent sends a CPU job, over HTTP (POST /x402/cpu) or MCP (tool run_cpu_job at /mcp). Without
payment it gets an x402 price whose recipient is the payout contract of the provider the gateway
picked. That contract pays the provider 97.5% and the network 2.5% on chain, so INNERNET never
receives, holds or forwards money. With a payment (x402 v2, scheme "exact", USDC on Base) the gateway:

  1. checks the payment names a listed compute provider's payout contract and its price,
  2. asks the facilitator to verify it (nothing moves yet),
  3. runs the job on that provider, which accepts it from the gateway's published client key,
  4. only if the provider ran it and signed a receipt: asks the facilitator to settle (the USDC moves
     to the payout contract) and returns the output, the receipt and the settlement.

A job that cannot run is never charged; nothing has to be refunded.

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
    """Mount /x402 (HTTP) and /mcp (MCP) on the registry app.

    candidates() -> [{"entry": provider entry, "route": route}] of listed, online compute providers on Base
    that run provider 0.7.1 or newer.
    run(entry, route, job, amount) -> provider job result (an x402 job, no prepaid credit).
    Both are replaceable for tests."""
    from . import presence

    if facilitator is None:
        key_id, secret = os.environ.get("CDP_API_KEY_ID", "").strip(), os.environ.get("CDP_API_KEY_SECRET", "").strip()
        facilitator = Facilitator(os.environ.get("INNERNET_X402_FACILITATOR", CDP_FACILITATOR), key_id, secret) \
            if key_id and secret else None
    http_url, mcp_url = settings.origin + P + "/x402/cpu", settings.origin + P + "/mcp"
    key_path = os.path.join(os.path.dirname(settings.db_path) or ".", "x402-client.key")
    client_key = load_client_key(key_path)
    # Providers run x402 jobs only from this key (they read it from /v1/config).
    app.state.x402_gateway_client = client_key.public_key().public_bytes_raw().hex() if facilitator else None

    def version_ok(software: str) -> bool:
        v = str(software).split("/")[-1].split(".")
        try:
            return tuple(int(x) for x in v[:3]) >= (0, 7, 1)
        except ValueError:
            return False

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
            if not version_ok(rec.get("software", "")):
                continue
            route = {"path": rec["path"], "host": rec["endpoint"]["host"], "port": rec["endpoint"]["port"]}
            if rec["path"] == "relay":
                route["relay_key"] = rec.get("relay_key")
            if rec["path"] == "tunnel":
                route["http_base"] = settings.origin + P + f"/t/{p['id']}"
            out.append({"entry": e, "route": route})
        return out

    candidates = candidates or default_candidates

    def default_run(entry: dict, route: dict, job: dict, amount: int) -> dict:
        from ..irm_client import Provider
        prov = Provider(entry, client_key, route=route, terms=terms.summary()["client"]["sha256"], timeout=30)
        wasm = base64.b64decode(job["wasm"]) if job.get("wasm") else None
        res = prov.run_job(wasm, stdin=base64.b64decode(job.get("input") or ""), args=tuple(job.get("args") or ()),
                           seed=int(job.get("seed") or 0), max_seconds=job["max_seconds"],
                           wasm_url=job.get("wasm_url"), wasm_sha256=job.get("wasm_sha256"), queue_seconds=20,
                           x402_amount=amount)
        return {"output": base64.b64encode(res["output"]).decode(), "exit_code": res["exit_code"],
                "stderr": res["stderr"], "seconds": res["seconds"], "error": res["error"], "receipt": res["receipt"]}

    run = run or default_run

    def requirements(entry: dict, seconds: int) -> dict:
        return {"scheme": "exact", "network": BASE, "amount": str(price_for(cpu_hour(entry), seconds)),
                "asset": USDC_BASE, "payTo": entry["payto"][BASE], "maxTimeoutSeconds": 120, "extra": dict(USDC_EXTRA)}

    DESCRIPTION = ("Run a WebAssembly (WASI) program on an INNERNET compute provider: standard input in, standard "
                   "output out, with the provider's signed receipt. Sealed off from files and network; the same "
                   "program, input and seed give the same output. Price: your time limit at the provider's CPU-hour "
                   "rate. Paid straight to the provider's payout contract, and only collected when the job ran.")

    def resource(url: str) -> dict:
        return {"url": url, "mimeType": "application/json", "serviceName": "INNERNET compute",
                "description": DESCRIPTION, "tags": ["compute", "wasm", "serverless", "cpu", "depin"],
                "iconUrl": settings.origin + P + "/static/favicon.svg"}

    JOB_SCHEMA = {"type": "object", "properties": {
        "wasm": {"type": "string", "description": "base64 WebAssembly module (WASI command), up to 1.5 MiB"},
        "wasm_url": {"type": "string", "description": "https address of a larger module (with wasm_sha256)"},
        "wasm_sha256": {"type": "string"},
        "input": {"type": "string", "description": "base64 standard input"},
        "input_text": {"type": "string", "description": "standard input as plain text (instead of input)"},
        "args": {"type": "array", "items": {"type": "string"}},
        "seed": {"type": "integer"},
        "max_seconds": {"type": "integer", "minimum": 1, "maximum": MAX_SECONDS, "default": 10}}}
    OUTPUT_EXAMPLE = {"output": "<base64 standard output>", "exit_code": 0, "seconds": "0.050",
                      "provider": {"id": "<provider id>", "name": "<name>"},
                      "receipt": {"payload": {"version": "PAY-1-USAGE"}, "signature": "<ed25519>"}}

    def bazaar(mcp: bool) -> dict:
        if mcp:
            info = {"input": {"type": "mcp", "toolName": "run_cpu_job", "description": DESCRIPTION,
                              "transport": "streamable-http", "inputSchema": JOB_SCHEMA, "example": EXAMPLE_JOB},
                    "output": {"type": "json", "example": OUTPUT_EXAMPLE}}
            props = {"type": {"type": "string", "const": "mcp"}, "toolName": {"type": "string"},
                     "description": {"type": "string"}, "transport": {"type": "string", "enum": ["streamable-http", "sse"]},
                     "inputSchema": {"type": "object"}, "example": {"type": "object"}}
            req = ["type", "toolName", "inputSchema"]
        else:
            info = {"input": {"type": "http", "method": "POST", "bodyType": "json", "body": EXAMPLE_JOB},
                    "output": {"type": "json", "example": OUTPUT_EXAMPLE}}
            props = {"type": {"type": "string", "const": "http"}, "method": {"type": "string", "enum": ["POST"]},
                     "bodyType": {"type": "string", "enum": ["json"]}, "body": JOB_SCHEMA}
            req = ["type", "method", "bodyType", "body"]
        return {"info": info, "schema": {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object",
                                         "properties": {"input": {"type": "object", "properties": props, "required": req},
                                                        "output": {"type": "object", "properties": {
                                                            "type": {"type": "string"}, "example": {"type": "object"}},
                                                            "required": ["type"]}},
                                         "required": ["input"]}}

    def required(entry: dict, seconds: int, error: str, mcp: bool) -> dict:
        return {"x402Version": 2, "error": error, "resource": resource(mcp_url if mcp else http_url),
                "accepts": [requirements(entry, seconds)], "extensions": {"bazaar": bazaar(mcp)}}

    def parse_job(job) -> dict:
        """Check a job; raises ValueError with a message for the caller."""
        if not isinstance(job, dict):
            raise ValueError("the job must be a JSON object: " + json.dumps(EXAMPLE_JOB))
        job = dict(job)
        if job.get("input_text") is not None and not job.get("input"):
            job["input"] = base64.b64encode(str(job.pop("input_text")).encode()).decode()
        job.pop("input_text", None)
        if (not job.get("wasm")) == (not job.get("wasm_url")):
            raise ValueError("the job needs wasm (base64 module) or wasm_url with wasm_sha256")
        try:
            seconds = int(job.get("max_seconds") or 10)
            if job.get("wasm"):
                base64.b64decode(job["wasm"], validate=True)
            base64.b64decode(job.get("input") or "", validate=True)
        except (ValueError, TypeError, binascii.Error):
            raise ValueError("wasm and input must be base64; max_seconds a whole number")
        if not 1 <= seconds <= MAX_SECONDS:
            raise ValueError(f"max_seconds must be 1 to {MAX_SECONDS}")
        if job.get("wasm_url") and not re.fullmatch(r"[0-9a-f]{64}", str(job.get("wasm_sha256", ""))):
            raise ValueError("wasm_url needs wasm_sha256 (64 hex)")
        if not isinstance(job.get("args") or [], list) or len(job.get("args") or []) > 32:
            raise ValueError("args must be a list of at most 32 strings")
        job["max_seconds"] = seconds
        return job

    def cheapest(cands: list[dict]) -> dict:
        """The entry of the provider with the lowest CPU-hour price (ties: by id, so it stays put)."""
        return min(cands, key=lambda c: (Decimal(str(cpu_hour(c["entry"]))), c["entry"]["id"]))["entry"]

    def handle(job: dict, payload: dict | None, mcp: bool) -> dict:
        """One paid job, whatever the transport. Outcomes:
        {"kind": "pay", "required": PaymentRequired}                - no or unusable payment (nothing charged)
        {"kind": "error", "status": n, "message": str}               - nothing charged
        {"kind": "settle_failed", "required": ..., "settle": s}      - the job ran but the payment did not settle
        {"kind": "done", "result": {...}, "settle": s}               - ran, paid"""
        cands = candidates()
        if not cands:
            return {"kind": "error", "status": 503,
                    "message": "no compute provider is online right now; try again in a few minutes"}
        if payload is None:
            return {"kind": "pay", "required": required(cheapest(cands), job["max_seconds"],
                                                        "Payment required" if mcp else "PAYMENT-SIGNATURE header is required", mcp)}
        if facilitator is None:
            return {"kind": "error", "status": 503, "message": "payments are not switched on yet (no facilitator configured)"}
        try:
            accepted = payload["accepted"]
            pay_to = str(accepted["payTo"]).lower()
        except (KeyError, TypeError):
            return {"kind": "pay", "required": required(cheapest(cands), job["max_seconds"],
                                                        "not a valid x402 v2 payment payload", mcp)}
        chosen = next((c for c in cands if c["entry"]["payto"][BASE].lower() == pay_to), None)
        if chosen is None:
            return {"kind": "pay", "required": required(cheapest(cands), job["max_seconds"],
                                                        "that provider is no longer available; pay the provider named here", mcp)}
        entry = chosen["entry"]
        req = requirements(entry, job["max_seconds"])
        try:
            amount_ok = int(accepted.get("amount", 0)) >= int(req["amount"])
        except (TypeError, ValueError):
            amount_ok = False
        if (payload.get("x402Version") != 2 or accepted.get("scheme") != "exact" or accepted.get("network") != BASE
                or str(accepted.get("asset", "")).lower() != USDC_BASE.lower() or not amount_ok):
            return {"kind": "pay", "required": required(entry, job["max_seconds"],
                                                        "payment does not match the price for this job", mcp)}
        req["amount"] = str(accepted["amount"])   # what the client signed (never less than the price)
        try:
            v = facilitator.verify(payload, req)
        except Exception as exc:  # noqa: BLE001
            log.warning("x402 verify: %s", exc)
            return {"kind": "error", "status": 502, "message": "the payment service could not check the payment; nothing was charged"}
        if not v.get("isValid"):
            return {"kind": "pay", "required": required(entry, job["max_seconds"], "payment refused: " +
                                                        str(v.get("invalidMessage") or v.get("invalidReason") or "invalid"), mcp)}
        try:
            out = run(entry, chosen["route"], job, int(req["amount"]))
        except Exception as exc:  # noqa: BLE001
            log.warning("x402 job on %s: %s", entry["id"][:12], exc)
            return {"kind": "error", "status": 502,
                    "message": "the provider could not run the job, so nothing was charged: " + str(exc)[:300]}
        receipt = (out.get("receipt") or {}).get("payload") or out.get("receipt") or {}
        if Decimal(str(receipt.get("cost") or "0")) <= 0:
            return {"kind": "error", "status": 422, "message": "the job did not run (" + str(out.get("error") or
                                                                                            "refused") + "), so nothing was charged"}
        try:
            s = facilitator.settle(payload, req)
        except Exception as exc:  # noqa: BLE001
            log.warning("x402 settle: %s", exc)
            s = {"success": False, "errorReason": "settle_unavailable", "transaction": "", "network": BASE}
        if not s.get("success") or not re.fullmatch(r"0x[0-9a-fA-F]{64}", str(s.get("transaction", ""))):
            store.audit(entry["id"], "x402-unpaid", f"job ran but payment did not settle: {s.get('errorReason')}", None)
            return {"kind": "settle_failed", "settle": s, "required": required(entry, job["max_seconds"], "Settlement failed: " +
                                                                              str(s.get("errorMessage") or s.get("errorReason") or "failed"), mcp)}
        store.audit(entry["id"], "x402-paid", f"{Decimal(int(req['amount'])) / 1_000_000} USDC from "
                                               f"{s.get('payer') or v.get('payer')}, tx {s['transaction']}", None)
        out["provider"] = {"id": entry["id"], "name": entry.get("name", "")}
        out["paid"] = {"usdc": str(Decimal(int(req["amount"])) / 1_000_000), "transaction": s["transaction"],
                       "pay_to": entry["payto"][BASE]}
        return {"kind": "done", "result": out, "settle": s}

    CORS = {"Access-Control-Allow-Origin": "*",
            "Access-Control-Expose-Headers": "PAYMENT-REQUIRED, PAYMENT-RESPONSE, Mcp-Session-Id"}

    # ---- HTTP ----------------------------------------------------------------------------------

    @app.options(P + "/x402/cpu")
    def x402_preflight():
        return JSONResponse({}, headers={**CORS, "Access-Control-Allow-Methods": "POST, OPTIONS",
                                         "Access-Control-Allow-Headers": "Content-Type, PAYMENT-SIGNATURE"})

    def price_info() -> dict:
        cands = candidates()
        best = cheapest(cands) if cands else None
        return {"providers_online": len(cands),
                "price_10s_usdc": str(Decimal(price_for(cpu_hour(best), 10)) / 1_000_000) if best else None,
                "cpu_hour_usdc": cpu_hour(best) if best else None, "max_seconds": MAX_SECONDS,
                "minimum_usdc": str(Decimal(MIN_PRICE) / 1_000_000), "network": BASE, "asset": USDC_BASE,
                "facilitator": "on" if facilitator else "not configured"}

    @app.get(P + "/x402")
    def x402_info():
        """What the gateway sells, at today's prices (no payment needed)."""
        info = price_info()
        return {"x402Version": 2, "services": [{
            "resource": http_url, "method": "POST", "description": DESCRIPTION, "example_body": EXAMPLE_JOB,
            "mcp": {"url": mcp_url, "tool": "run_cpu_job"}, **info}]}

    @app.post(P + "/x402/cpu")
    async def x402_cpu(request: Request):
        raw = await request.body()
        if len(raw) > MAX_BODY:
            raise HTTPException(413, "job too large (module up to 1.5 MiB; larger: wasm_url + wasm_sha256)")
        try:
            job = parse_job(json.loads(raw or b"{}"))
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        sig = request.headers.get("payment-signature", "")
        payload = None
        if sig:
            try:
                payload = json.loads(base64.b64decode(sig))
            except (ValueError, binascii.Error):
                payload = {}
        r = await run_in_threadpool(handle, job, payload, False)
        if r["kind"] == "pay":
            return JSONResponse(r["required"], status_code=402, headers={"PAYMENT-REQUIRED": b64json(r["required"]), **CORS})
        if r["kind"] == "error":
            return JSONResponse({"error": r["message"]}, status_code=r["status"], headers=CORS)
        if r["kind"] == "settle_failed":
            return JSONResponse(r["required"], status_code=402, headers={
                "PAYMENT-REQUIRED": b64json(r["required"]), "PAYMENT-RESPONSE": b64json(r["settle"]), **CORS})
        return JSONResponse(r["result"], headers={"PAYMENT-RESPONSE": b64json(r["settle"]), **CORS})

    # ---- MCP (Streamable HTTP, stateless JSON responses) -----------------------------------------

    TOOLS = [
        {"name": "run_cpu_job", "title": "Run a CPU job (paid with x402)",
         "description": DESCRIPTION + " Call without payment to get the x402 price; pay with _meta['x402/payment'].",
         "inputSchema": JOB_SCHEMA},
        {"name": "innernet_prices", "title": "INNERNET compute prices (free)",
         "description": "Current price for CPU jobs, how many providers are online, limits.",
         "inputSchema": {"type": "object", "properties": {}}},
    ]

    def tool_result(obj: dict, *, error: bool = False, text: str | None = None, meta: dict | None = None) -> dict:
        res = {"content": [{"type": "text", "text": text if text is not None else json.dumps(obj, separators=(",", ":"))}],
               "structuredContent": obj}
        if error:
            res["isError"] = True
        if meta:
            res["_meta"] = meta
        return res

    def call_tool(params: dict) -> dict:
        name, args = params.get("name"), params.get("arguments") or {}
        if name == "innernet_prices":
            return tool_result(price_info())
        if name != "run_cpu_job":
            raise LookupError(f"unknown tool {name}")
        try:
            job = parse_job(args)
        except ValueError as exc:
            return tool_result({"error": str(exc)}, error=True, text=str(exc))
        payload = ((params.get("_meta") or {}).get("x402/payment"))
        r = handle(job, payload if isinstance(payload, dict) else None, True)
        if r["kind"] == "pay":
            return tool_result(r["required"], error=True)
        if r["kind"] == "error":
            return tool_result({"error": r["message"]}, error=True, text=r["message"])
        if r["kind"] == "settle_failed":
            return tool_result(r["required"], error=True, meta={"x402/payment-response": r["settle"]})
        res = r["result"]
        try:
            text = base64.b64decode(res["output"]).decode("utf-8")
        except (UnicodeDecodeError, ValueError, binascii.Error):
            text = "(binary output, base64 in structuredContent.output)"
        summary = f"exit code {res['exit_code']}, {res['seconds']} s on {res['provider']['name'] or res['provider']['id'][:12]}, " \
                  f"paid {res['paid']['usdc']} USDC (tx {res['paid']['transaction']})\n\n{text}"
        return tool_result(res, text=summary, meta={"x402/payment-response": r["settle"]})

    def rpc(msg: dict) -> dict | None:
        mid, method, params = msg.get("id"), msg.get("method"), msg.get("params") or {}
        if mid is None:                     # a notification (e.g. notifications/initialized): no answer
            return None
        try:
            if method == "initialize":
                result = {"protocolVersion": params.get("protocolVersion") or "2025-06-18",
                          "capabilities": {"tools": {"listChanged": False}},
                          "serverInfo": {"name": "innernet", "title": "INNERNET compute", "version": "0.7.1"},
                          "instructions": "Run WebAssembly jobs on INNERNET providers, paid per call with x402 "
                                          "(USDC on Base). innernet_prices is free; run_cpu_job answers with the price "
                                          "first, then runs when called again with _meta['x402/payment']."}
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "tools/call":
                result = call_tool(params)
            else:
                return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}
        except LookupError as exc:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": str(exc)}}
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    @app.options(P + "/mcp")
    def mcp_preflight():
        return JSONResponse({}, headers={**CORS, "Access-Control-Allow-Methods": "POST, GET, DELETE, OPTIONS",
                                         "Access-Control-Allow-Headers": "Content-Type, Accept, Mcp-Session-Id, MCP-Protocol-Version"})

    @app.get(P + "/mcp")
    def mcp_get():
        return JSONResponse({"error": "this MCP server answers POST requests (no event stream)"}, status_code=405,
                            headers={"Allow": "POST", **CORS})

    @app.post(P + "/mcp")
    async def mcp_post(request: Request):
        raw = await request.body()
        if len(raw) > MAX_BODY:
            return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "request too large"}},
                                status_code=413, headers=CORS)
        try:
            msg = json.loads(raw)
        except ValueError:
            return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}},
                                status_code=400, headers=CORS)
        batch = isinstance(msg, list)
        out = [await run_in_threadpool(rpc, m) for m in (msg if batch else [msg]) if isinstance(m, dict)]
        out = [o for o in out if o is not None]
        if not out:
            return JSONResponse(None, status_code=202, headers=CORS)
        return JSONResponse(out if batch else out[0], headers=CORS)
