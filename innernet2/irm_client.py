"""IRM-1 client (draft): store files on paid providers, check them, pay them, repair them.

How a file is stored (record version IRM1-CLIENT-2):

1. Cut     the file into 64 KiB chunks.
2. Seal    each chunk for the owner with the OB80-2 chunk cipher (fresh object key).
3. Mix     cut each sealed chunk into 4 KiB cells and shuffle them with a key derived
           from the object key (keyed Fisher-Yates; an extra layer, not the encryption).
4. Spread  Reed-Solomon over GF(256): 6 shards per chunk, any 4 rebuild it.
5. Place   shard slot j of every chunk goes to one provider lease. Six slots across at
           least 3 providers, at most 2 slots per provider, different regions first, so
           losing any one provider still leaves 4 of 6. No provider holds a whole sealed chunk.

Then:

* get     For each chunk, fetch shards (healthy holders first), verify each against its
          recorded STO-1 root, stop at 4, rebuild, unshuffle, decrypt.
* check   Ask every holder for random 1 KiB blocks with Merkle proofs (STO-1).
* pay     Pay only holders that passed this epoch's check, for the GiB-days they hold;
          the provider checks the USDC payment on-chain and returns a signed PAY-1 ticket.
* repair  A holder failing longer than the grace period (default 24 h) is replaced: its
          shards are rebuilt from any 4 verified shards and uploaded to another provider.

The object key and the record of where every shard lives stay on this machine
(~/.innernet/client, mode 0700/0600). Providers only ever see shards of ciphertext.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import secrets
import sys
import time
from dataclasses import dataclass
from decimal import ROUND_CEILING, Decimal
from pathlib import Path
from typing import Callable

import threading

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import irm_storage
from .bulk_v080 import BulkError
from . import codec
from . import rly0
from . import stream_v080 as st81
from .crypto import decrypt_chunk, deinterleave, derive, encrypt_chunk, interleave, new_root
from .irm_registry import verify_presence, verify_registry, verify_ticket, verify_usage

CHUNK = 64 * 1024
REQUEST_DOMAIN = b"INNERnet/STO-1/request\x00"
RESPONSE_DOMAIN = b"INNERnet/STO-1/response\x00"
K, N = 4, 6               # any 4 of 6 shards rebuild a chunk
CELL = 4096               # mixing cell size, bytes
MAX_SLOTS_PER_PROVIDER = N - K
GRACE = 24 * 3600
EPOCH = 86400
GIB = 1 << 30


def state_home() -> Path:
    return Path(os.environ.get("INNERNET_CLIENT_HOME") or Path.home() / ".innernet" / "client")


def _private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


def load_identity(home: Path) -> Ed25519PrivateKey:
    p = home / "identity.key"
    if not p.exists():
        _private(p, Ed25519PrivateKey.generate().private_bytes_raw().hex().encode() + b"\n")
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(p.read_text().strip()))


# ---- talking to one provider ------------------------------------------------

HOLDBACK_BPS = 2000   # clients hold back 20 % of each storage payment until the next proof passes


class ProviderError(Exception):
    pass


class ProviderBusy(ProviderError):
    """The provider is full right now (HTTP 503); try another provider or again after retry_after seconds."""

    def __init__(self, msg: str, retry_after: int = 10):
        super().__init__(msg)
        self.retry_after = retry_after


class _Reply:
    """What an ST81 answer looks like to the rest of the client (same shape as an HTTP reply)."""

    def __init__(self, status: int, headers: dict, content: bytes):
        self.status_code, self.content = status, content
        self.headers = {str(k).lower(): str(v) for k, v in headers.items()}

    def json(self):
        return json.loads(self.content)


# One ST81 session per provider address and client key, reused across requests.
_SESSIONS: dict[tuple, list] = {}         # idle sessions per provider address and client key
_ST81_DOWN: dict[tuple, float] = {}       # address -> time until which we use HTTP only
_LOCK = threading.Lock()


def transport_mode() -> str:
    """INNERNET_TRANSPORT: auto (ST81 first, HTTP fallback), st81 (ST81 only) or http."""
    mode = os.environ.get("INNERNET_TRANSPORT", "auto")
    return mode if mode in ("auto", "st81", "http") else "auto"


@dataclass
class Provider:
    entry: dict
    key: Ed25519PrivateKey
    timeout: float = 10.0
    last_transport: str = ""
    terms: str = ""                  # SHA-256 of the client terms the client agreed to (sent with payments)
    route: dict | None = None        # live presence: {"path", "host", "port", "relay_key"?, "http_base"?}

    @property
    def id(self) -> str:
        return self.entry["id"]

    @property
    def base(self) -> str:
        if self.route and self.route.get("http_base"):
            return self.route["http_base"]
        ep = self.endpoint
        return f"http://{ep['host']}:{ep['port']}"

    @property
    def endpoint(self) -> dict:
        if self.route and self.route["path"] in ("direct", "router"):
            return {"host": self.route["host"], "port": self.route["port"]}
        return self.entry["endpoints"][0]

    def _request(self, method: str, path: str, body: bytes = b"", timeout: float | None = None) -> httpx.Response:
        ts, nonce = str(int(time.time())), secrets.token_hex(16)
        msg = REQUEST_DOMAIN + f"{method}\n{path}\n{hashlib.sha256(body).hexdigest()}\n{ts}\n{nonce}".encode()
        headers = {"X-Innernet-Client": self.key.public_key().public_bytes_raw().hex(), "X-Innernet-Time": ts,
                   "X-Innernet-Nonce": nonce, "X-Innernet-Signature": self.key.sign(msg).hex()}
        mode = transport_mode()
        if self.route and self.route["path"] == "tunnel":
            mode = "http"                      # HTTPS tunnel: the HTTP binding is the only way in
        if mode != "http":
            try:
                r = self._st81(method, path, body, headers, timeout)
                self.last_transport = "st81"
                return r
            except (st81.StreamError, OSError) as exc:
                if mode == "st81":
                    raise ProviderError(f"{self.entry['name']}: ST81 failed ({exc})") from exc
        try:
            r = httpx.request(method, self.base + path, content=body, headers=headers, timeout=timeout or self.timeout)
        except httpx.HTTPError as exc:
            raise ProviderError(f"{self.entry['name']}: unreachable ({exc.__class__.__name__})") from exc
        self.last_transport = "http"
        return r

    def _st81(self, method: str, path: str, body: bytes, headers: dict, timeout: float | None = None) -> _Reply:
        """STO-1 over ST81 (spec 5.9a): the provider's listed key is the pinned server key."""
        ep = self.endpoint
        via = self.route if self.route and self.route["path"] == "relay" else None
        if via:
            ep = {"host": via["host"], "port": via["port"]}
        addr = (self.id, ep["host"], ep["port"])
        if _ST81_DOWN.get(addr, 0) > time.monotonic():
            raise st81.StreamError("ST81 recently failed for this provider")
        slot = addr + (self.key.public_key().public_bytes_raw(),)
        # A pool of sessions per provider: requests in parallel each get their own session, so a long
        # job never blocks other requests (to this provider or any other).
        with _LOCK:
            idle = _SESSIONS.setdefault(slot, [])
            sess = idle.pop() if idle else None
        for attempt in (0, 1):
            try:
                if sess is None and via:
                    sess = rly0.connect(via["host"], via["port"], bytes.fromhex(via["relay_key"]), bytes.fromhex(self.id),
                                        self.key, timeout=self.timeout)
                if sess is None:
                    sess = st81.connect(ep["host"], ep["port"], self.key, bytes.fromhex(self.id), timeout=self.timeout)
                rid = secrets.randbelow(2**53)
                sess.sock.settimeout(timeout or self.timeout)
                sess.write({"rid": rid, "method": method, "path": path, "headers": headers}, body)
                head, data = sess.read()
                if head.get("rid") != rid or type(head.get("status")) is not int:
                    raise st81.StreamError("answer does not match the request")
                with _LOCK:
                    pool = _SESSIONS.setdefault(slot, [])
                    if len(pool) < 8:
                        pool.append(sess)
                    else:
                        sess.sock.close()
                return _Reply(head["status"], head.get("headers") or {}, data)
            except (st81.StreamError, OSError):
                if sess is not None:
                    try:
                        sess.sock.close()
                    except OSError:
                        pass
                sess = None
                if attempt == 1:
                    _ST81_DOWN[addr] = time.monotonic() + 60
                    raise

    def open_session(self):
        """A fresh ST81 session to this provider (direct, or end to end through its relay), for streams
        such as VPN exit. Providers reached only through the HTTPS tunnel cannot carry streams."""
        if self.route and self.route["path"] == "tunnel":
            raise ProviderError(f"{self.entry['name']}: reachable only through the HTTPS tunnel; streams need a direct or relayed provider")
        if self.route and self.route["path"] == "relay":
            r = self.route
            return rly0.connect(r["host"], r["port"], bytes.fromhex(r["relay_key"]), bytes.fromhex(self.id), self.key,
                                timeout=self.timeout)
        ep = self.endpoint
        return st81.connect(ep["host"], ep["port"], self.key, bytes.fromhex(self.id), timeout=self.timeout)

    def _json(self, r: httpx.Response) -> dict:
        """Verify the provider's signature on a JSON reply; it is our evidence."""
        sig = r.headers.get("x-innernet-signature", "")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.id)).verify(bytes.fromhex(sig), RESPONSE_DOMAIN + r.content)
        except (ValueError, InvalidSignature) as exc:
            raise ProviderError(f"{self.entry['name']}: reply not signed by the listed provider key") from exc
        data = r.json()
        if r.status_code == 503:
            try:
                after = int(r.headers.get("retry-after", "10"))
            except ValueError:
                after = 10
            raise ProviderBusy(f"{self.entry['name']}: {data.get('error', 'busy')}", after)
        if r.status_code >= 400:
            raise ProviderError(f"{self.entry['name']}: {data.get('error', r.status_code)}")
        return data

    def put_chunk(self, lease: str, obj: str, index: int, data: bytes) -> dict:
        return self._json(self._request("PUT", f"/sto/v1/leases/{lease}/objects/{obj}/chunks/{index}", data))

    def get_chunk(self, lease: str, obj: str, index: int) -> bytes:
        r = self._request("GET", f"/sto/v1/leases/{lease}/objects/{obj}/chunks/{index}")
        if r.status_code != 200:
            raise ProviderError(f"{self.entry['name']}: chunk {index} unavailable ({r.status_code})")
        return r.content

    def challenge(self, lease: str, obj: str, index: int, block: int) -> dict:
        body = json.dumps({"object": obj, "index": index, "block": block}).encode()
        return self._json(self._request("POST", f"/sto/v1/leases/{lease}/challenge", body))

    def pay(self, lease: str, units: str, tx: str, held: int = 0, released: int = 0) -> dict:
        body = json.dumps({"units": units, "tx": tx, "terms": self.terms, "held": held, "released": released}).encode()
        return self._json(self._request("POST", f"/sto/v1/leases/{lease}/pay", body))

    def delete(self, lease: str) -> None:
        self._json(self._request("DELETE", f"/sto/v1/leases/{lease}"))

    # ---- compute: the client brings the program or model, the provider the CPU or GPU ----

    @property
    def _me(self) -> str:
        return self.key.public_key().public_bytes_raw().hex()

    def _receipt(self, rec: dict) -> dict:
        return verify_usage(rec, bytes.fromhex(self.id), self._me)

    def credit(self, tx: str) -> dict:
        """Turn a USDC payment to this provider's payout contract into credit on this provider."""
        return self._json(self._request("POST", "/cmp/v1/credit", json.dumps({"tx": tx, "terms": self.terms}).encode()))

    def balance(self) -> str:
        return self._json(self._request("GET", "/cmp/v1/balance"))["balance"]

    def run_job(self, wasm: bytes | None = None, stdin: bytes = b"", args: tuple = (), seed: int = 0,
                max_seconds: int = 60, wasm_url: str | None = None, wasm_sha256: str | None = None,
                queue_seconds: int = 30) -> dict:
        """CMP-1: run a WebAssembly (WASI) program; same program, input and seed give the same output anywhere."""
        job = {"input": base64.b64encode(stdin).decode(), "args": list(args), "seed": seed, "max_seconds": max_seconds,
               "queue_seconds": queue_seconds}
        if wasm is not None:
            job["wasm"] = base64.b64encode(wasm).decode()
        else:
            job["wasm_url"], job["wasm_sha256"] = wasm_url, wasm_sha256
        out = self._json(self._request("POST", "/cmp/v1/jobs", json.dumps(job).encode(),
                                        timeout=max_seconds + queue_seconds + 60))
        receipt = self._receipt(out["receipt"])
        output = base64.b64decode(out["output"])
        if receipt["output_sha256"] != hashlib.sha256(output).hexdigest():
            raise ProviderError(f"{self.entry['name']}: output does not match its receipt")
        return {"output": output, "exit_code": out["exit_code"], "stderr": out.get("stderr", ""),
                "seconds": out["seconds"], "error": out.get("error"), "receipt": receipt}

    def run_gpu_job(self, program: bytes | str | None = None, stdin: bytes = b"", args: tuple = (), lang: str = "js",
                    max_seconds: int = 300, program_url: str | None = None, program_sha256: str | None = None,
                    queue_seconds: int = 30, max_memory_mib: int = 1024) -> dict:
        """GPU-1: run a JavaScript or TypeScript module that uses WebGPU (navigator.gpu). It reads standard
        input and writes standard output; it has no files, network or environment. Billed per GPU-hour."""
        job = {"input": base64.b64encode(stdin).decode(), "args": list(args), "lang": lang, "max_seconds": max_seconds,
               "queue_seconds": queue_seconds, "max_memory_mib": max_memory_mib}
        if program is not None:
            job["program"] = base64.b64encode(program.encode() if isinstance(program, str) else program).decode()
        else:
            job["program_url"], job["program_sha256"] = program_url, program_sha256
        out = self._json(self._request("POST", "/gpu/v1/jobs", json.dumps(job).encode(),
                                        timeout=max_seconds + queue_seconds + 60))
        receipt = self._receipt(out["receipt"])
        output = base64.b64decode(out["output"])
        if receipt["output_sha256"] != hashlib.sha256(output).hexdigest():
            raise ProviderError(f"{self.entry['name']}: output does not match its receipt")
        return {"output": output, "exit_code": out["exit_code"], "stderr": out.get("stderr", ""),
                "seconds": out["seconds"], "error": out.get("error"), "receipt": receipt}


# ---- choosing providers -----------------------------------------------------

def choose(entries: list[dict], k: int, exclude: set[str] = frozenset(), service: str = "STO-1") -> list[dict]:
    """Pick k providers offering `service`: most reachable first, one per region before repeating a region."""
    pool = [e for e in entries if service in e["services"] and e["id"] not in exclude]
    pool.sort(key=lambda e: (-float(e.get("reputation", {}).get("uptime_7d", "0")), Decimal(e["prices"][service]["amount"])))
    picked, regions = [], set()
    for e in pool:
        if e["region"] not in regions:
            picked.append(e)
            regions.add(e["region"])
        if len(picked) == k:
            return picked
    for e in pool:
        if e not in picked:
            picked.append(e)
        if len(picked) == k:
            break
    return picked


# ---- the client -------------------------------------------------------------

Payer = Callable[[str, str, int], str]   # (network, payto, amount in USDC base units) -> transaction hash


class Client:
    def __init__(self, home: Path | None = None, *, registry_doc: dict | None = None, pinned: list[bytes] | None = None,
                 registry_url: str | None = None, now: Callable[[], float] = time.time,
                 presence_url: str | None = None, accept_terms: str | None = None):
        self.home = Path(home or state_home())
        self.home.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.key = load_identity(self.home)
        self.now = now
        self.pinned = pinned or []
        self.registry_url = registry_url
        self.presence_url = presence_url
        self._routes: dict[str, tuple[float, dict | None]] = {}
        self._doc = registry_doc
        # The client terms this user agreed to (their SHA-256, from /registry/v1/terms). Payments carry it.
        self.terms = accept_terms or ""

    # registry
    def _pin(self) -> list[bytes]:
        """The registry key to trust. Given keys win; otherwise the key seen first is kept in
        <home>/registry-key.pin and every later document must be signed by it (trust on first use)."""
        if self.pinned:
            return self.pinned
        pin = self.home / "registry-key.pin"
        if pin.exists():
            return [bytes.fromhex(pin.read_text().strip())]
        if not self.registry_url:
            raise BulkError("no registry key pinned")
        key = httpx.get(self.registry_url.rstrip("/") + "/registry-key", timeout=20).json()["registry_key"]
        _private(pin, key.encode())
        return [bytes.fromhex(key)]

    def providers(self) -> list[dict]:
        doc = self._doc
        if doc is None:
            if not self.registry_url:
                raise BulkError("no registry configured")
            doc = httpx.get(self.registry_url.rstrip("/") + "/registry.json", timeout=20).json()
        payload = verify_registry(doc, self._pin(), now=int(self.now()))
        self._no_rollback(doc)
        return payload["providers"]

    def _no_rollback(self, doc: dict) -> None:
        """Refuse an older registry document than one already seen. The same document may be
        read again; a different document with the same sequence number is refused."""
        p = self.home / "registry-seen.json"
        seen = json.loads(p.read_text()) if p.exists() else {}
        key, seq = doc["registry_key"], doc["payload"]["sequence"]
        digest = hashlib.sha256(json.dumps(doc["payload"], sort_keys=True).encode()).hexdigest()
        last = seen.get(key)
        if last and (seq < last["sequence"] or (seq == last["sequence"] and digest != last["digest"])):
            raise BulkError("registry document is older than one already seen (rollback refused)")
        if not last or seq > last["sequence"]:
            seen[key] = {"sequence": seq, "digest": digest}
            _private(p, json.dumps(seen).encode())

    def provider(self, entry: dict) -> Provider:
        return Provider(entry, self.key, route=self.route(entry["id"]), terms=self.terms)

    def client_terms(self) -> dict:
        """The current client terms from the registry: read them, then pass their sha256 as accept_terms."""
        if not self.registry_url:
            raise BulkError("no registry configured")
        return httpx.get(self.registry_url.rstrip("/") + "/terms", timeout=20).json()["client"]

    def compute_providers(self, service: str = "CMP-1") -> list[dict]:
        """Providers offering CPU (CMP-1) or GPU (GPU-1) time, those with free capacity right now first,
        then the cheapest. Capacity comes from each provider's own signed presence."""
        key = "gpu_free" if service == "GPU-1" else "cpu_free"
        ranked = []
        for e in self.providers():
            if service not in e["services"]:
                continue
            stats = (self.route(e["id"]) or {}).get("stats") or {}
            free = stats.get(key, 0) - stats.get("queued", 0)
            ranked.append((-free, Decimal(e["prices"][service]["amount"]), e))
        return [e for *_, e in sorted(ranked, key=lambda x: (x[0], x[1]))]

    def run_job(self, wasm: bytes | None = None, **kw) -> dict:
        """Run a CPU job on the first provider with room; a busy provider passes it to the next.
        Credit must already be on the provider that runs it (Provider.credit)."""
        last: Exception | None = None
        for e in self.compute_providers("CMP-1"):
            try:
                return self.provider(e).run_job(wasm, **kw)
            except ProviderBusy as exc:
                last = exc
        raise last or ProviderError("no provider offers CPU time")

    def route(self, pid: str) -> dict | None:
        """Where a provider can be reached right now, from its own signed presence record
        (the registry only passes it on). Cached for a minute; None means use the listing."""
        base = self.presence_url or self.registry_url
        if not base:
            return None
        hit = self._routes.get(pid)
        if hit and hit[0] > time.monotonic():
            return hit[1]
        route = None
        try:
            r = httpx.get(base.rstrip("/") + f"/presence/{pid}", timeout=10)
            if r.status_code == 200:
                live = r.json()
                p = verify_presence(live["record"], now=int(self.now()), max_age=900)
                if p["provider"] == pid and live.get("online"):
                    ep = p["endpoint"]
                    route = {"path": p["path"], "host": ep["host"], "port": ep["port"]}
                    if p["path"] == "relay":
                        route["relay_key"] = p["relay_key"]
                    if p["path"] == "tunnel":
                        route["http_base"] = base.rstrip("/").removesuffix("/v1") + f"/t/{pid}"
                    route["stats"] = p["stats"]
        except (httpx.HTTPError, ValueError, KeyError, BulkError):
            route = None
        self._routes[pid] = (time.monotonic() + 60, route)
        return route

    # records
    def _path(self, obj: str) -> Path:
        return self.home / "objects" / f"{obj}.json"

    def load(self, obj: str) -> dict:
        return json.loads(self._path(obj).read_text())

    def save(self, rec: dict) -> None:
        _private(self._path(rec["object"]), json.dumps(rec, indent=1).encode())

    def list(self) -> list[dict]:
        d = self.home / "objects"
        return [json.loads(p.read_text()) for p in sorted(d.glob("*.json"))] if d.exists() else []

    # put
    def put(self, data: bytes, name: str = "file") -> dict:
        if not data:
            raise BulkError("empty file")
        root, obj = new_root(), secrets.token_bytes(16)
        meta, shards = [], []
        for i in range(0, len(data), CHUNK):
            index, plain = i // CHUNK, data[i:i + CHUNK]
            cipher = encrypt_chunk(root, obj, index, plain)
            mixed = interleave(cipher, _mix_key(root, index), CELL)
            parts = codec.encode(mixed, K, N)
            roots = [irm_storage.chunk_root(s) for s in parts]
            shards.append(parts)
            meta.append({"index": index, "plain": len(plain), "cipher": len(cipher), "mixed": len(mixed),
                         "shard_bytes": len(parts[0]), "roots": [r.hex() for r, _ in roots], "blocks": [b for _, b in roots]})
        rec = {"version": "IRM1-CLIENT-2", "object": obj.hex(), "name": name, "size": len(data), "key": root.hex(),
               "k": K, "n": N, "cell": CELL, "created": int(self.now()), "chunks": meta, "holders": [], "history": []}
        candidates = self.providers()
        for slot in range(N):
            holder = self._place_slot(candidates, rec, slot, [parts[slot] for parts in shards])
            if holder is None:
                for h in rec["holders"]:                       # do not leave half a file behind
                    try:
                        self.provider(h["entry"]).delete(h["lease"])
                    except ProviderError:
                        pass
                raise BulkError(f"could not place shard slot {slot}: need at least {math.ceil(N / MAX_SLOTS_PER_PROVIDER)} "
                                "working providers")
            rec["holders"].append(holder)
        self.save(rec)
        return rec

    def _place_slot(self, candidates: list[dict], rec: dict, slot: int, shards: list[bytes],
                    avoid: set[str] = frozenset()) -> dict | None:
        """Upload one slot to the best provider that still has room for it. Returns the holder or None."""
        tried: set[str] = set(avoid)
        while True:
            entry = _pick(candidates, rec["holders"], tried)
            if entry is None:
                return None
            tried.add(entry["id"])
            try:
                return self._upload(entry, rec, slot, shards)
            except ProviderError as exc:
                rec["history"].append({"time": int(self.now()), "event": "placement-failed", "provider": entry["id"],
                                       "slot": slot, "detail": str(exc)})

    def _upload(self, entry: dict, rec: dict, slot: int, shards: list[bytes]) -> dict:
        p, lease = self.provider(entry), secrets.token_hex(16)
        for m, shard in zip(rec["chunks"], shards):
            ack = p.put_chunk(lease, rec["object"], m["index"], shard)
            if ack.get("root") != m["roots"][slot] or ack.get("blocks") != m["blocks"][slot]:
                raise ProviderError(f"{entry['name']}: stored shard {m['index']}/{slot} does not match")
        network = next(iter(entry["payto"]))
        return {"slot": slot, "provider": entry["id"], "name": entry["name"], "region": entry["region"], "entry": entry,
                "lease": lease, "network": network, "payto": entry["payto"][network],
                "price": entry["prices"]["STO-1"]["amount"], "since": int(self.now()), "status": "ok",
                "first_failure": None, "last_check": None, "paid_epochs": [], "tickets": []}

    # get
    def _shards(self, rec: dict, m: dict, holders: list[dict], want: int = K) -> dict[int, bytes]:
        """Fetch verified shards of one chunk, healthy holders first, until `want` are in hand."""
        got: dict[int, bytes] = {}
        for h in sorted(holders, key=lambda h: h["status"] != "ok"):
            if len(got) >= want:
                break
            try:
                s = self.provider(h["entry"]).get_chunk(h["lease"], rec["object"], m["index"])
            except ProviderError:
                continue
            if irm_storage.chunk_root(s)[0].hex() == m["roots"][h["slot"]]:
                got[h["slot"]] = s                             # wrong or corrupted shards are skipped
        return got

    def _mixed(self, rec: dict, m: dict, holders: list[dict]) -> bytes:
        got = self._shards(rec, m, holders)
        if len(got) < rec["k"]:
            raise BulkError(f"chunk {m['index']}: only {len(got)} of {rec['n']} shards available, need {rec['k']}")
        return codec.decode(got, rec["k"], rec["n"], m["mixed"])

    def get(self, obj: str) -> bytes:
        rec = self.load(obj)
        root, oid = bytes.fromhex(rec["key"]), bytes.fromhex(rec["object"])
        out = []
        for m in rec["chunks"]:
            mixed = self._mixed(rec, m, rec["holders"])
            cipher = deinterleave(mixed, _mix_key(root, m["index"]), rec["cell"], m["cipher"])
            out.append(decrypt_chunk(root, oid, m["index"], cipher, m["plain"]))
        data = b"".join(out)
        if len(data) != rec["size"]:
            raise BulkError("recovered size does not match")
        return data

    # check
    def check(self, obj: str, samples: int = 3, rng=secrets.SystemRandom()) -> dict:
        rec = self.load(obj)
        result = {}
        for h in rec["holders"]:
            ok, why = True, ""
            p = self.provider(h["entry"])
            for _ in range(samples):
                m = rec["chunks"][rng.randrange(len(rec["chunks"]))]
                block = rng.randrange(m["blocks"][h["slot"]])
                try:
                    ans = p.challenge(h["lease"], rec["object"], m["index"], block)
                    good = (ans.get("index") == m["index"] and ans.get("block") == block and irm_storage.verify(
                        bytes.fromhex(m["roots"][h["slot"]]), m["blocks"][h["slot"]], block, bytes.fromhex(ans["data"]),
                        [bytes.fromhex(x) for x in ans["path"]]))
                except (ProviderError, KeyError, ValueError, TypeError) as exc:
                    good, why = False, str(exc)
                if not good:
                    ok, why = False, why or "proof did not verify"
                    break
            now = int(self.now())
            h["last_check"] = now
            if ok:
                h["status"], h["first_failure"] = "ok", None
            else:
                h["status"] = "failing"
                h["first_failure"] = h["first_failure"] or now
                rec["history"].append({"time": now, "event": "check-failed", "provider": h["provider"],
                                       "slot": h["slot"], "detail": why})
            result[_key(h)] = {"ok": ok, "detail": why, "provider": h["provider"], "slot": h["slot"]}
        self.save(rec)
        return result

    # pay
    def pay(self, obj: str, payer: Payer, epoch: int | None = None) -> dict:
        """Pay each holder that passed its latest check in `epoch` (default: today) for the shards it holds."""
        rec = self.load(obj)
        epoch = int(self.now() // EPOCH) if epoch is None else epoch
        stored = sum(m["shard_bytes"] for m in rec["chunks"])          # bytes per slot
        units = (Decimal(stored) / GIB).quantize(Decimal("0.000001"), rounding=ROUND_CEILING)
        units = max(units, Decimal("0.000001"))
        out = {}
        for h in rec["holders"]:
            if epoch in h["paid_epochs"]:
                out[_key(h)] = "already paid"
                continue
            if h["status"] != "ok" or h["last_check"] is None or h["last_check"] // EPOCH != epoch:
                out[_key(h)] = "not paid: no passing check this epoch"
                continue
            if not self.terms:
                raise BulkError("agree to the client terms first: Client(accept_terms=<sha256 from client_terms()>)")
            amount = int((units * Decimal(h["price"]) * 1_000_000).to_integral_value(rounding=ROUND_CEILING))
            amount = max(amount, 1)
            # Holdback: keep 20 % of this period until the next proof passes; release last period's now.
            held = amount * HOLDBACK_BPS // 10000
            released = h.get("held", 0)
            pay_now = amount - held + released
            self.check_payment(h["network"], pay_now)
            tx = payer(h["network"], h["payto"], pay_now)
            ticket = self.provider(h["entry"]).pay(h["lease"], format(units, "f"), tx, held=held, released=released)
            verify_ticket(ticket, bytes.fromhex(h["provider"]), now=int(self.now()))
            h["held"] = held
            h["paid_epochs"].append(epoch)
            h["tickets"].append(ticket)
            out[_key(h)] = f"paid {pay_now} base units ({held} held back until the next proof), ticket verified"
        self.save(rec)
        return out

    def limits(self, network: str) -> dict | None:
        """Mainnet beta limits published by the registry (max_payment_usdc, max_credit_usdc), or None."""
        if not self.registry_url:
            return None
        if not hasattr(self, "_config"):
            try:
                self._config = httpx.get(self.registry_url.rstrip("/") + "/config", timeout=20).json()
            except (httpx.HTTPError, ValueError):
                self._config = {}
        for n in self._config.get("networks", []):
            if n.get("caip2") == network:
                return n.get("limits")
        return None

    def check_payment(self, network: str, amount: int) -> None:
        """Refuse a single payment above the network's beta limit (amount in USDC base units)."""
        lim = self.limits(network)
        if lim and amount > int(Decimal(lim["max_payment_usdc"]) * 1_000_000):
            raise BulkError(f"payment of {Decimal(amount) / 1_000_000} USDC is above the beta limit of "
                            f"{lim['max_payment_usdc']} USDC per payment on this network")

    # repair
    def repair(self, obj: str, grace: int = GRACE, force: bool = False) -> list[dict]:
        rec = self.load(obj)
        now = int(self.now())
        bad = [h for h in rec["holders"] if h["status"] != "ok" and (force or now - (h["first_failure"] or now) >= grace)]
        if not bad:
            return []
        healthy = [h for h in rec["holders"] if h["status"] == "ok"]
        if len(healthy) < rec["k"]:
            raise BulkError(f"only {len(healthy)} healthy shard holders; need {rec['k']} to rebuild")
        rebuilt: dict[int, list[bytes]] = {h["slot"]: [] for h in bad}
        for m in rec["chunks"]:
            parts = codec.encode(self._mixed(rec, m, healthy), rec["k"], rec["n"])
            for slot in rebuilt:
                if irm_storage.chunk_root(parts[slot])[0].hex() != m["roots"][slot]:
                    raise BulkError(f"rebuilt shard {m['index']}/{slot} does not match its recorded root")
                rebuilt[slot].append(parts[slot])
        changes = []
        candidates = self.providers()
        failing = {h["provider"] for h in bad}
        for h in bad:
            others = [x for x in rec["holders"] if x is not h]
            view = dict(rec, holders=others)
            new = self._place_slot(candidates, view, h["slot"], rebuilt[h["slot"]], avoid=failing)
            rec["history"] = view["history"]
            if new is None:
                changes.append({"slot": h["slot"], "replaced": h["provider"], "with": None, "held_kept": h.get("held", 0)})
                continue
            try:
                self.provider(h["entry"]).delete(h["lease"])     # best effort; the old provider may be gone
            except ProviderError:
                pass
            rec["holders"][rec["holders"].index(h)] = new
            rec["history"].append({"time": now, "event": "repaired", "provider": h["provider"], "slot": h["slot"],
                                   "detail": new["provider"]})
            # The failed provider's held-back amount is never released: it stays with the client for the repair.
            changes.append({"slot": h["slot"], "replaced": h["provider"], "with": new["provider"], "held_kept": h.get("held", 0)})
        self.save(rec)
        return changes


def _key(h: dict) -> str:
    return f"{h['provider']}#{h['slot']}"


def _mix_key(root: bytes, index: int) -> bytes:
    return derive(root, f"irm/sto-1/mix/{index}")


def _pick(candidates: list[dict], holders: list[dict], exclude: set[str]) -> dict | None:
    """Next provider for a shard slot: fewest slots already held, then a region not yet used,
    then the `choose` order (most reachable, cheapest). Never more than MAX_SLOTS_PER_PROVIDER."""
    count: dict[str, int] = {}
    for h in holders:
        count[h["provider"]] = count.get(h["provider"], 0) + 1
    full = {pid for pid, c in count.items() if c >= MAX_SLOTS_PER_PROVIDER}
    pool = choose(candidates, len(candidates), set(exclude) | full)
    if not pool:
        return None
    regions = {h["region"] for h in holders}
    order = {e["id"]: i for i, e in enumerate(pool)}
    return min(pool, key=lambda e: (count.get(e["id"], 0), e["region"] in regions, order[e["id"]]))


# ---- command line -----------------------------------------------------------

def _manual_payer(network: str, payto: str, amount: int) -> str:
    print(f"Pay {amount / 1_000_000:.6f} USDC ({amount} base units) on {network} to {payto}")
    return input("Transaction hash of the payment: ").strip()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="innernet-client", description="Store files on INNERnet providers (IRM-1 draft, testnet)")
    ap.add_argument("--registry", default=os.environ.get("INNERNET_REGISTRY", "https://innernetcorp.com/registry/v1"))
    ap.add_argument("--registry-key", default=os.environ.get("INNERNET_REGISTRY_KEY", ""),
                    help="pinned registry public key (hex); see /registry/v1/registry-key")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("put"); s.add_argument("file")
    s = sub.add_parser("get"); s.add_argument("object"); s.add_argument("out")
    s = sub.add_parser("check"); s.add_argument("object")
    s = sub.add_parser("pay"); s.add_argument("object")
    s = sub.add_parser("repair"); s.add_argument("object"); s.add_argument("--now", action="store_true", help="skip the grace period")
    sub.add_parser("list")
    args = ap.parse_args(argv)
    if not args.registry_key:
        print("Set --registry-key (or INNERNET_REGISTRY_KEY) to the registry's public key.", file=sys.stderr)
        return 2
    c = Client(registry_url=args.registry, pinned=[bytes.fromhex(args.registry_key)])
    if args.cmd == "put":
        rec = c.put(Path(args.file).read_bytes(), Path(args.file).name)
        print(rec["object"], "stored as 6 shards (any 4 rebuild it) on",
              ", ".join(f"{h['name']}[{h['slot']}]" for h in rec["holders"]))
    elif args.cmd == "get":
        Path(args.out).write_bytes(c.get(args.object))
        print("written", args.out)
    elif args.cmd == "check":
        for res in c.check(args.object).values():
            print(res["provider"][:12], "shard", res["slot"], "ok" if res["ok"] else "FAILED " + res["detail"])
    elif args.cmd == "pay":
        for key, res in c.pay(args.object, _manual_payer).items():
            print(key[:12], "shard", key.split("#")[1], res)
    elif args.cmd == "repair":
        for ch in c.repair(args.object, force=args.now):
            print("shard", ch["slot"], "moved from", ch["replaced"][:12], "to", (ch["with"] or "nobody (no free provider)")[:12])
    else:
        for rec in c.list():
            print(rec["object"], rec["name"], rec["size"], "bytes,", ", ".join(f"{h['name']}[{h['slot']}]:{h['status']}" for h in rec["holders"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
