"""IRM-1 client (draft): store files on paid providers, check them, pay them, repair them.

What it does, end to end:

* put     Encrypt a file chunk by chunk (the OB80-2 chunk cipher, a fresh object key),
          pick 3 providers from the signed registry (different regions first),
          upload every chunk to each, and check each provider computed the same
          STO-1 Merkle root as we did.
* get     Read each chunk from the first replica that answers and verify it against
          the recorded root before decrypting. A dead provider is skipped (failover).
* check   Ask every replica for random 1 KiB blocks with Merkle proofs (STO-1).
          Passing replicas are marked healthy; failing ones record when they first failed.
* pay     Pay only replicas that passed this epoch's check: units are GiB-days of
          ciphertext held, sent as USDC to the provider's payout contract; the provider
          checks the payment on-chain and returns a signed PAY-1 ticket, which we verify.
* repair  Replace replicas that failed for longer than the grace period (default 24 h):
          copy the chunks from a healthy replica, verify them, upload to a new provider.

The object key and the record of where every piece lives stay on this machine
(~/.innernet/client, mode 0700/0600). Providers only ever see ciphertext.
"""
from __future__ import annotations

import argparse
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

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import irm_storage
from .bulk_v080 import BulkError
from .crypto import decrypt_chunk, encrypt_chunk, new_root
from .irm_registry import verify_registry, verify_ticket

CHUNK = 64 * 1024
REQUEST_DOMAIN = b"INNERnet/STO-1/request\x00"
RESPONSE_DOMAIN = b"INNERnet/STO-1/response\x00"
REPLICAS = 3
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

class ProviderError(Exception):
    pass


@dataclass
class Provider:
    entry: dict
    key: Ed25519PrivateKey
    timeout: float = 10.0

    @property
    def id(self) -> str:
        return self.entry["id"]

    @property
    def base(self) -> str:
        ep = self.entry["endpoints"][0]
        return f"http://{ep['host']}:{ep['port']}"

    def _request(self, method: str, path: str, body: bytes = b"") -> httpx.Response:
        ts, nonce = str(int(time.time())), secrets.token_hex(16)
        msg = REQUEST_DOMAIN + f"{method}\n{path}\n{hashlib.sha256(body).hexdigest()}\n{ts}\n{nonce}".encode()
        headers = {"X-Innernet-Client": self.key.public_key().public_bytes_raw().hex(), "X-Innernet-Time": ts,
                   "X-Innernet-Nonce": nonce, "X-Innernet-Signature": self.key.sign(msg).hex()}
        try:
            r = httpx.request(method, self.base + path, content=body, headers=headers, timeout=self.timeout)
        except httpx.HTTPError as exc:
            raise ProviderError(f"{self.entry['name']}: unreachable ({exc.__class__.__name__})") from exc
        return r

    def _json(self, r: httpx.Response) -> dict:
        """Verify the provider's signature on a JSON reply; it is our evidence."""
        sig = r.headers.get("x-innernet-signature", "")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.id)).verify(bytes.fromhex(sig), RESPONSE_DOMAIN + r.content)
        except (ValueError, InvalidSignature) as exc:
            raise ProviderError(f"{self.entry['name']}: reply not signed by the listed provider key") from exc
        data = r.json()
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

    def pay(self, lease: str, units: str, tx: str) -> dict:
        body = json.dumps({"units": units, "tx": tx}).encode()
        return self._json(self._request("POST", f"/sto/v1/leases/{lease}/pay", body))

    def delete(self, lease: str) -> None:
        self._json(self._request("DELETE", f"/sto/v1/leases/{lease}"))


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
                 registry_url: str | None = None, now: Callable[[], float] = time.time):
        self.home = Path(home or state_home())
        self.home.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.key = load_identity(self.home)
        self.now = now
        self.pinned = pinned or []
        self.registry_url = registry_url
        self._doc = registry_doc

    # registry
    def providers(self) -> list[dict]:
        doc = self._doc
        if doc is None:
            if not self.registry_url:
                raise BulkError("no registry configured")
            doc = httpx.get(self.registry_url.rstrip("/") + "/registry.json", timeout=20).json()
        payload = verify_registry(doc, self.pinned, now=int(self.now()))
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
        return Provider(entry, self.key)

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
    def put(self, data: bytes, name: str = "file", replicas: int = REPLICAS) -> dict:
        if not data:
            raise BulkError("empty file")
        root, obj = new_root(), secrets.token_bytes(16)
        chunks, meta = [], []
        for i in range(0, len(data), CHUNK):
            plain = data[i:i + CHUNK]
            cipher = encrypt_chunk(root, obj, i // CHUNK, plain)
            croot, blocks = irm_storage.chunk_root(cipher)
            chunks.append(cipher)
            meta.append({"index": i // CHUNK, "plain": len(plain), "bytes": len(cipher), "root": croot.hex(), "blocks": blocks})
        rec = {"version": "IRM1-CLIENT-1", "object": obj.hex(), "name": name, "size": len(data), "key": root.hex(),
               "created": int(self.now()), "chunks": meta, "replicas": [], "history": []}
        candidates = self.providers()
        tried: set[str] = set()
        while len(rec["replicas"]) < replicas:
            picks = choose(candidates, 1, tried | {r["provider"] for r in rec["replicas"]})
            if not picks:
                break
            entry = picks[0]
            tried.add(entry["id"])
            try:
                rec["replicas"].append(self._place(entry, rec, chunks))
            except ProviderError as exc:
                rec["history"].append({"time": int(self.now()), "event": "placement-failed", "provider": entry["id"], "detail": str(exc)})
        if not rec["replicas"]:
            raise BulkError("no provider accepted the file")
        self.save(rec)
        return rec

    def _place(self, entry: dict, rec: dict, chunks: list[bytes]) -> dict:
        p, lease = self.provider(entry), secrets.token_hex(16)
        for m, cipher in zip(rec["chunks"], chunks):
            ack = p.put_chunk(lease, rec["object"], m["index"], cipher)
            if ack.get("root") != m["root"] or ack.get("blocks") != m["blocks"]:
                raise ProviderError(f"{entry['name']}: stored chunk {m['index']} does not match")
        network = next(iter(entry["payto"]))
        return {"provider": entry["id"], "name": entry["name"], "region": entry["region"], "entry": entry, "lease": lease,
                "network": network, "payto": entry["payto"][network], "price": entry["prices"]["STO-1"]["amount"],
                "since": int(self.now()), "status": "ok", "first_failure": None, "last_check": None,
                "paid_epochs": [], "tickets": []}

    # get
    def get(self, obj: str) -> bytes:
        rec = self.load(obj)
        root, oid = bytes.fromhex(rec["key"]), bytes.fromhex(rec["object"])
        order = sorted(rec["replicas"], key=lambda r: r["status"] != "ok")
        out = []
        for m in rec["chunks"]:
            for r in order:
                try:
                    cipher = self.provider(r["entry"]).get_chunk(r["lease"], rec["object"], m["index"])
                except ProviderError:
                    continue
                if irm_storage.chunk_root(cipher)[0].hex() != m["root"]:
                    continue                                   # wrong or corrupted: try the next replica
                out.append(decrypt_chunk(root, oid, m["index"], cipher, m["plain"]))
                break
            else:
                raise BulkError(f"chunk {m['index']} is unavailable on every replica")
        data = b"".join(out)
        if len(data) != rec["size"]:
            raise BulkError("recovered size does not match")
        return data

    # check
    def check(self, obj: str, samples: int = 3, rng=secrets.SystemRandom()) -> dict:
        rec = self.load(obj)
        result = {}
        for r in rec["replicas"]:
            ok, why = True, ""
            p = self.provider(r["entry"])
            for _ in range(samples):
                m = rec["chunks"][rng.randrange(len(rec["chunks"]))]
                block = rng.randrange(m["blocks"])
                try:
                    ans = p.challenge(r["lease"], rec["object"], m["index"], block)
                    good = (ans.get("index") == m["index"] and ans.get("block") == block and irm_storage.verify(
                        bytes.fromhex(m["root"]), m["blocks"], block, bytes.fromhex(ans["data"]),
                        [bytes.fromhex(x) for x in ans["path"]]))
                except (ProviderError, KeyError, ValueError, TypeError) as exc:
                    good, why = False, str(exc)
                if not good:
                    ok, why = False, why or "proof did not verify"
                    break
            now = int(self.now())
            r["last_check"] = now
            if ok:
                r["status"], r["first_failure"] = "ok", None
            else:
                r["status"] = "failing"
                r["first_failure"] = r["first_failure"] or now
                rec["history"].append({"time": now, "event": "check-failed", "provider": r["provider"], "detail": why})
            result[r["provider"]] = {"ok": ok, "detail": why}
        self.save(rec)
        return result

    # pay
    def pay(self, obj: str, payer: Payer, epoch: int | None = None) -> dict:
        """Pay each replica that passed its latest check for `epoch` (default: the current day)."""
        rec = self.load(obj)
        epoch = int(self.now() // EPOCH) if epoch is None else epoch
        stored = sum(m["bytes"] for m in rec["chunks"])
        units = (Decimal(stored) / GIB).quantize(Decimal("0.000001"), rounding=ROUND_CEILING)
        units = max(units, Decimal("0.000001"))
        out = {}
        for r in rec["replicas"]:
            if epoch in r["paid_epochs"]:
                out[r["provider"]] = "already paid"
                continue
            if r["status"] != "ok" or r["last_check"] is None or r["last_check"] // EPOCH != epoch:
                out[r["provider"]] = "not paid: no passing check this epoch"
                continue
            amount = int((units * Decimal(r["price"]) * 1_000_000).to_integral_value(rounding=ROUND_CEILING))
            amount = max(amount, 1)
            tx = payer(r["network"], r["payto"], amount)
            ticket = self.provider(r["entry"]).pay(r["lease"], format(units, "f"), tx)
            verify_ticket(ticket, bytes.fromhex(r["provider"]), now=int(self.now()))
            r["paid_epochs"].append(epoch)
            r["tickets"].append(ticket)
            out[r["provider"]] = f"paid {amount} base units, ticket verified"
        self.save(rec)
        return out

    # repair
    def repair(self, obj: str, grace: int = GRACE, force: bool = False) -> list[dict]:
        rec = self.load(obj)
        now = int(self.now())
        bad = [r for r in rec["replicas"] if r["status"] != "ok" and (force or now - (r["first_failure"] or now) >= grace)]
        if not bad:
            return []
        healthy = [r for r in rec["replicas"] if r["status"] == "ok"]
        if not healthy:
            raise BulkError("no healthy replica to repair from")
        chunks = []
        for m in rec["chunks"]:
            for r in healthy:
                try:
                    c = self.provider(r["entry"]).get_chunk(r["lease"], rec["object"], m["index"])
                except ProviderError:
                    continue
                if irm_storage.chunk_root(c)[0].hex() == m["root"]:
                    chunks.append(c)
                    break
            else:
                raise BulkError(f"chunk {m['index']} could not be read from a healthy replica")
        changes = []
        candidates = self.providers()
        for r in bad:
            used = {x["provider"] for x in rec["replicas"]}
            tried: set[str] = set()
            new = None
            while True:
                picks = choose(candidates, 1, used | tried)
                if not picks:
                    break
                tried.add(picks[0]["id"])
                try:
                    new = self._place(picks[0], rec, chunks)
                    break
                except ProviderError as exc:
                    rec["history"].append({"time": now, "event": "placement-failed", "provider": picks[0]["id"], "detail": str(exc)})
            if new is None:
                changes.append({"replaced": r["provider"], "with": None})
                continue
            try:
                self.provider(r["entry"]).delete(r["lease"])     # best effort; the old provider may be gone
            except ProviderError:
                pass
            rec["replicas"][rec["replicas"].index(r)] = new
            rec["history"].append({"time": now, "event": "repaired", "provider": r["provider"], "detail": new["provider"]})
            changes.append({"replaced": r["provider"], "with": new["provider"]})
        self.save(rec)
        return changes


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
    s = sub.add_parser("put"); s.add_argument("file"); s.add_argument("--replicas", type=int, default=REPLICAS)
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
        rec = c.put(Path(args.file).read_bytes(), Path(args.file).name, args.replicas)
        print(rec["object"], "stored on", ", ".join(r["name"] for r in rec["replicas"]))
    elif args.cmd == "get":
        Path(args.out).write_bytes(c.get(args.object))
        print("written", args.out)
    elif args.cmd == "check":
        for pid, res in c.check(args.object).items():
            print(pid[:12], "ok" if res["ok"] else "FAILED " + res["detail"])
    elif args.cmd == "pay":
        for pid, res in c.pay(args.object, _manual_payer).items():
            print(pid[:12], res)
    elif args.cmd == "repair":
        for ch in c.repair(args.object, force=args.now):
            print("replaced", ch["replaced"][:12], "with", (ch["with"] or "nobody (no free provider)")[:12])
    else:
        for rec in c.list():
            print(rec["object"], rec["name"], rec["size"], "bytes,", ", ".join(f"{r['name']}:{r['status']}" for r in rec["replicas"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
