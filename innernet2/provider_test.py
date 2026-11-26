"""Test one INNERnet provider from the outside, the way a client sees it.

    python -m innernet2.provider_test <provider id, id prefix or name> [--json]
    python -m innernet2.provider_test all

Free checks (no money): listed in the signed registry document, live presence and path, the
signed /sto/v1/info answer, response time, and a storage round trip (store 1 MiB of random
bytes on the provider, read it back, compare, delete).

Paid check (test USDC on Base Sepolia): pay the provider's payout contract from your own wallet
(any wallet app), then pass the transaction with --credit-tx 0x…; the test credits it and runs a
small CPU job, and shows the signed receipt. This tool never sees a wallet key.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
import time

import httpx

from .irm_client import Client, ProviderError

REGISTRY = "https://innernetcorp.com/registry/v1"

# A WebAssembly program that copies its input to its output (wasm32-wasi, 196 bytes), built
# from testdata/wasmjob; small enough to inline so the tester needs no files.
ECHO_WASM_HEX = os.environ.get("INNERNET_TEST_WASM_HEX", "")


class Report:
    def __init__(self, name: str):
        self.name, self.rows, self.failed = name, [], False

    def add(self, check: str, ok: bool | None, detail: str) -> None:
        self.rows.append({"check": check, "result": "pass" if ok else ("skip" if ok is None else "FAIL"), "detail": detail})
        self.failed |= ok is False

    def text(self) -> str:
        w = max(len(r["check"]) for r in self.rows) if self.rows else 10
        lines = [f"\n  {self.name}"]
        for r in self.rows:
            mark = {"pass": "✓", "FAIL": "✗", "skip": "–"}[r["result"]]
            lines.append(f"  {mark} {r['check'].ljust(w)}  {r['detail']}")
        lines.append("  " + ("FAILED" if self.failed else "PASSED"))
        return "\n".join(lines)


def find(client: Client, wanted: str) -> list[dict]:
    entries = client.providers()
    if wanted == "all":
        return entries
    w = wanted.lower()
    hits = [e for e in entries if e["id"] == w or e["id"].startswith(w) or e.get("name", "").lower() == w]
    return hits


def test_provider(client: Client, entry: dict, credit_tx: str = "", wasm: bytes = b"") -> Report:
    rep = Report(f"{entry.get('name')} ({entry['id'][:16]}…)")
    rep.add("Listed", True, f"in the signed registry document · offers {', '.join(entry.get('services', []))}")
    route = client.route(entry["id"])
    if route is None:
        rep.add("Online", False, "no recent check-in (presence) from this machine")
    else:
        rep.add("Online", True, f"reached {route['path']}" + (f" at {route.get('host')}:{route.get('port')}"
                                                             if route["path"] in ("direct", "router") else ""))
    p = client.provider(entry)
    # Signed info, and how fast it answers.
    times, info = [], None
    for _ in range(3):
        t0 = time.monotonic()
        try:
            r = p._request("GET", "/sto/v1/info")
            info = p._json(r)
            times.append((time.monotonic() - t0) * 1000)
        except ProviderError as exc:
            rep.add("Signed answer", False, str(exc))
            return rep
    fresh = abs(int(info.get("time", 0)) - time.time()) < 300
    rep.add("Signed answer", info.get("provider") == entry["id"] and fresh,
            f"signed by the listed key over {p.last_transport or 'http'}" + ("" if fresh else "; clock is off by more than 5 minutes"))
    rep.add("Response time", True, f"{min(times):.0f} ms best, {sum(times) / len(times):.0f} ms average (3 tries)")
    # Storage round trip on this provider alone (no payment needed inside the grace period).
    if "STO-1" in entry.get("services", []):
        lease, obj = secrets.token_hex(16), secrets.token_hex(16)
        data = secrets.token_bytes(1 << 20)
        try:
            t0 = time.monotonic()
            p.put_chunk(lease, obj, 0, data)
            up = time.monotonic() - t0
            t0 = time.monotonic()
            back = p.get_chunk(lease, obj, 0)
            down = time.monotonic() - t0
            same = hashlib.sha256(back).digest() == hashlib.sha256(data).digest()
            rep.add("Storage round trip", same, f"1 MiB stored in {up:.1f} s, read back in {down:.1f} s"
                    + ("" if same else "; the data came back different"))
            try:
                p.delete(lease)
            except ProviderError:
                pass
        except ProviderError as exc:
            rep.add("Storage round trip", False, str(exc))
    else:
        rep.add("Storage round trip", None, "does not offer storage")
    # Paid: CPU job on credit the tester paid from its own wallet.
    if "CMP-1" not in entry.get("services", []):
        rep.add("CPU job", None, "does not offer CPU compute")
    elif not credit_tx:
        rep.add("CPU job", None, "pay test USDC to " + ", ".join(entry.get("payto", {}).values())
                + " and run again with --credit-tx 0x…")
    elif not wasm:
        rep.add("CPU job", None, "give a WebAssembly program with --wasm FILE (for example the echo test program)")
    else:
        try:
            p.terms = client.terms
            p.credit(credit_tx)
            msg = b"innernet tester " + secrets.token_hex(4).encode()
            t0 = time.monotonic()
            out = p.run_job(wasm, stdin=msg)
            ok = out["exit_code"] == 0 and out["output"] == msg
            rep.add("CPU job", ok, f"ran in {time.monotonic() - t0:.1f} s · charged {out['receipt'].get('cost')} USDC · "
                    f"credit left {out['receipt'].get('balance')} · signed receipt checked")
        except ProviderError as exc:
            rep.add("CPU job", False, str(exc))
    return rep


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Test an INNERnet provider the way a client sees it")
    ap.add_argument("provider", help="provider id, id prefix or name, or 'all'")
    ap.add_argument("--registry", default=os.environ.get("INNERNET_REGISTRY", REGISTRY))
    ap.add_argument("--accept-terms", default="", help="SHA-256 of the client terms (needed for the paid check)")
    ap.add_argument("--credit-tx", default="", help="transaction that paid test USDC to the provider (paid check)")
    ap.add_argument("--wasm", default="", help="WebAssembly program for the CPU job (reads stdin, writes it back)")
    ap.add_argument("--registry-key", default=os.environ.get("INNERNET_REGISTRY_KEY", ""),
                    help="the registry's public key (hex) to pin; default: ask the registry (trust on first use)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    a = ap.parse_args(argv)
    key = a.registry_key or httpx.get(a.registry.rstrip("/") + "/registry-key", timeout=20).json()["registry_key"]
    client = Client(registry_url=a.registry, presence_url=a.registry, accept_terms=a.accept_terms or None,
                    pinned=[bytes.fromhex(key)])
    hits = find(client, a.provider)
    if not hits:
        print(f"No listed provider matches {a.provider!r}. Only listed machines can be tested.", file=sys.stderr)
        return 2
    wasm = open(a.wasm, "rb").read() if a.wasm else (bytes.fromhex(ECHO_WASM_HEX) if ECHO_WASM_HEX else b"")
    reports = [test_provider(client, e, a.credit_tx, wasm) for e in hits]
    if a.json:
        print(json.dumps([{"provider": e["id"], "name": e.get("name"), "passed": not r.failed, "checks": r.rows}
                          for e, r in zip(hits, reports)], indent=1))
    else:
        for r in reports:
            print(r.text())
    return 1 if any(r.failed for r in reports) else 0


if __name__ == "__main__":
    sys.exit(main())
