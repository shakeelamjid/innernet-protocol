"""IRM-1 end to end: 4 real Go providers (`innernet-provider serve`), the Python client,
a signed registry document and a fake chain. Files are sealed, mixed and spread as 6 shards
(any 4 rebuild). One provider goes down; the client keeps reading, detects it, stops paying
it and rebuilds its shards onto another provider."""
from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from innernet2.irm_client import Client, Provider, ProviderError
from innernet2.irm_registry import sign_registry, verify_descriptor, verify_ticket

GO = shutil.which("go")
pytestmark = pytest.mark.skipif(GO is None, reason="Go toolchain not installed")
ROOT = Path(__file__).resolve().parents[1]
SEPOLIA = "eip155:84532"
USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
FEE = "0x" + "fe" * 20


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class FakeChain:
    """Just enough JSON-RPC for providers to check USDC payments."""

    def __init__(self):
        self.receipts: dict[str, dict] = {}
        chain = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                result = chain.receipts.get(req["params"][0].lower()) if req["method"] == "eth_getTransactionReceipt" else None
                body = json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": result}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.payments: list[tuple[str, int]] = []

    def pay(self, network: str, payto: str, amount: int) -> str:
        tx = "0x" + secrets.token_hex(32)
        self.receipts[tx] = {"status": "0x1", "logs": [{"address": USDC, "data": hex(amount),
                             "topics": [TRANSFER, "0x" + "0" * 24 + "11" * 20, "0x" + "0" * 24 + payto[2:].lower()]}]}
        self.payments.append((payto, amount))
        return tx


@pytest.fixture(scope="module")
def binary(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("bin") / "innernet-provider"
    subprocess.run([GO, "build", "-o", str(out), "."], cwd=ROOT / "provider", check=True, capture_output=True,
                   env={**os.environ, "CGO_ENABLED": "0"})
    return out


@pytest.fixture
def network(binary, tmp_path):
    chain = FakeChain()
    regions = ["asia-south", "eu-central", "us-east", "eu-central"]
    providers, procs = [], []
    for i, region in enumerate(regions):
        home = tmp_path / f"p{i}"
        port = free_port()
        env = {**os.environ, "INNERNET_HOME": str(home), "INNERNET_RPC": chain.url}
        run = lambda *a: subprocess.run([str(binary), *a], env=env, check=True, capture_output=True, text=True)  # noqa: E731
        run("init", "--yes", "--name", f"p{i}", "--region", region, "--host", "127.0.0.1", "--port", str(port),
            "--storage-gib", "1", "--price-storage", "0.0020")
        run("wallet", "set", "0x" + f"{i + 1:02x}" * 20)
        run("apply", "--dry-run")
        entry = verify_descriptor(json.loads((home / "descriptor.json").read_text()))
        proc = subprocess.Popen([str(binary), "serve", "--listen", f"127.0.0.1:{port}"], env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(proc)
        for _ in range(100):
            try:
                if httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=0.5).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.05)
        providers.append(dict(entry, listed_at=1))
    reg_key = Ed25519PrivateKey.generate()
    now = int(time.time())
    doc = sign_registry({"version": "REG-1", "sequence": now, "issued_at": now, "expires_at": now + 3600, "fee_bps": 250,
                         "fee_payto": {SEPOLIA: FEE}, "providers": providers}, reg_key, now=now)
    client = Client(tmp_path / "client", registry_doc=doc, pinned=[reg_key.public_key().public_bytes_raw()])
    yield client, providers, procs, chain, tmp_path
    for p in procs:
        p.kill()
    chain.server.shutdown()


def _slots(rec):
    count = {}
    for h in rec["holders"]:
        count[h["name"]] = count.get(h["name"], 0) + 1
    return count


def test_store_fail_over_check_pay_and_repair(network):
    client, providers, procs, chain, tmp = network
    data = os.urandom(200_000)                                   # 4 chunks
    rec = client.put(data, "report.bin")
    assert rec["version"] == "IRM1-CLIENT-2" and (rec["k"], rec["n"]) == (4, 6)
    assert sorted(h["slot"] for h in rec["holders"]) == list(range(6))
    count = _slots(rec)
    assert set(count) == {"p0", "p1", "p2", "p3"} and max(count.values()) == 2   # all 4 used, at most 2 slots each
    assert client.get(rec["object"]) == data

    # Providers only hold shards of sealed, mixed chunks: no plaintext, and about 1.5x the size in total.
    stored = {p: b"".join(f.read_bytes() for f in (tmp / p / "data").rglob("*.chunk")) for p in count}
    assert all(data[:4096] not in s for s in stored.values())
    total = sum(len(s) for s in stored.values())
    assert 1.4 * len(data) < total < 1.7 * len(data)
    # No provider holds enough to rebuild anything on its own.
    assert all(len(s) < 0.6 * len(data) for s in stored.values())

    # Every holder passes the daily check and gets paid for this epoch; tickets verify.
    assert all(v["ok"] for v in client.check(rec["object"]).values())
    paid = client.pay(rec["object"], chain.pay)
    assert len(paid) == 6 and all(v.startswith("paid") for v in paid.values()) and len(chain.payments) == 6
    first = rec["holders"][0]
    assert client.pay(rec["object"], chain.pay)[f"{first['provider']}#{first['slot']}"] == "already paid"

    # A provider holding 2 shards goes down: 4 remain, reads still work, its checks fail, it is not paid.
    victim = next(i for i, p in enumerate(providers) if count[p["name"]] == 2)
    vid = providers[victim]["id"]
    procs[victim].kill()
    procs[victim].wait()
    assert client.get(rec["object"]) == data
    res = client.check(rec["object"])
    assert all(not v["ok"] for v in res.values() if v["provider"] == vid)
    assert all(v["ok"] for v in res.values() if v["provider"] != vid)
    out = client.pay(rec["object"], chain.pay, epoch=int(time.time() // 86400) + 1)
    assert all(v.startswith("not paid") for k, v in out.items() if k.startswith(vid))

    # Within the grace period nothing moves; forced, both shards are rebuilt onto other providers.
    assert client.repair(rec["object"]) == []
    changes = client.repair(rec["object"], force=True)
    assert len(changes) == 2 and all(c["replaced"] == vid and c["with"] not in (None, vid) for c in changes)
    rec = client.load(rec["object"])
    assert vid not in {h["provider"] for h in rec["holders"]} and max(_slots(rec).values()) == 2
    assert all(v["ok"] for v in client.check(rec["object"]).values())
    assert client.get(rec["object"]) == data
    # Lose one more provider (at most 2 shards): still readable from the remaining 4.
    other = next(i for i, p in enumerate(providers) if i != victim and p["id"] in {h["provider"] for h in rec["holders"]})
    procs[other].kill()
    procs[other].wait()
    assert client.get(rec["object"]) == data


def test_tampered_shard_fails_check_and_get_skips_it(network):
    client, providers, procs, chain, tmp = network
    data = os.urandom(70_000)
    rec = client.put(data, "x")
    victim = rec["holders"][0]
    lease_dir = next(d for d in (tmp / victim["name"] / "data").rglob("*") if d.is_dir() and victim["lease"] in str(d))
    for f in lease_dir.rglob("*.chunk"):
        raw = bytearray(f.read_bytes())
        raw[10] ^= 0xFF
        f.write_bytes(bytes(raw))
    assert client.get(rec["object"]) == data                       # the bad shard is skipped, 4 good ones rebuild
    key = f"{victim['provider']}#{victim['slot']}"
    for _ in range(5):                                             # random samples: catches it fast
        res = client.check(rec["object"], samples=8)
        if not res[key]["ok"]:
            break
    assert not res[key]["ok"]


def test_needs_three_providers(network, tmp_path):
    client, providers, procs, chain, tmp = network
    for p in procs[2:]:
        p.kill()
        p.wait()
    with pytest.raises(Exception, match="at least 3"):
        client.put(os.urandom(10_000), "y")


def test_provider_rejects_wrong_owner_replay_and_reused_payment(network):
    client, providers, procs, chain, tmp = network
    rec = client.put(os.urandom(5000), "small")
    r = rec["holders"][0]
    stranger = Provider(r["entry"], Ed25519PrivateKey.generate())
    with pytest.raises(ProviderError, match="another client"):
        stranger.put_chunk(r["lease"], rec["object"], 0, b"overwrite")
    owner = client.provider(r["entry"])
    tx = chain.pay(SEPOLIA, r["payto"], 1_000_000)
    ticket = owner.pay(r["lease"], "1", tx)
    payload = verify_ticket(ticket, bytes.fromhex(r["provider"]))
    assert payload["payment_tx"] == tx and payload["units"] == "1" and payload["client"] == client.key.public_key().public_bytes_raw().hex()
    with pytest.raises(ProviderError, match="already used"):
        owner.pay(r["lease"], "1", tx)
    small = chain.pay(SEPOLIA, r["payto"], 1)
    with pytest.raises(ProviderError, match="too small"):
        owner.pay(r["lease"], "1000", small)
    other = chain.pay(SEPOLIA, "0x" + "99" * 20, 10_000_000)
    with pytest.raises(ProviderError, match="no USDC transfer"):
        owner.pay(r["lease"], "1", other)
    # A replayed signed request is refused.
    ts, nonce = str(int(time.time())), secrets.token_hex(16)
    import hashlib
    msg = b"INNERnet/STO-1/request\x00" + f"GET\n/sto/v1/leases/{r['lease']}/objects/{rec['object']}/chunks/0\n{hashlib.sha256(b'').hexdigest()}\n{ts}\n{nonce}".encode()
    headers = {"X-Innernet-Client": client.key.public_key().public_bytes_raw().hex(), "X-Innernet-Time": ts,
               "X-Innernet-Nonce": nonce, "X-Innernet-Signature": client.key.sign(msg).hex()}
    url = owner.base + f"/sto/v1/leases/{r['lease']}/objects/{rec['object']}/chunks/0"
    assert httpx.get(url, headers=headers).status_code == 200
    assert httpx.get(url, headers=headers).status_code == 401


def test_st81_is_used_first_and_http_is_the_fallback(network, monkeypatch):
    """Clients speak ST81 to providers by default (pinned to the provider key), on the same port
    as HTTP; with INNERNET_TRANSPORT=http they use the HTTP binding; a provider whose key does not
    match the listing is refused over ST81 (pin) and its HTTP replies fail the signature check."""
    import innernet2.irm_client as ic
    client, providers, procs, chain, tmp = network
    entry = providers[0]
    p = client.provider(entry)
    lease, obj = secrets.token_hex(16), secrets.token_hex(16)
    ack = p.put_chunk(lease, obj, 0, b"sealed shard bytes" * 100)
    assert p.last_transport == "st81" and ack["blocks"] >= 1
    assert p.get_chunk(lease, obj, 0) == b"sealed shard bytes" * 100 and p.last_transport == "st81"
    monkeypatch.setenv("INNERNET_TRANSPORT", "http")
    q = client.provider(entry)
    assert q.get_chunk(lease, obj, 0) == b"sealed shard bytes" * 100 and q.last_transport == "http"
    monkeypatch.setenv("INNERNET_TRANSPORT", "st81")
    impostor = dict(entry, id=providers[1]["id"])                     # listing says another key for this address
    with pytest.raises(ProviderError, match="ST81 failed"):
        client.provider(impostor).get_chunk(lease, obj, 0)
    ic._ST81_DOWN.clear()
    ic._SESSIONS.clear()
