"""Machines nobody can connect to: providers reached through an INNERnet relay (RLY-0 over
ST81, with a second ST81 session end to end inside) or, as a fallback, the registry's HTTPS
tunnel. Real registry, real relay, real providers, the real client."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_registry_service import SEPOLIA, free_tcp_port, live_registry  # noqa: E402

from innernet2.irm_client import Client, Provider  # noqa: E402
from innernet2.irm_registry import sign_registry  # noqa: E402
from innernet2.registry_service.terms import current as _current_terms  # noqa: E402

CLIENT_TERMS = _current_terms("client")["sha256"]

GO = shutil.which("go")
pytestmark = pytest.mark.skipif(GO is None, reason="Go toolchain not installed")
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def binary(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("bin") / "innernet-provider"
    subprocess.run([GO, "build", "-o", str(out), "."], cwd=ROOT / "provider", check=True, capture_output=True,
                   env={**os.environ, "CGO_ENABLED": "0"})
    return out


def start_relay(binary: Path, home: Path):
    port = free_tcp_port()
    proc = subprocess.Popen([str(binary), "relay", "--listen", f"127.0.0.1:{port}"],
                            env={**os.environ, "INNERNET_HOME": str(home)}, stderr=subprocess.PIPE, text=True)
    line = proc.stderr.readline()
    key = re.search(r"relay key ([0-9a-f]{64})", line).group(1)
    return proc, f"127.0.0.1:{port}", key


def wait_for(fn, seconds=15.0):
    end = time.time() + seconds
    while time.time() < end:
        got = fn()
        if got:
            return got
        time.sleep(0.1)
    return None


def test_providers_behind_routers_serve_through_the_st81_relay_and_the_https_tunnel(binary, tmp_path):
    relay, relay_addr, relay_key = start_relay(binary, tmp_path / "relay")
    server, th, port, fake, store = live_registry(tmp_path, split_factory={SEPOLIA: "0x" + "fa" * 20},
                                                  relays=[{"addr": relay_addr, "key": relay_key}])
    reg = f"http://127.0.0.1:{port}/registry/v1"
    procs = [relay]
    try:
        cfg = httpx.get(reg + "/config").json()
        assert cfg["relays"] == [{"addr": relay_addr, "key": relay_key}]
        ids = []
        for i, via in enumerate(["relay", "relay", "relay", "tunnel"]):
            wallet = "0x" + f"{i + 60:02x}" * 20
            fake.splits[wallet] = "0x" + f"{i + 70:02x}" * 20
            env = {**os.environ, "INNERNET_HOME": str(tmp_path / f"p{i}"), "INNERNET_REGISTRY": reg,
                   "INNERNET_NO_SERVICE": "1", "INNERNET_NO_PORTMAP": "1", "INNERNET_NO_FIREWALL": "1",
                   "INNERNET_POLL_MS": "100", "INNERNET_PRESENCE_SEC": "1", "TZ": "Asia/Karachi"}
            r = subprocess.run([str(binary), "start", "--yes", "--wallet", wallet, "--via", via, "--port", str(free_tcp_port()),
                                "--registry", reg], env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)
            assert r.returncode == 0, r.stdout + r.stderr
            assert f"through {via}" in r.stdout
            desc = json.loads((tmp_path / f"p{i}" / "descriptor.json").read_text())
            entry = desc["payload"]["provider"]
            if via == "relay":
                assert entry["endpoints"] == [{"host": "127.0.0.1", "port": int(relay_addr.split(":")[1])}]
            ids.append(entry["id"])
            procs.append(subprocess.Popen([str(binary), "serve", "--listen", "127.0.0.1:0"], env=env,
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        # each provider checks in; the registry reaches the relayed ones through the relay, end to end
        for pid, path in zip(ids, ["relay", "relay", "relay", "tunnel"]):
            live = wait_for(lambda: (lambda r: r.json() if r.status_code == 200 and r.json()["reachable"] else None)(
                httpx.get(f"{reg}/presence/{pid}")))
            assert live and live["record"]["payload"]["path"] == path, (pid, live)
            if path == "relay":
                assert live["record"]["payload"]["relay_key"] == relay_key

        # the client follows live presence: ST81 through the relay for three, HTTPS tunnel for one
        for pid in ids:
            store.x("UPDATE providers SET state='listed', listed_at=? WHERE id=?", (int(time.time()), pid))
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        rk = Ed25519PrivateKey.generate()
        now = int(time.time())
        entries = [dict(store.provider(pid)["entry"], listed_at=1) for pid in ids]
        doc = sign_registry({"version": "REG-1", "sequence": now, "issued_at": now, "expires_at": now + 3600, "fee_bps": 250,
                             "fee_payto": {SEPOLIA: "0x" + "fe" * 20}, "providers": entries}, rk, now=now)
        client = Client(tmp_path / "client", registry_doc=doc, pinned=[rk.public_key().public_bytes_raw()], presence_url=reg,
                        accept_terms=CLIENT_TERMS)
        data = os.urandom(150_000)
        rec = client.put(data, "behind-a-router.bin")
        assert client.get(rec["object"]) == data
        assert all(v["ok"] for v in client.check(rec["object"]).values())
        h = next(h for h in rec["holders"] if h["provider"] in ids[:3])
        p = client.provider(h["entry"])
        assert p.route["path"] == "relay" and p.route["relay_key"] == relay_key
        assert len(p.get_chunk(h["lease"], rec["object"], 0)) > 0 and p.last_transport == "st81"
        t = client.provider(entries[3])
        assert t.route["path"] == "tunnel" and t.base.endswith(f"/registry/t/{ids[3]}")
        info = httpx.get(t.base + "/sto/v1/info").json()                  # through the HTTPS tunnel
        assert info["provider"] == ids[3]

        # the registry's end-to-end check through the relay works, and fails once the relay is gone
        from innernet2.registry_service.presence import relay_check
        rhost, rport = relay_addr.split(":")
        assert relay_check(rhost, int(rport), relay_key, ids[0])
        relay.kill()
        relay.wait()
        assert not relay_check(rhost, int(rport), relay_key, ids[0], timeout=2)
        assert httpx.get(t.base + "/sto/v1/info").status_code == 200        # the tunnel provider is unaffected
    finally:
        for proc in procs:
            proc.kill()
        server.should_exit = True
        th.join(timeout=5)


def test_relay_cannot_read_or_impersonate(binary, tmp_path):
    """The client pins the provider key inside the relayed stream: a relay that answers for the
    wrong provider (or a provider that is not attached) is refused."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from innernet2 import rly0, stream_v080 as st
    relay, relay_addr, relay_key = start_relay(binary, tmp_path / "relay")
    try:
        host, port = relay_addr.split(":")
        with pytest.raises(st.StreamError, match="not connected"):
            rly0.connect(host, int(port), bytes.fromhex(relay_key), os.urandom(32), Ed25519PrivateKey.generate(), timeout=3)
        with pytest.raises(st.StreamError):                                # wrong relay pin
            rly0.connect(host, int(port), os.urandom(32), os.urandom(32), Ed25519PrivateKey.generate(), timeout=3)
    finally:
        relay.kill()
