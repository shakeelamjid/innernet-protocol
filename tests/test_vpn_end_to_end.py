"""VPN exit (VPN-1) end to end: the real Go provider as exit, the Python SOCKS5 client, a local web
server as the destination. Credit, per-GiB charging, receipts, consent and port rules."""
from __future__ import annotations

import json
import os
import socket
import struct
import subprocess
import threading
import time
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from innernet2.irm_client import Provider
from innernet2.irm_registry import verify_descriptor
from innernet2.vpn import ExitError, open_exit, serve_socks

from tests.test_compute_end_to_end import built  # noqa: F401  (fixture)
from tests.test_irm_end_to_end import CLIENT_TERMS, GO, SEPOLIA, FakeChain, free_port

pytestmark = pytest.mark.skipif(GO is None, reason="Go toolchain not installed")
PAGE = os.urandom(3 * 1024 * 1024)            # 3 MiB, so the per-MiB charging runs


def web():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(PAGE)))
            self.end_headers()
            self.wfile.write(PAGE)
    s = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


def provider(built, tmp_path, *flags):  # noqa: F811
    chain = FakeChain()
    home, port = tmp_path / "exit", free_port()
    env = {**os.environ, "INNERNET_HOME": str(home), "INNERNET_RPC": chain.url, "INNERNET_TEST_HTTP": "1",
           "INNERNET_CLIENT_TERMS": CLIENT_TERMS, "INNERNET_NO_PRESENCE": "1"}
    run = lambda *a: subprocess.run([str(built / "innernet-provider"), *a], env=env, check=True,  # noqa: E731
                                    capture_output=True, text=True)
    run("init", "--yes", "--network", "base-sepolia", "--name", "exit1", "--region", "asia-south", "--host", "127.0.0.1", "--port", str(port),
        "--relay-gib", "1", "--price-relay", "0.01", "--price-vpn", "1.024", *flags)
    run("wallet", "set", "0x" + "cd" * 20)
    run("apply", "--dry-run")
    entry = verify_descriptor(json.loads((home / "descriptor.json").read_text()))
    proc = subprocess.Popen([str(built / "innernet-provider"), "serve", "--listen", f"127.0.0.1:{port}"], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            if httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=0.5).status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.05)
    return entry, chain, proc


def socks_get(proxy_port: int, host: str, port: int) -> bytes:
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=30)
    s.sendall(b"\x05\x01\x00")
    assert s.recv(2) == b"\x05\x00"
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host.encode() + struct.pack(">H", port))
    rep = s.recv(10)
    if rep[1] != 0:
        s.close()
        raise ConnectionRefusedError(rep[1])
    s.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
    out = b""
    while chunk := s.recv(65536):
        out += chunk
    s.close()
    return out.split(b"\r\n\r\n", 1)[1]


def test_vpn_exit_carries_traffic_and_charges_per_gib(built, tmp_path):  # noqa: F811
    entry, chain, proc = provider(built, tmp_path, "--vpn", "--vpn-consent", "--vpn-all-ports")
    try:
        assert "VPN-1" in entry["services"] and entry["limits"]["VPN-1"] == {"max_gib_per_month": 1, "all_ports": 1}
        site = web()
        p = Provider(entry, Ed25519PrivateKey.generate(), terms=CLIENT_TERMS)
        with pytest.raises(ExitError, match="add credit"):
            open_exit(p, "127.0.0.1", site.server_address[1])
        p.credit(chain.pay(SEPOLIA, entry["payto"][SEPOLIA], 1_000_000))       # 1 USDC
        receipts, ready, stop = [], threading.Event(), threading.Event()
        threading.Thread(target=serve_socks, args=(p, ("127.0.0.1", 0), receipts, ready, stop), daemon=True).start()
        ready.wait(5)
        body = socks_get(ready.port, "127.0.0.1", site.server_address[1])
        assert body == PAGE
        for _ in range(50):
            if receipts:
                break
            time.sleep(0.1)
        r = receipts[0]
        # 1.024 USDC per GiB = 0.001 per MiB; a bit over 3 MiB went through
        assert r["service"] == "VPN-1" and r["unit"] == "GiB" and Decimal("0.003") <= Decimal(r["cost"]) < Decimal("0.0045")
        assert Decimal(p.balance()) == Decimal(1) - Decimal(r["cost"])
        no_terms = Provider(entry, p.key, terms="")
        with pytest.raises(ExitError, match="client terms"):
            open_exit(no_terms, "127.0.0.1", site.server_address[1])
        stop.set()
        site.shutdown()
    finally:
        proc.kill()
        chain.server.shutdown()


def test_web_only_exit_and_no_exit_without_consent(built, tmp_path):  # noqa: F811
    entry, chain, proc = provider(built, tmp_path, "--vpn", "--vpn-consent")
    try:
        p = Provider(entry, Ed25519PrivateKey.generate(), terms=CLIENT_TERMS)
        p.credit(chain.pay(SEPOLIA, entry["payto"][SEPOLIA], 1_000_000))
        with pytest.raises(ExitError, match="80 and 443"):
            open_exit(p, "127.0.0.1", 8080)
    finally:
        proc.kill()
        chain.server.shutdown()
    r = subprocess.run([str(built / "innernet-provider"), "init", "--yes", "--network", "base-sepolia", "--name", "x", "--region", "eu", "--host", "127.0.0.1",
                        "--relay-gib", "1", "--vpn"], env={**os.environ, "INNERNET_HOME": str(tmp_path / "x")},
                       capture_output=True, text=True)
    assert r.returncode != 0 and "--vpn-consent" in r.stderr
