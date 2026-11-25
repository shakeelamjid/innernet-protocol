"""ST81 cross-language conformance: the Go provider's ST81 against the Python reference
(innernet2/stream_v080.py), in both directions, plus refusal of a wrong pin."""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import threading
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from innernet2 import stream_v080 as st

GO = shutil.which("go")
pytestmark = pytest.mark.skipif(GO is None, reason="Go toolchain not installed")
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def binary(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("st81") / "innernet-provider"
    subprocess.run([GO, "build", "-o", str(out), "."], cwd=ROOT / "provider", check=True, capture_output=True,
                   env={**os.environ, "CGO_ENABLED": "0"})
    return out


def test_python_client_to_go_server(binary):
    proc = subprocess.Popen([str(binary), "st81-echo", "127.0.0.1:0"], stdout=subprocess.PIPE, text=True)
    try:
        pin_hex, addr = proc.stdout.readline().split()
        host, port = addr.rsplit(":", 1)
        key = Ed25519PrivateKey.generate()
        s = st.connect(host, int(port), key, bytes.fromhex(pin_hex), timeout=5)
        s.write({"op": "put", "n": 3, "nested": {"a": [1, 2, {"b": "ü"}]}}, b"\x00binary\xff" * 1000)
        head, body = s.read()
        assert head["op"] == "put" and head["nested"]["a"][2]["b"] == "ü" and body == b"\x00binary\xff" * 1000
        assert head["peer"] == key.public_key().public_bytes_raw().hex()           # Go authenticated our key
        for i in range(20):                                                         # counters stay in step
            s.write({"i": i})
            assert s.read()[0]["i"] == i
        s.sock.close()
        with pytest.raises(st.StreamError):                                         # wrong pin refused
            st.connect(host, int(port), key, os.urandom(32), timeout=3)
    finally:
        proc.kill()


def test_go_client_to_python_server(binary):
    server_key = Ed25519PrivateKey.generate()
    ln = socket.socket()
    ln.bind(("127.0.0.1", 0))
    ln.listen(1)
    port = ln.getsockname()[1]
    seen = {}

    def serve():
        conn, _ = ln.accept()
        # Python reference responder with an allowlist; allow whatever key the Go client presents
        class Any(set):
            def __contains__(self, item):
                seen["client"] = item.hex()
                return True
        s = st.accept(conn, server_key, Any())
        head, body = s.read()
        s.write({"echo": head["op"], "n": head["n"] + 1}, body[::-1])
        conn.close()

    th = threading.Thread(target=serve, daemon=True)
    th.start()
    pin = server_key.public_key().public_bytes_raw().hex()
    r = subprocess.run([str(binary), "st81-ping", f"127.0.0.1:{port}", pin], capture_output=True, text=True, timeout=20)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["header"] == {"echo": "ping", "n": 8} and out["body"] == "olleh" and out["me"] == seen["client"]
    th.join(timeout=5)
    ln.close()
