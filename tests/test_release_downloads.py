"""Downloads under the network's own address: /registry/dl/* forwards to the release files, and the
installer works against it (checksum checked)."""
from __future__ import annotations

import hashlib
import os
import platform
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest

from innernet2.registry_service.releases import Releases

ROOT = Path(__file__).resolve().parents[1]


class Fake:
    def __init__(self, status, payload=None, text=""):
        self.status_code, self._p, self.text = status, payload, text

    def json(self):
        return self._p


def test_latest_picks_the_highest_published_release_and_falls_back():
    calls = []

    def get(url, **kw):
        calls.append(url)
        if "api.github.com" in url:
            return Fake(200, [{"tag_name": "provider-v0.10.0"}, {"tag_name": "provider-v0.9.9"},
                              {"tag_name": "v1.0.0"}, {"tag_name": "provider-v0.11.0", "draft": True}])
        return Fake(404)
    r = Releases("owner/repo", get=get)
    assert r.latest() == "provider-v0.10.0" and r.latest() == "provider-v0.10.0" and len(calls) == 1   # cached
    r2 = Releases("owner/repo", get=lambda url, **kw: Fake(403) if "api." in url else Fake(200, text="provider-v0.6.0\n"))
    assert r2.latest() == "provider-v0.6.0"
    assert r.file_url("provider-v0.6.0", "innernet-provider-darwin-arm64") == \
        "https://github.com/owner/repo/releases/download/provider-v0.6.0/innernet-provider-darwin-arm64"
    for tag, name in (("v1.0.0", "SHA256SUMS"), ("provider-v0.6.0", "../secrets"), ("provider-v0.6.0", "x.exe")):
        assert r.file_url(tag, name) is None


@pytest.mark.skipif(platform.system() not in ("Linux", "Darwin") or not shutil.which("sh"), reason="POSIX shell needed")
def test_installer_uses_the_download_address_and_checks_the_sum(tmp_path):
    osname = {"Linux": "linux", "Darwin": "darwin"}[platform.system()]
    arch = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}[platform.machine().lower()]
    asset = f"innernet-provider-{osname}-{arch}"
    prog = b"#!/bin/sh\necho innernet-provider 9.9.9\n"
    files = {"/latest": b"provider-v9.9.9\n", f"/provider-v9.9.9/{asset}": prog,
             "/provider-v9.9.9/SHA256SUMS": f"{hashlib.sha256(prog).hexdigest()}  {asset}\n".encode()}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = files.get(self.path)
            self.send_response(200 if body is not None else 404)
            self.end_headers()
            self.wfile.write(body or b"")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    env = {**os.environ, "INNERNET_DL": f"http://127.0.0.1:{srv.server_address[1]}", "INNERNET_BIN_DIR": str(tmp_path / "bin"),
           "NO_COLOR": "1"}
    r = subprocess.run(["sh", str(ROOT / "provider/install.sh")], env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert "provider-v9.9.9" in r.stdout and (tmp_path / "bin/innernet-provider").read_bytes() == prog
    assert "shakeelamjid" not in r.stdout + r.stderr
    files[f"/provider-v9.9.9/{asset}"] = b"tampered"
    bad = subprocess.run(["sh", str(ROOT / "provider/install.sh")], env=env, capture_output=True, text=True, timeout=60)
    assert bad.returncode != 0 and "checksum mismatch" in bad.stderr
    srv.shutdown()
