"""Compute end to end with the real Go provider: credit from an on-chain payment, CPU jobs
(WebAssembly) and GPU jobs (WebGPU modules in Deno). GPU tests need deno (INNERNET_DENO or on PATH)."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import subprocess
import threading
import time
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from concurrent.futures import ThreadPoolExecutor

from innernet2.irm_client import Provider, ProviderBusy, ProviderError
from innernet2.irm_registry import verify_descriptor

from tests.test_irm_end_to_end import CLIENT_TERMS, GO, ROOT, SEPOLIA, FakeChain, free_port

pytestmark = pytest.mark.skipif(GO is None, reason="Go toolchain not installed")



class Files:
    """Serves files over local HTTP, like a model or program host."""

    def __init__(self, files: dict[str, bytes]):
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                data = files.get(self.path.lstrip("/"))
                self.send_response(200 if data is not None else 404)
                self.send_header("Content-Length", str(len(data or b"")))
                self.end_headers()
                self.wfile.write(data or b"")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    d = tmp_path_factory.mktemp("bin")
    env = {**os.environ, "CGO_ENABLED": "0"}
    subprocess.run([GO, "build", "-o", str(d / "innernet-provider"), "."], cwd=ROOT / "provider", check=True,
                   capture_output=True, env=env)
    subprocess.run([GO, "build", "-o", str(d / "job.wasm"), "."], cwd=ROOT / "provider/testdata/wasmjob", check=True,
                   capture_output=True, env={**env, "GOOS": "wasip1", "GOARCH": "wasm"})
    return d


DENO = os.environ.get("INNERNET_DENO") or shutil.which("deno")
needs_deno = pytest.mark.skipif(not DENO, reason="deno not installed")
DOUBLE = (ROOT / "provider/testdata/gpujob/double.js").read_bytes()


@pytest.fixture
def compute(built, tmp_path):
    chain = FakeChain()
    home, port = tmp_path / "p", free_port()
    env = {**os.environ, "INNERNET_HOME": str(home), "INNERNET_RPC": chain.url, "INNERNET_TEST_HTTP": "1",
           "INNERNET_CLIENT_TERMS": CLIENT_TERMS,
           "INNERNET_DENO": DENO or "/nonexistent/deno", "INNERNET_NO_PRESENCE": "1",
           "INNERNET_TEST_GPUS": json.dumps([{"vendor": "NVIDIA", "model": "NVIDIA L4", "vram_mib": 23034, "api": "cuda"}])}
    run = lambda *a: subprocess.run([str(built / "innernet-provider"), *a], env=env, check=True,  # noqa: E731
                                    capture_output=True, text=True)
    run("init", "--yes", "--network", "base-sepolia", "--name", "gpu1", "--region", "asia-south", "--host", "127.0.0.1", "--port", str(port),
        "--compute", "--cpus", "2", "--memory-mib", "256", "--price-compute", "0.36",
        "--gpus", "1", "--price-gpu", "3.60", "--per-client", "1", "--reserve-gib", "0")
    run("wallet", "set", "0x" + "ab" * 20)
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
    yield Provider(entry, Ed25519PrivateKey.generate(), terms=CLIENT_TERMS), entry, chain, built
    proc.kill()
    chain.server.shutdown()


def test_descriptor_lists_cpu_and_gpu_per_hour(compute):
    _, entry, _, _ = compute
    assert entry["prices"]["CMP-1"] == {"asset": "USDC", "unit": "CPU-hour", "amount": "0.36"}
    assert entry["prices"]["GPU-1"]["unit"] == "GPU-hour" and entry["hardware"]["gpu_model"] == "NVIDIA L4"
    assert entry["limits"]["CMP-1"] == {"max_cpus": 2, "max_memory_mib": 256}


def test_credit_then_cpu_job(compute):
    p, entry, chain, built = compute
    wasm = (built / "job.wasm").read_bytes()
    files = Files({"job.wasm": wasm})
    url, sha = files.url + "/job.wasm", hashlib.sha256(wasm).hexdigest()
    with pytest.raises(ProviderError, match="add credit"):
        p.run_job(wasm_url=url, wasm_sha256=sha, stdin=b"x")
    tx = chain.pay(SEPOLIA, entry["payto"][SEPOLIA], 1_000_000)         # 1 USDC
    assert p.credit(tx)["balance"] == "1"
    with pytest.raises(ProviderError, match="already used"):
        p.credit(tx)
    a = p.run_job(wasm_url=url, wasm_sha256=sha, stdin=b"hello", seed=5, max_seconds=30)
    b = p.run_job(wasm_url=url, wasm_sha256=sha, stdin=b"hello", seed=5, max_seconds=30)
    assert a["output"].startswith(b"HELLO|") and a["output"] == b["output"] and a["exit_code"] == 0
    r = a["receipt"]
    assert r["service"] == "CMP-1" and r["unit"] == "CPU-second" and r["wasm_sha256"] == sha
    # 0.36 USDC per CPU-hour = 0.0001 per second: a sub-second job costs a few base units
    assert Decimal(r["cost"]) < Decimal("0.001") and Decimal(p.balance()) == Decimal(b["receipt"]["balance"])
    bad = p.run_job(wasm_url=url, wasm_sha256=sha, args=("spin",), max_seconds=2)
    assert "time limit" in bad["error"]
    assert Decimal(bad["receipt"]["cost"]) >= Decimal("0.0002")                # about 2 s charged
    with pytest.raises(ProviderError, match="SHA-256"):
        p.run_job(wasm_url=url, wasm_sha256="00" * 32)
    files.server.shutdown()


def test_many_clients_at_once_fair_and_bounded(compute):
    p, entry, chain, built = compute
    wasm = (built / "job.wasm").read_bytes()
    files = Files({"job.wasm": wasm})
    url, sha = files.url + "/job.wasm", hashlib.sha256(wasm).hexdigest()
    a, b, c = (Provider(entry, Ed25519PrivateKey.generate(), terms=CLIENT_TERMS) for _ in range(3))
    for cl in (a, b, c):
        cl.credit(chain.pay(SEPOLIA, entry["payto"][SEPOLIA], 1_000_000))
    a.run_job(wasm_url=url, wasm_sha256=sha)                       # module cached before timing
    with ThreadPoolExecutor(4) as pool:
        t0 = time.monotonic()
        fa = pool.submit(a.run_job, wasm_url=url, wasm_sha256=sha, args=("spin",), max_seconds=2)
        fb = pool.submit(b.run_job, wasm_url=url, wasm_sha256=sha, args=("spin",), max_seconds=2)
        time.sleep(0.4)
        # client a is at its cap of 1 running job: told at once, no charge
        with pytest.raises(ProviderBusy):
            a.run_job(wasm_url=url, wasm_sha256=sha, queue_seconds=0)
        # both CPUs are busy: client c waits in line, then runs when one frees up
        fc = pool.submit(c.run_job, wasm_url=url, wasm_sha256=sha, stdin=b"c", queue_seconds=20)
        ra, rb, rc = fa.result(), fb.result(), fc.result()
        took = time.monotonic() - t0
    assert "time limit" in ra["error"] and "time limit" in rb["error"]
    assert rc["output"].startswith(b"C|") and 1.5 < took < 8           # a and b ran side by side
    assert Decimal(a.balance()) > Decimal("0.99")                       # the refused job cost nothing
    files.server.shutdown()


@needs_deno
def test_gpu_job_runs_webgpu_and_is_sealed(compute):
    p, entry, chain, _ = compute
    p.credit(chain.pay(SEPOLIA, entry["payto"][SEPOLIA], 1_000_000))
    nums = [i + 0.25 for i in range(256)]
    out = p.run_gpu_job(DOUBLE, stdin=struct.pack("<256f", *nums), max_seconds=60)
    assert out["error"] is None and list(struct.unpack("<256f", out["output"])) == [2 * x for x in nums]
    r = out["receipt"]
    assert r["service"] == "GPU-1" and r["unit"] == "GPU-second" and r["program_sha256"] == hashlib.sha256(DOUBLE).hexdigest()
    # 3.60 USDC per GPU-hour = 0.001 per second
    assert Decimal(r["cost"]) == (Decimal(r["units"]) * Decimal("0.001")).quantize(Decimal("0.000001"), rounding="ROUND_CEILING")
    probe = json.loads(p.run_gpu_job(DOUBLE, args=("probe",))["output"])
    assert probe == {"files": "NotCapable", "network": "NotCapable", "env": "NotCapable", "run": "NotCapable"}
    spin = p.run_gpu_job(DOUBLE, args=("spin",), max_seconds=2)
    assert "time limit" in spin["error"] and Decimal(spin["receipt"]["cost"]) >= Decimal("0.002")


@needs_deno
def test_gpu_job_by_url_hash_checked_and_one_at_a_time(compute):
    p, entry, chain, _ = compute
    files = Files({"double.js": DOUBLE})
    url, sha = files.url + "/double.js", hashlib.sha256(DOUBLE).hexdigest()
    a, b = Provider(entry, Ed25519PrivateKey.generate(), terms=CLIENT_TERMS), Provider(entry, Ed25519PrivateKey.generate(), terms=CLIENT_TERMS)
    for cl in (a, b):
        cl.credit(chain.pay(SEPOLIA, entry["payto"][SEPOLIA], 1_000_000))
    with pytest.raises(ProviderError, match="SHA-256"):
        a.run_gpu_job(program_url=url, program_sha256="00" * 32)
    with ThreadPoolExecutor(2) as pool:
        fa = pool.submit(a.run_gpu_job, program_url=url, program_sha256=sha, args=("spin",), max_seconds=3)
        time.sleep(0.8)
        with pytest.raises(ProviderBusy):                      # one GPU: the second client is told at once
            b.run_gpu_job(program_url=url, program_sha256=sha, queue_seconds=0)
        fb = pool.submit(b.run_gpu_job, program_url=url, program_sha256=sha, stdin=struct.pack("<4f", 1, 2, 3, 4),
                         queue_seconds=30)
        assert "time limit" in fa.result()["error"]
        assert struct.unpack("<4f", fb.result()["output"]) == (2, 4, 6, 8)
    files.server.shutdown()
