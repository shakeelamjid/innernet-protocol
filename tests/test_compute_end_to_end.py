"""Compute end to end with the real Go provider: credit from an on-chain payment, a CPU job
(WebAssembly) and a GPU session running the client's own model file. llama-server is replaced by
a small stand-in that speaks its HTTP API; everything else is the real code."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
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

from tests.test_irm_end_to_end import GO, ROOT, SEPOLIA, FakeChain, free_port

pytestmark = pytest.mark.skipif(GO is None, reason="Go toolchain not installed")

FAKE_LLAMA = '''import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
args = sys.argv[1:]
port = int(args[args.index("--port") + 1]); model = args[args.index("-m") + 1]
open(model, "rb").read(4)
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(200 if self.path == "/health" else 404); self.end_headers(); self.wfile.write(b"{}")
    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        text = "echo: " + req["messages"][-1]["content"]
        body = json.dumps({"choices": [{"index": 0, "message": {"role": "assistant", "content": text}}],
                           "usage": {"prompt_tokens": 7, "completion_tokens": 3}}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(body)
ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
'''


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
    fake = d / "llama-server"
    fake.write_text("#!" + sys.executable + "\n" + FAKE_LLAMA)
    fake.chmod(0o755)
    return d


@pytest.fixture
def compute(built, tmp_path):
    chain = FakeChain()
    home, port = tmp_path / "p", free_port()
    env = {**os.environ, "INNERNET_HOME": str(home), "INNERNET_RPC": chain.url, "INNERNET_TEST_HTTP": "1",
           "INNERNET_LLAMA_SERVER": str(built / "llama-server"), "INNERNET_NO_PRESENCE": "1",
           "INNERNET_TEST_GPUS": json.dumps([{"vendor": "NVIDIA", "model": "NVIDIA L4", "vram_mib": 23034, "api": "cuda"}])}
    run = lambda *a: subprocess.run([str(built / "innernet-provider"), *a], env=env, check=True,  # noqa: E731
                                    capture_output=True, text=True)
    run("init", "--yes", "--name", "gpu1", "--region", "asia-south", "--host", "127.0.0.1", "--port", str(port),
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
    yield Provider(entry, Ed25519PrivateKey.generate()), entry, chain, built
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


def test_gpu_session_with_clients_own_model(compute):
    p, entry, chain, _ = compute
    model = os.urandom(300_000)
    files = Files({"my-model.gguf": model})
    tx = chain.pay(SEPOLIA, entry["payto"][SEPOLIA], 2_000_000)
    p.credit(tx)
    with pytest.raises(ProviderError, match="sha256"):
        p.gpu_start(files.url + "/my-model.gguf", "zz")
    sid = p.gpu_start(files.url + "/my-model.gguf", hashlib.sha256(model).hexdigest(), max_seconds=600)
    # 3.60 USDC per GPU-hour, 600 s held up front
    assert Decimal(p.balance()) == Decimal("1.4")
    with pytest.raises(ProviderError, match="in use"):
        p.gpu_start(files.url + "/my-model.gguf", hashlib.sha256(model).hexdigest())
    st = p.gpu_wait(sid, timeout=30, every=0.2)
    assert st["status"] == "ready", st
    ans = p.gpu_chat(sid, [{"role": "user", "content": "hi"}], max_tokens=10)
    assert ans["choices"][0]["message"]["content"] == "echo: hi" and ans["usage"]["completion_tokens"] == 3
    time.sleep(1.2)
    end = p.gpu_end(sid)
    r = end["receipt"]
    assert r["service"] == "GPU-1" and r["unit"] == "GPU-second" and int(r["units"]) >= 1
    assert Decimal(r["cost"]) == Decimal(r["units"]) * Decimal("0.001")       # 3.60 / 3600 per second
    assert Decimal(p.balance()) == Decimal("2") - Decimal(r["cost"])
    with pytest.raises(ProviderError, match="not ready"):
        p.gpu_chat(sid, [{"role": "user", "content": "again"}])
    other = Provider(entry, Ed25519PrivateKey.generate())
    with pytest.raises(ProviderError, match="no such session"):
        other.gpu_status(sid)
    files.server.shutdown()


def test_wrong_model_hash_refunds(compute):
    p, entry, chain, _ = compute
    files = Files({"m.gguf": b"not the model you asked for"})
    p.credit(chain.pay(SEPOLIA, entry["payto"][SEPOLIA], 500_000))
    sid = p.gpu_start(files.url + "/m.gguf", "11" * 32, max_seconds=60)
    st = p.gpu_wait(sid, timeout=20, every=0.2)
    assert st["status"].startswith("error") and "SHA-256" in st["status"]
    assert p.balance() == "0.5"
    files.server.shutdown()


def test_many_clients_at_once_fair_and_bounded(compute):
    p, entry, chain, built = compute
    wasm = (built / "job.wasm").read_bytes()
    files = Files({"job.wasm": wasm})
    url, sha = files.url + "/job.wasm", hashlib.sha256(wasm).hexdigest()
    a, b, c = (Provider(entry, Ed25519PrivateKey.generate()) for _ in range(3))
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


def test_second_gpu_session_waits_for_the_gpu(compute):
    p, entry, chain, _ = compute
    model = os.urandom(200_000)
    files = Files({"m.gguf": model})
    sha = hashlib.sha256(model).hexdigest()
    a, b = Provider(entry, Ed25519PrivateKey.generate()), Provider(entry, Ed25519PrivateKey.generate())
    for cl in (a, b):
        cl.credit(chain.pay(SEPOLIA, entry["payto"][SEPOLIA], 1_000_000))
    s1 = a.gpu_start(files.url + "/m.gguf", sha, max_seconds=120)
    assert a.gpu_wait(s1, timeout=20, every=0.2)["status"] == "ready"
    s2 = b.gpu_start(files.url + "/m.gguf", sha, max_seconds=120)
    time.sleep(1.5)
    assert b.gpu_status(s2)["status"] == "waiting for a free GPU"
    with pytest.raises(ProviderBusy):
        a.gpu_start(files.url + "/m.gguf", sha)                  # a already has its one session
    a.gpu_end(s1)
    assert b.gpu_wait(s2, timeout=20, every=0.2)["status"] == "ready"
    assert b.gpu_chat(s2, [{"role": "user", "content": "x"}])["choices"][0]["message"]["content"] == "echo: x"
    b.gpu_end(s2)
    files.server.shutdown()


def test_idle_gpu_session_ends_by_itself(compute):
    p, entry, chain, _ = compute
    model = os.urandom(100_000)
    files = Files({"m.gguf": model})
    p.credit(chain.pay(SEPOLIA, entry["payto"][SEPOLIA], 1_000_000))
    sid = p.gpu_start(files.url + "/m.gguf", hashlib.sha256(model).hexdigest(), max_seconds=600, idle_seconds=2)
    assert p.gpu_wait(sid, timeout=20, every=0.2)["status"] == "ready"
    st = p.gpu_wait(sid, timeout=20, every=0.5)
    for _ in range(30):
        st = p.gpu_status(sid)
        if st["status"].startswith("ended"):
            break
        time.sleep(0.5)
    assert st["status"].startswith("ended")
    secs = int(st["status"].split()[2])
    assert secs < 15 and Decimal(p.balance()) == Decimal(1) - Decimal(secs) * Decimal("0.001")
    files.server.shutdown()
