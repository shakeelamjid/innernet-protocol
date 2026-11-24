"""Reproducible localhost *process* benchmark (no external servers).

python benchmarks/benchmark_mesh_io.py --bytes 180000,1048576

Measures CPU + localhost HTTP and a signed 9-node mesh. NOT internet speed,
not equivalent storage durability, and not a cryptographic security test.
"""
from __future__ import annotations

import argparse
import hashlib
import contextlib
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from innernet2.cli import create_demo
from innernet2.network import MeshClient, MAX_CHUNK


def free_base() -> int:
    for base in range(40000, 58000, 19):
        sockets = []
        try:
            for offset in range(9):
                sock = socket.socket()
                sock.bind(("127.0.0.1", base + offset))
                sockets.append(sock)
            return base
        except OSError:
            continue
        finally:
            for sock in sockets:
                sock.close()
    raise RuntimeError("cannot allocate 9 localhost ports")


def run(sizes: list[int], workers: list[int], chunk_bytes: int = MAX_CHUNK) -> dict:
    with tempfile.TemporaryDirectory(prefix="innernet-v033-bench-") as temporary:
        base = Path(temporary)
        nodes = base / "mesh"
        port = free_base()
        with contextlib.redirect_stdout(io.StringIO()):
            create_demo(nodes, 9, port)
        processes = []
        try:
            for i in range(9):
                proc = subprocess.Popen([sys.executable, "-m", "innernet2.cli", "serve-node",
                                         "--dir", str(nodes / f"node-{i+1:02d}"),
                                         "--port", str(port + i)],
                                        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                processes.append(proc)
            with httpx.Client(timeout=1.0, trust_env=False) as check:
                for _ in range(100):
                    try:
                        if all(check.get(f"http://127.0.0.1:{port + i}/.well-known/innernet-node").status_code == 200
                               for i in range(9)):
                            break
                    except httpx.HTTPError:
                        pass
                    time.sleep(.1)
                else:
                    raise RuntimeError("lab nodes failed to start")
            rows = []
            for size in sizes:
                source = base / f"input-{size}.bin"
                original = os.urandom(size)
                source.write_bytes(original)
                expected_hash = hashlib.sha256(original).hexdigest()
                for count in workers:
                    with httpx.Client(timeout=12.0, trust_env=False, follow_redirects=False) as http:
                        publisher = MeshClient(nodes / "peers.json", nodes / "writers.json",
                                               http=http, max_workers=count)
                        t0 = time.monotonic()
                        saved = publisher.upload_file(source, k=4, n=6, chunk_bytes=chunk_bytes)
                        t1 = time.monotonic()
                        reader = MeshClient(nodes / "peers.json", http=http, max_workers=count)
                        target = base / f"restored-{size}-{count}.bin"
                        reader.restore_file(saved["capability"], target)
                        t2 = time.monotonic()
                        assert hashlib.sha256(target.read_bytes()).hexdigest() == expected_hash
                    up = round(1000*(t1-t0))
                    down = round(1000*(t2-t1))
                    rows.append({"bytes":size, "workers":count,
                                 "chunk_bytes": chunk_bytes, "upload_ms":up,
                                 "recovery_ms":down,
                                 "upload_mib_s":round(size / 1048576 / max(t1-t0, .001), 3),
                                 "read_mib_s":round(size / 1048576 / max(t2-t1, .001), 3),
                                 "sha256_verified":True})
            return {"benchmark":"single-host 9-process localhost HTTP",
                    "warning":"NOT a Mac-to-Contabo speed or independent fault-domain benchmark",
                    "trials":rows}
        finally:
            for p in processes:
                p.terminate()
            for p in processes:
                try:
                    p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bytes", default="180000,1048576")
    parser.add_argument("--workers", default="1,6")
    parser.add_argument("--chunk-bytes", type=int, default=MAX_CHUNK)
    args = parser.parse_args()
    sizes = [int(v) for v in args.bytes.split(",")]
    workers = [int(v) for v in args.workers.split(",")]
    if not sizes or any(not 1 <= n <= 100_000_000 for n in sizes) or not workers or any(w not in range(1, 10) for w in workers):
        parser.error("sizes 1..100MB, workers 1..9")
    if not 4096 <= args.chunk_bytes <= MAX_CHUNK or args.chunk_bytes % 4096:
        parser.error("--chunk-bytes must be a 4096-byte multiple, <=1048576")
    print(json.dumps(run(sizes, workers, args.chunk_bytes), indent=2))
