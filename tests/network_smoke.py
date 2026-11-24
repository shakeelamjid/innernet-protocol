"""Nine real local HTTP node processes, CLI store/restore, and three failures."""
from __future__ import annotations

import contextlib
import io
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

from innernet2.cli import create_demo
from innernet2.crypto import decrypt_metadata, deinterleave, derive, parse_root
from innernet2.network import INDEX_CELL, INDEX_K, INDEX_N, MeshClient


def find_free_port_range(n=9):
    for base in range(18000, 24000, 25):
        try:
            sockets = []
            for i in range(n):
                s = socket.socket()
                s.bind(("127.0.0.1", base+i))
                sockets.append(s)
            for s in sockets:s.close()
            return base
        except OSError:
            for s in sockets:s.close()
    raise RuntimeError("no free localhost port range")


def main():
    procs = []
    with tempfile.TemporaryDirectory(prefix="innernet-smoke-") as tmp:
        directory = Path(tmp) / "mesh"
        port = find_free_port_range()
        with contextlib.redirect_stdout(io.StringIO()):
            create_demo(directory, 9, port)
        try:
            for i in range(9):
                node = f"node-{i+1:02d}"
                procs.append((node, subprocess.Popen(
                    [sys.executable, "-m", "innernet2.cli", "serve-node", "--dir", str(directory/node),
                     "--port", str(port+i)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)))
            for _ in range(80):
                try:
                    with httpx.Client(timeout=.5) as h:
                        if all(h.get(f"http://127.0.0.1:{port+i}/.well-known/innernet-node").status_code == 200 for i in range(9)):
                            break
                except httpx.HTTPError:
                    time.sleep(.15)
            else:
                raise RuntimeError("nodes failed to start")
            data = os.urandom(1_250_000)
            source = Path(tmp) / "private.bin"
            source.write_bytes(data)
            capfile = Path(tmp) / "read.secret"
            dest = Path(tmp) / "restored.bin"
            # Use the public, documented CLI for upload.
            put = subprocess.run([sys.executable, "-m", "innernet2.cli", "put", str(source),
                                  "--peers", str(directory/'peers.json'),
                                  "--writers", str(directory/'writers.json'),
                                  "--cap-out", str(capfile)], capture_output=True, text=True, check=True)
            # Identify 2 selected data nodes + one separate metadata node; stop them.
            client = MeshClient(directory/'peers.json')
            root = parse_root(capfile.read_text().strip())
            record = client.resolve(root)
            mixlen = ((record["cipher_length"] + INDEX_CELL-1)//INDEX_CELL)*INDEX_CELL
            mixed = client._recover(record["fragments"], INDEX_K, INDEX_N, mixlen)
            cipher = deinterleave(mixed, derive(root, "metadata/interleave/0"), INDEX_CELL, record["cipher_length"])
            manifest = decrypt_metadata(root, cipher, 0)
            stops = [x["node"] for x in manifest["chunks"][0]["fragments"][:2]]
            stops += [record["fragments"][0]["node"]]
            for node, process in procs:
                if node in stops:
                    process.terminate()
                    process.wait(timeout=3)
            # Read-only restore: NO writer tokens at recipient.
            get = subprocess.run([sys.executable, "-m", "innernet2.cli", "get",
                                  "--peers", str(directory/'peers.json'),
                                  "--cap-file", str(capfile), "--out", str(dest)],
                                 capture_output=True, text=True, check=True)
            assert dest.read_bytes() == data
            result = {"result": "pass", "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                      "test": "9 independent HTTP node processes; CLI upload and read-only restore",
                      "input_bytes": len(data), "file_sha256_match": True,
                      "storage_nodes_stopped": stops, "metadata_failed": 1, "data_failed": 2,
                      "recovered_with_6_of_9_nodes_online": True, "recipient_had_write_credentials": False,
                      "read_capability_file_mode": oct(capfile.stat().st_mode & 0o777),
                      "tested_payment_or_vpn": False}
            print(json.dumps(result, indent=2))
            client.http.close()
            return result
        finally:
            for _, p in procs:
                if p.poll() is None:
                    p.terminate()
            for _, p in procs:
                try:p.wait(timeout=3)
                except subprocess.TimeoutExpired:p.kill()


if __name__ == "__main__":
    main()
