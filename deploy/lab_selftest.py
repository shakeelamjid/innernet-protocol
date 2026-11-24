"""Synthetic round trip and simulated site outage on the ONE-VPS lab.

Must run inside the optional lab container; never touches production node1.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path

import httpx
from innernet2.network import MeshClient
from .lab_mesh import BASE, START_PORT
from .lab_control import set_offline, status


def wait_for_nodes(*, target_count: int, timeout_sec: float = 35) -> None:
    until = time.monotonic() + timeout_sec
    while time.monotonic() < until:
        with httpx.Client(timeout=0.6) as client:
            count = 0
            for offset in range(9):
                try:
                    r = client.get(f"http://127.0.0.1:{START_PORT + offset}/.well-known/innernet-node")
                    count += int(r.status_code == 200)
                except httpx.HTTPError:
                    pass
        if count == target_count:
            return
        time.sleep(0.4)
    raise RuntimeError(f"only {count} nodes reachable, expected {target_count}")


def main():
    registry = BASE / "peers.json"
    writers = BASE / "writers.json"
    if not registry.exists() or not writers.exists():
        raise RuntimeError("Lab mesh isn't initialized")
    # Restore full lab before test; avoids stale offline flags from interrupted runs.
    set_offline("all", False)
    wait_for_nodes(target_count=9)
    outage_verified = False
    result = None
    try:
        with tempfile.TemporaryDirectory(prefix="inn-lab-trial-") as tmp:
            folder = Path(tmp)
            plain = os.urandom(180_000)
            source = folder / "source.bin"
            source.write_bytes(plain)
            publisher = MeshClient(registry, writers)
            try:
                result = publisher.upload_file(source, k=4, n=6, chunk_bytes=65536,
                                               survive_one_domain=True)
            finally:
                publisher.http.close()
            secret = result.pop("capability")
            # Reader intentionally has NO write credentials.
            reader = MeshClient(registry)
            try:
                restored = folder / "restored.bin"
                reader.restore_file(secret, restored)
                if restored.read_bytes() != plain:
                    raise AssertionError("ordinary recovery differs from input")
                # All 3 simulated-group-a nodes down at once: 2 data + 1 metadata lost.
                set_offline("group-a", True)
                wait_for_nodes(target_count=6)
                after_failure = folder / "after-outage.bin"
                reader.restore_file(secret, after_failure)
                if after_failure.read_bytes() != plain:
                    raise AssertionError("outage recovery differs from input")
                outage_verified = True
            finally:
                reader.http.close()
    finally:
        set_offline("all", False)
        wait_for_nodes(target_count=9)
    print(json.dumps({
        "result": "PASS" if outage_verified else "FAIL",
        "test": "9 HTTP node processes on ONE VPS; 3 simulated nodes down",
        "original_bytes": len(plain),
        "sha256": hashlib.sha256(plain).hexdigest(),
        "ordinary_recovery": True,
        "group_a_three_nodes_down_recovery": outage_verified,
        "read_client_had_upload_tokens": False,
        "data_shards": result["data_shards"],
        "metadata_shards": result["metadata_shards"],
        "nodes_recovered_to_online": 9,
        "limitations": "All nodes share one VPS, disk and network; not independent hosting or audited security."
    }, indent=2))


if __name__ == "__main__":
    main()
