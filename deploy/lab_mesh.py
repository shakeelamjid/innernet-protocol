"""Isolated single-VPS research mesh for INNERnet.

NINE independent node processes on ONE physical VPS. Ports are Docker-bound to
host loopback only. This provides fault-injection and remote SSH-tunnel tests;
it is NOT high availability or independent provider validation.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from innernet2.cli import create_demo

BASE = Path(os.environ.get("INN_LAB_DATA", "/var/lib/innernet-lab/mesh"))
START_PORT = 19401
NUM_NODES = 9
GROUPS = ("simulated-group-a", "simulated-group-b", "simulated-group-c")


def init_lab() -> None:
    BASE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not BASE.exists():
        create_demo(BASE, NUM_NODES, START_PORT)
        peers_path = BASE / "peers.json"
        peers = json.loads(peers_path.read_text(encoding="utf-8"))
        for index, node in enumerate(peers["nodes"]):
            node["failure_domain"] = GROUPS[index // 3]
        peers_path.write_text(json.dumps(peers, indent=2) + "\n", encoding="utf-8")
        peers_path.chmod(0o644)
        print("Initialized persistent 9-node single-VPS laboratory", flush=True)
    else:
        for name in ("peers.json", "writers.json"):
            if not (BASE / name).is_file():
                raise RuntimeError(f"Partial lab initialization; missing {name}; aborting")
        peers = json.loads((BASE / "peers.json").read_text(encoding="utf-8"))
        if len(peers.get("nodes", [])) != NUM_NODES:
            raise RuntimeError("Persistent lab node count changed; refusing to recreate")
        for index, node in enumerate(peers["nodes"]):
            expected_id = f"node-{index + 1:02d}"
            if (node.get("id") != expected_id or node.get("url") != f"http://127.0.0.1:{START_PORT + index}"
                    or node.get("failure_domain") != GROUPS[index // 3]
                    or not (BASE / expected_id / "node.key").exists()):
                raise RuntimeError("Persistent lab identity mismatch; refusing to regenerate")
        print("Reusing persistent 9-node lab identities", flush=True)


def offline_list() -> set[str]:
    path = BASE / "offline.json"
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        requested = data["offline"]
        if not isinstance(requested, list) or not all(isinstance(v, str) for v in requested):
            raise ValueError("bad offline value")
        allowed = {f"node-{i:02d}" for i in range(1, NUM_NODES + 1)}
        if not set(requested) <= allowed:
            raise ValueError("unknown lab node")
        return set(requested)
    except (json.JSONDecodeError, KeyError, ValueError) as exc:
        raise RuntimeError("Invalid offline.json: refusing unintended node changes") from exc


def main() -> None:
    init_lab()
    processes: dict[str, subprocess.Popen] = {}
    running = True

    def request_shutdown(_sig, _frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)
    try:
        while running:
            offline = offline_list()
            for i in range(1, NUM_NODES + 1):
                name = f"node-{i:02d}"
                child = processes.get(name)
                if name in offline:
                    if child is not None:
                        child.terminate()
                        try:
                            child.wait(timeout=4)
                        except subprocess.TimeoutExpired:
                            child.kill()
                            child.wait()
                        del processes[name]
                        print(f"LAB node {name}: offline (fault injection)", flush=True)
                elif child is None or child.poll() is not None:
                    processes[name] = subprocess.Popen(
                        [sys.executable, "-m", "deploy.lab_worker", "--dir", str(BASE / name),
                         "--port", str(START_PORT + i - 1)],
                        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
                    )
                    print(f"LAB node {name}: launched on :{START_PORT + i - 1}", flush=True)
            time.sleep(0.6)
    finally:
        for child in processes.values():
            child.terminate()
        for child in processes.values():
            try:
                child.wait(timeout=4)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


if __name__ == "__main__":
    main()
