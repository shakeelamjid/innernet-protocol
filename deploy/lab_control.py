"""Private fault-injection control for nine nodes on one physical VPS.

Use inside the lab container only. The controller does not expose HTTP APIs.
"""
from __future__ import annotations
import argparse
import json
import os
import tempfile
import time
from pathlib import Path

import httpx
from .lab_mesh import BASE, GROUPS, START_PORT, NUM_NODES


def group_nodes(name: str) -> set[str]:
    if name == "all":
        return {f"node-{i:02d}" for i in range(1, NUM_NODES + 1)}
    if name.startswith("group-"):
        try:
            group_index = "abc".index(name.removeprefix("group-"))
        except ValueError as exc:
            raise ValueError("group must be group-a, group-b, or group-c") from exc
        return {f"node-{i:02d}" for i in range(1 + group_index * 3, 4 + group_index * 3)}
    if name.startswith("node-") and name in group_nodes("all"):
        return {name}
    raise ValueError("target must be all, group-a/b/c, or node-01 ... node-09")


def set_offline(target: str, enable: bool) -> dict:
    if not (BASE / "writers.json").exists():
        raise RuntimeError("lab is not initialized")
    path = BASE / "offline.json"
    current = set()
    if path.exists():
        current = set(json.loads(path.read_text(encoding="utf-8"))["offline"])
    selected = group_nodes(target)
    if enable:
        current |= selected
    else:
        current -= selected
    fd, temp = tempfile.mkstemp(prefix=".offline-", dir=BASE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"offline": sorted(current)}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    return {"set_offline": sorted(current), "requested": target, "state": "offline" if enable else "online"}


def status() -> dict:
    offline = set()
    path = BASE / "offline.json"
    if path.exists():
        offline = set(json.loads(path.read_text(encoding="utf-8"))["offline"])
    nodes = []
    with httpx.Client(timeout=1) as client:
        for i in range(1, NUM_NODES + 1):
            name = f"node-{i:02d}"
            try:
                r = client.get(f"http://127.0.0.1:{START_PORT + i - 1}/.well-known/innernet-node")
                reachable = r.status_code == 200 and r.json().get("node_id") == name
            except (httpx.HTTPError, ValueError):
                reachable = False
            nodes.append({"id": name, "group": GROUPS[(i - 1)//3],
                          "requested_offline": name in offline, "http_reachable": reachable})
    return {"nodes": nodes, "reachable": sum(n["http_reachable"] for n in nodes),
            "caution": "All 9 lab nodes share one VPS. These groups are NOT independent failure domains."}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("operation", choices=["status", "down", "up"])
    p.add_argument("target", nargs="?", default="all")
    args = p.parse_args()
    if args.operation == "status":
        print(json.dumps(status(), indent=2))
    else:
        print(json.dumps(set_offline(args.target, args.operation == "down"), indent=2))
        print("Lab supervisor applies control changes within ~1 second.")


if __name__ == "__main__":
    main()
