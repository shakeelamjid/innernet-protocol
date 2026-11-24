"""Start exactly one research storage node inside its isolated Coolify container.

The original CLI intentionally refuses to bind to non-loopback addresses.
Here the node is isolated on a Docker Compose network, accessible only to the
public read-only Nginx gateway and other explicitly connected private services.
Do not add a public domain to this service or publish its port.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

import uvicorn

from innernet2.node import create_app, initialize_node


def bootstrap():
    directory = Path(os.getenv("INN_NODE_DATA", "/var/lib/innernet/node"))
    node_id = os.getenv("INN_NODE_ID", "node-contabo-01")
    public_url = os.environ["INN_PUBLIC_URL"].rstrip("/")
    parsed = urlsplit(public_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.path or parsed.query or parsed.fragment:
        raise ValueError("INN_PUBLIC_URL must be an HTTPS origin without path or query")
    capacity = int(os.getenv("INN_CAPACITY_BYTES", str(256 * 1024 * 1024)))
    if not (64 * 1024 * 1024 <= capacity <= 1024**4):
        raise ValueError("INN_CAPACITY_BYTES outside pilot range")
    if not directory.exists():
        initialize_node(directory, node_id, public_url, capacity_bytes=capacity)
        print("Initialized fresh persistent node identity; secrets remain in private volume", flush=True)
    else:
        config_file = directory / "config.json"
        if not config_file.is_file():
            raise RuntimeError("Node volume exists without valid config.json; refusing to replace identity")
        config = json.loads(config_file.read_text(encoding="utf-8"))
        if config["node_id"] != node_id or config["public_url"] != public_url:
            raise RuntimeError("Node identity or URL changed; inspect persistent config before proceeding")
        if not all((directory / f).is_file() for f in ("node.key", "write.token")):
            raise RuntimeError("Persistent identity files missing; refusing unsafe regeneration")
        print("Using existing persistent node identity", flush=True)
    return directory


def main():
    directory = bootstrap()
    uvicorn.run(create_app(directory), host="0.0.0.0", port=9400,
                log_level="warning", workers=1, proxy_headers=False, access_log=False)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Never print private keys, tokens or environment values.
        print(f"INNERnet startup failed: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1) from None
