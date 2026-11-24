"""Read-only deployment preflight; never prints secrets or mutates persistent storage."""
from __future__ import annotations
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit


def verify() -> None:
    public_url = os.environ.get("INN_PUBLIC_URL", "")
    parsed = urlsplit(public_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError("INN_PUBLIC_URL must be a bare HTTPS origin (no path, credentials or query)")
    node_id = os.environ.get("INN_NODE_ID", "node-contabo-01")
    import re
    if not re.fullmatch(r"node-[a-z0-9-]{1,40}", node_id):
        raise ValueError("INN_NODE_ID must match node-[a-z0-9-]{1,40}")
    base = Path(os.environ.get("INN_NODE_DATA", "/var/lib/innernet/node"))
    if base.exists():
        conf = base / "config.json"
        if not conf.is_file():
            raise RuntimeError("node storage directory exists but config.json is absent; do not erase the volume")
        cfg = json.loads(conf.read_text(encoding="utf-8"))
        if cfg.get("node_id") != node_id or cfg.get("public_url") != public_url.rstrip("/"):
            raise RuntimeError("stored node ID / public URL do not match the current environment; preserve identity and investigate")
        if any(not (base / name).is_file() for name in ("node.key", "write.token")):
            raise RuntimeError("persistent node identity is incomplete; do not regenerate it")
        print("PREFLIGHT_OK existing node identity and configuration consistent")
    else:
        if not base.parent.is_dir() or not os.access(base.parent, os.W_OK):
            raise RuntimeError("persistent storage parent is not writable by container user 10001")
        print("PREFLIGHT_OK new node can initialize under the persistent volume")


if __name__ == "__main__":
    try:
        verify()
    except Exception as exc:
        print(f"PREFLIGHT_FAILED {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
