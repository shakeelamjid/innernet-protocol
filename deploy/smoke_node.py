"""One-node private smoke test: writes synthetic bytes directly to internal API.

Run from the node container terminal. Never prints the write bearer token.
This does not demonstrate 4-of-6 distributed recovery or an internet transfer.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from pathlib import Path
from urllib.request import Request, urlopen


def main():
    base = Path(os.getenv("INN_NODE_DATA", "/var/lib/innernet/node"))
    token = (base / "write.token").read_text(encoding="utf-8").strip()
    payload = b"INNERnet synthetic Coolify test " + secrets.token_bytes(16)
    sha = hashlib.sha256(payload).hexdigest()
    url = "http://127.0.0.1:9400/v2/fragments/" + sha
    req = Request(url, data=payload, method="PUT", headers={"X-Innernet-Write-Token": token})
    with urlopen(req, timeout=5) as res:
        receipt = json.load(res)
    with urlopen(url, timeout=5) as res:
        recovered = res.read()
    if recovered != payload or receipt["digest"] != sha:
        raise RuntimeError("smoke test recovery mismatch")
    print(json.dumps({"status": "PASS", "fragment_sha256": sha,
                      "fragment_size": len(payload), "local_read_matches": True}, indent=2))


if __name__ == "__main__":
    main()
