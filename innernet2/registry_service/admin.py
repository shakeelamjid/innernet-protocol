"""Operator commands, run inside the registry container:

  python -m innernet2.registry_service.admin keygen /data/registry_ed25519
  python -m innernet2.registry_service.admin list
  python -m innernet2.registry_service.admin approve <provider id>
  python -m innernet2.registry_service.admin suspend <provider id> "<reason>"
  python -m innernet2.registry_service.admin remove <provider id> "<reason>"
"""
from __future__ import annotations

import argparse
import os
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..native_udp import pub_bytes
from . import chain, probe
from .config import Settings
from .store import Store


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="registry-admin")
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen", help="create the registry signing key file (0600)")
    k.add_argument("path")
    sub.add_parser("list")
    for name in ("approve", "suspend", "remove"):
        s = sub.add_parser(name)
        s.add_argument("provider")
        if name != "approve":
            s.add_argument("reason")
        else:
            s.add_argument("--force", action="store_true", help="approve even if the payout check fails")
    args = ap.parse_args(argv)

    if args.cmd == "keygen":
        if os.path.exists(args.path):
            print("refusing to overwrite", args.path, file=sys.stderr)
            return 1
        key = Ed25519PrivateKey.generate()
        fd = os.open(args.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(key.private_bytes_raw().hex() + "\n")
        print("registry public key (pin this in clients):", pub_bytes(key).hex())
        return 0

    store = Store(Settings.from_env().db_path)
    if args.cmd == "list":
        now = int(time.time())
        for p in store.providers():
            ratio, n = probe.uptime(store, p["id"], since=now - 7 * 86400)
            up = "n/a" if ratio is None else f"{ratio:.1%}"
            print(f"{p['id']}  {p['state']:<9}  {p['entry']['name']:<24} {','.join(p['entry']['services']):<18} "
                  f"uptime7d={up} ({n})  {p['reason']}")
        return 0
    p = store.provider(args.provider.lower())
    if p is None:
        print("unknown provider", file=sys.stderr)
        return 1
    now = int(time.time())
    if args.cmd == "approve":
        if p["state"] == "removed":
            print("provider was removed; it must apply again under a new key", file=sys.stderr)
            return 1
        settings = Settings.from_env()
        for network, address in p["entry"]["payto"].items():
            ok, why = chain.payout_check(settings, network, address)
            if not ok and not args.force:
                print(f"refusing: {why} (use --force to override)", file=sys.stderr)
                return 1
            if why:
                print("note:", why)
        store.x("UPDATE providers SET state='listed', reason='', listed_at=COALESCE(listed_at, ?), updated_at=? WHERE id=?",
                (now, now, p["id"]))
        store.audit(p["id"], "listed", "approved by operator")
    else:
        state = "suspended" if args.cmd == "suspend" else "removed"
        store.x("UPDATE providers SET state=?, reason=?, updated_at=? WHERE id=?", (state, args.reason, now, p["id"]))
        store.audit(p["id"], state, args.reason)
    print(p["id"], "->", "listed" if args.cmd == "approve" else state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
