"""Owner accounts: one person, many machines.

An owner is identified by the id of the first machine they set up (its provider id), so existing
data needs no migration: passkeys and web sessions already belong to that id. A machine joins an
owner when the signed-in owner enters its machine code (`machine_owner`). Machines of one owner may
share a payout contract; every machine still checks the owner's passkey itself before signing.
"""
from __future__ import annotations

import time

from .store import Store

SCHEMA = """
CREATE TABLE IF NOT EXISTS machine_owner (
  provider TEXT PRIMARY KEY, owner TEXT NOT NULL, linked_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS machine_owner_by_owner ON machine_owner(owner);
CREATE TABLE IF NOT EXISTS key_backups (     -- encrypted with the owner's passphrase, the registry cannot open them
  provider TEXT PRIMARY KEY, blob TEXT NOT NULL, stored_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tx_claims (
  network TEXT NOT NULL, tx TEXT NOT NULL, provider TEXT NOT NULL, claimed_at INTEGER NOT NULL,
  PRIMARY KEY (network, tx)
);
"""


def migrate(store: Store) -> None:
    for stmt in SCHEMA.strip().split(";"):
        if stmt.strip():
            store.x(stmt)


def owner_of(store: Store, pid: str) -> str:
    row = store.one("SELECT owner FROM machine_owner WHERE provider=?", (pid,))
    return row["owner"] if row else pid


def machines_of(store: Store, owner: str) -> list[str]:
    """Machines of an owner, oldest link first; the owner's own first machine leads."""
    linked = [r["provider"] for r in store.q("SELECT provider FROM machine_owner WHERE owner=? ORDER BY linked_at", (owner,))]
    own = [] if store.one("SELECT 1 FROM machine_owner WHERE provider=?", (owner,)) else [owner]
    known = {r["id"] for r in store.q("SELECT id FROM providers")} | {r["provider"] for r in store.q(
        "SELECT DISTINCT provider FROM claims")}
    return [m for m in own + linked if m in known or m in linked]


def link(store: Store, machine: str, owner: str) -> None:
    if machine == owner:
        store.x("DELETE FROM machine_owner WHERE provider=?", (machine,))
        return
    store.x("INSERT INTO machine_owner(provider, owner, linked_at) VALUES (?,?,?) "
            "ON CONFLICT(provider) DO UPDATE SET owner=excluded.owner, linked_at=excluded.linked_at",
            (machine, owner, int(time.time())))
    # Machines that had joined this machine's own account follow it.
    store.x("UPDATE machine_owner SET owner=? WHERE owner=?", (owner, machine))
