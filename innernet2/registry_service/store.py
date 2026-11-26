"""SQLite storage. One connection guarded by a lock; WAL for concurrent reads."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS providers (
  id TEXT PRIMARY KEY,
  record TEXT NOT NULL,            -- signed descriptor {payload, signature}
  state TEXT NOT NULL,             -- testing | listed | paused | leaving | suspended | gone | removed
  reason TEXT NOT NULL DEFAULT '',
  applied_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  listed_at INTEGER,
  checked_at INTEGER
);
CREATE TABLE IF NOT EXISTS probes (
  provider TEXT NOT NULL, ts INTEGER NOT NULL, ok INTEGER NOT NULL, latency_ms INTEGER
);
CREATE INDEX IF NOT EXISTS probes_by_provider ON probes(provider, ts);
CREATE TABLE IF NOT EXISTS login_challenges (
  challenge TEXT PRIMARY KEY, provider TEXT NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS enroll_tokens (
  token_hash TEXT PRIMARY KEY, provider TEXT NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS webauthn_flows (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, provider TEXT, challenge BLOB NOT NULL,
  token_hash TEXT, expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS passkeys (
  cred_id TEXT PRIMARY KEY, provider TEXT NOT NULL, public_key BLOB NOT NULL, sign_count INTEGER NOT NULL,
  name TEXT NOT NULL, created_at INTEGER NOT NULL, last_used INTEGER
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, id TEXT NOT NULL UNIQUE, provider TEXT NOT NULL, created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, ip TEXT, user_agent TEXT, revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, provider TEXT NOT NULL, ts INTEGER NOT NULL, event TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '', ip TEXT
);
CREATE INDEX IF NOT EXISTS audit_by_provider ON audit(provider, ts);
CREATE TABLE IF NOT EXISTS payments (
  network TEXT NOT NULL, tx_hash TEXT NOT NULL, log_index INTEGER NOT NULL, provider TEXT NOT NULL,
  payto TEXT NOT NULL, payer TEXT NOT NULL, amount INTEGER NOT NULL, block INTEGER NOT NULL, ts INTEGER NOT NULL,
  PRIMARY KEY (network, tx_hash, log_index)
);
CREATE INDEX IF NOT EXISTS payments_by_provider ON payments(provider, ts);
CREATE TABLE IF NOT EXISTS chain_cursor (
  network TEXT NOT NULL, payto TEXT NOT NULL, next_block INTEGER NOT NULL, PRIMARY KEY (network, payto)
);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pairing (           -- the machine code: permanent until the machine rekeys
  provider TEXT PRIMARY KEY, code_hash TEXT NOT NULL UNIQUE, set_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS claims (
  code_hash TEXT PRIMARY KEY, poll_hash TEXT NOT NULL UNIQUE, provider TEXT NOT NULL, detected TEXT NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  status TEXT NOT NULL,            -- waiting | claimed | submitted | done
  draft TEXT, claimed_at INTEGER, submitted_at INTEGER
);
CREATE INDEX IF NOT EXISTS claims_by_provider ON claims(provider, created_at);
"""


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Store:
    def __init__(self, path: str):
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), mode=0o700, exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.executescript(SCHEMA)
        from . import presence          # tables and columns added after the first release
        presence.migrate(self)
        from . import owners
        owners.migrate(self)

    @contextmanager
    def tx(self):
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            self._db.execute("COMMIT")

    def q(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    def one(self, sql: str, args: tuple = ()):
        rows = self.q(sql, args)
        return rows[0] if rows else None

    def x(self, sql: str, args: tuple = ()) -> int:
        with self._lock:
            return self._db.execute(sql, args).rowcount

    # ---- providers -----------------------------------------------------
    def provider(self, pid: str):
        row = self.one("SELECT * FROM providers WHERE id=?", (pid,))
        if row is None:
            return None
        d = dict(row)
        d["record"] = json.loads(d["record"])
        d["entry"] = d["record"]["payload"]["provider"]
        return d

    def providers(self, state: str | None = None) -> list[dict]:
        rows = self.q("SELECT id FROM providers" + (" WHERE state=?" if state else "") + " ORDER BY id",
                      (state,) if state else ())
        return [self.provider(r["id"]) for r in rows]

    def audit(self, provider: str, event: str, detail: str = "", ip: str | None = None) -> None:
        self.x("INSERT INTO audit(provider, ts, event, detail, ip) VALUES (?,?,?,?,?)",
               (provider, int(time.time()), event, detail[:500], ip))

    def meta(self, key: str, default: str | None = None) -> str | None:
        row = self.one("SELECT v FROM meta WHERE k=?", (key,))
        return row["v"] if row else default

    def set_meta(self, key: str, value: str) -> None:
        self.x("INSERT INTO meta(k, v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (key, value))
