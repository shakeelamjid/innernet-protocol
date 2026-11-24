"""v0.6.0-alpha experimental SQLite message journal and local sender outbox.

A SQLite commit confirms persistence into a local database, NOT independent
replication, guaranteed hardware fsync, end-user delivery or production security.
Strict mode requires IE60 ciphertext. Legacy mode and old DBs remain plaintext; synthetic data only.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import secrets
import sqlite3
import threading
import time

MAX_BODY = 960
MAX_TTL = 86400
MIN_TTL = 60
MAX_ROWS = 2000


class MailboxError(ValueError):
    pass


def _safe_path(path: str | Path) -> Path:
    p = Path(path).expanduser().absolute()
    if p.is_symlink() or (p.exists() and not p.is_file()):
        raise MailboxError("database path must be a regular non-symlink file")
    if p.parent.is_symlink():
        raise MailboxError("database parent cannot be a symlink")
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Owner-only DB directory is required for prototype plaintext synthetic data.
    if p.parent.stat().st_mode & 0o077:
        raise MailboxError("database parent directory must have permissions 0700")
    if p.exists() and p.stat().st_mode & 0o077:
        raise MailboxError("database file must have permissions 0600")
    return p


def _open(path: str | Path) -> sqlite3.Connection:
    p = _safe_path(path)
    fd = os.open(p, os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    os.fchmod(fd, 0o600)
    os.close(fd)
    db = sqlite3.connect(str(p), timeout=5, isolation_level=None, check_same_thread=False)
    # SQLite WAL/SHM files inherit process umask; the owner-only parent
    # prevents other users from traversing to these files.
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("PRAGMA busy_timeout=5000")
    return db


class MailboxStore:
    """Single-node durable-ish journal; idempotency lasts until explicit pruning."""

    def __init__(self, path: str | Path, *, max_rows: int = MAX_ROWS,
                 require_e2ee: bool = False):
        if not 1 <= max_rows <= 100000:
            raise MailboxError("invalid mailbox capacity")
        self.db = _open(path)
        self.lock = threading.RLock()
        self.max_rows = max_rows
        self.require_e2ee = require_e2ee
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS messages (
                sender BLOB NOT NULL, recipient BLOB NOT NULL,
                message_id BLOB NOT NULL, payload BLOB NOT NULL,
                digest BLOB NOT NULL, created REAL NOT NULL,
                expires REAL NOT NULL, consumed REAL,
                PRIMARY KEY(sender, message_id)
            );
            CREATE INDEX IF NOT EXISTS inbox_lookup
                ON messages(recipient, consumed, created);
            CREATE TABLE IF NOT EXISTS udp_hello_replay (
                digest BLOB PRIMARY KEY, expires REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS cursor_history (
                recipient BLOB NOT NULL, sender BLOB NOT NULL,
                message_id BLOB NOT NULL, created REAL NOT NULL,
                original_rowid INTEGER NOT NULL, expires REAL NOT NULL,
                PRIMARY KEY(recipient,sender,message_id)
            );
            CREATE INDEX IF NOT EXISTS cursor_history_cleanup
                ON cursor_history(expires,created);
        """)

    def mark_udp_hello(self, digest: bytes, *, now: float | None = None) -> bool:
        """Atomically accept one hello hash across mailbox server restarts.

        A bounded retention window still cannot establish cryptographic freshness
        for timeless IN40 messages; that requires a versioned timestamped wire.
        """
        if not isinstance(digest, bytes) or len(digest) != 32:
            raise MailboxError("invalid UDP hello digest")
        instant = time.time() if now is None else now
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self.db.execute("SELECT expires FROM udp_hello_replay WHERE digest=?",
                                      (digest,)).fetchone()
                if row is not None and row[0] > instant:
                    self.db.execute("COMMIT")
                    return False
                self.db.execute("DELETE FROM udp_hello_replay WHERE expires<=?",(instant,))
                self.db.execute("INSERT OR REPLACE INTO udp_hello_replay VALUES (?,?)",
                                (digest,instant+3600))
                self.db.execute("COMMIT")
                return True
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def close(self) -> None:
        with self.lock:
            self.db.close()

    def store(self, sender: bytes, recipient: bytes, message_id: bytes, payload: bytes,
              ttl: int = 3600, *, now: float | None = None) -> tuple[str, bytes]:
        if (len(sender) != 32 or len(recipient) != 32 or len(message_id) != 16
                or not 1 <= len(payload) <= MAX_BODY or not MIN_TTL <= ttl <= MAX_TTL):
            raise MailboxError("invalid message parameters")
        instant = time.time() if now is None else now
        if self.require_e2ee:
            # Additive strict mode. Preserve legacy IN50 plaintext behavior when
            # explicitly using the old mailbox configuration.
            from .mailbox_e2ee import inspect_envelope
            try:
                inspect_envelope(payload, sender=sender, recipient=recipient,
                                 message_id=message_id, ttl=ttl, now=int(instant))
            except ValueError as exc:
                raise MailboxError("server requires authenticated IE60 ciphertext") from exc
        digest = hashlib.sha256(payload).digest()
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                existing = self.db.execute(
                    "SELECT recipient,digest FROM messages WHERE sender=? AND message_id=?",
                    (sender, message_id)).fetchone()
                if existing is not None:
                    if existing != (recipient, digest):
                        raise MailboxError("message ID was already used for different content or recipient")
                    outcome = "DUPLICATE"
                else:
                    # Persist stable cursor positions before removing expired messages.
                    # Tombstones are recipient-scoped; pruning is independent of payload TTL.
                    self.db.execute("INSERT OR IGNORE INTO cursor_history "
                        "SELECT recipient,sender,message_id,created,rowid,? FROM messages WHERE expires<=?",
                        (instant+7*86400,instant))
                    self.db.execute("DELETE FROM messages WHERE expires<=?",(instant,))
                    self.db.execute("DELETE FROM cursor_history WHERE expires<=?",(instant,))
                    # Tombstones preserve cursors after expiry, but may not
                    # grow without bound under a sustained churn attack.
                    keep=max(32,4*self.max_rows)
                    self.db.execute(
                        "DELETE FROM cursor_history WHERE rowid IN "
                        "(SELECT rowid FROM cursor_history ORDER BY created,rowid "
                        "LIMIT MAX(0,(SELECT COUNT(*) FROM cursor_history)-?))",
                        (keep,))
                    current = self.db.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
                    sender_count = self.db.execute("SELECT COUNT(*) FROM messages WHERE sender=?",(sender,)).fetchone()[0]
                    # Keep one allowlisted peer from exhausting all global slots.
                    if sender_count >= max(1,(self.max_rows*4+4)//5):
                        raise MailboxError("sender mailbox quota reached")
                    # Delivery quota is for pending, unexpired messages. ACKed
                    # rows remain as idempotency receipts, not inbox backlog.
                    recipient_count = self.db.execute(
                        "SELECT COUNT(*) FROM messages WHERE recipient=? "
                        "AND consumed IS NULL AND expires>?",
                        (recipient,instant)).fetchone()[0]
                    recipient_cap = max(1,(self.max_rows*4+4)//5)
                    # Fairness across different senders to the same recipient.
                    # Very small test stores retain at least one slot for others.
                    pair_count = self.db.execute(
                        "SELECT COUNT(*) FROM messages WHERE sender=? AND recipient=? "
                        "AND consumed IS NULL AND expires>?",(sender,recipient,instant)).fetchone()[0]
                    if pair_count >= max(1, recipient_cap // 4):
                        raise MailboxError("sender-recipient pending quota reached")
                    if recipient_count >= recipient_cap:
                        raise MailboxError("recipient mailbox quota reached")
                    if current >= self.max_rows:
                        raise MailboxError("mailbox storage capacity reached")
                    self.db.execute(
                        "INSERT INTO messages VALUES (?,?,?,?,?,?,?,NULL)",
                        (sender, recipient, message_id, payload, digest, instant, instant + ttl))
                    outcome = "STORED"
                self.db.execute("COMMIT")
                return outcome, digest
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def fetch(self, recipient: bytes, *, now: float | None = None,
              after: tuple[bytes, bytes] | None = None) -> tuple[bytes, bytes, bytes] | None:
        if len(recipient) != 32:
            raise MailboxError("invalid recipient identity")
        instant = time.time() if now is None else now
        with self.lock:
            cursor_clause = ""
            params = [recipient, instant]
            if after is not None:
                if len(after) != 2 or len(after[0]) != 32 or len(after[1]) != 16:
                    raise MailboxError("invalid mailbox cursor")
                point = self.db.execute(
                    "SELECT created,rowid FROM messages WHERE recipient=? AND sender=? AND message_id=?",
                    (recipient,*after)).fetchone()
                if point is None:
                    point = self.db.execute(
                        "SELECT created,original_rowid FROM cursor_history "
                        "WHERE recipient=? AND sender=? AND message_id=? AND expires>?",
                        (recipient,*after,instant)).fetchone()
                if point is None:
                    raise MailboxError("unknown mailbox cursor")
                cursor_clause = "AND (created>? OR (created=? AND rowid>?)) "
                params.extend((point[0],point[0],point[1]))
            row = self.db.execute(
                "SELECT sender,message_id,payload FROM messages "
                "WHERE recipient=? AND consumed IS NULL AND expires>? " + cursor_clause +
                "ORDER BY created,rowid LIMIT 1", params).fetchone()
            return tuple(row) if row is not None else None

    def consume(self, recipient: bytes, sender: bytes, message_id: bytes, *,
                now: float | None = None) -> bool:
        if len(recipient) != 32 or len(sender) != 32 or len(message_id) != 16:
            raise MailboxError("invalid consumption key")
        instant = time.time() if now is None else now
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self.db.execute(
                    "SELECT recipient,consumed,expires FROM messages WHERE sender=? AND message_id=?",
                    (sender, message_id)).fetchone()
                ok = bool(row and row[0] == recipient and row[2] > instant and
                          (row[1] is None or row[1] >= 0))
                if ok and row[1] is None:
                    self.db.execute(
                        "UPDATE messages SET consumed=? WHERE sender=? AND message_id=?",
                        (instant, sender, message_id))
                self.db.execute("COMMIT")
                return ok
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def reject(self, recipient: bytes, sender: bytes, message_id: bytes, *,
               now: float | None = None) -> bool:
        """Recipient-authenticated discard. Negative consumed time means REJECTED.

        A rejected row remains for idempotency, but is no longer pending inbox mail.
        An unrelated identity cannot reject another recipient's message.
        """
        if len(recipient) != 32 or len(sender) != 32 or len(message_id) != 16:
            raise MailboxError("invalid rejection key")
        instant = time.time() if now is None else now
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self.db.execute(
                    "SELECT recipient,consumed,expires FROM messages WHERE sender=? AND message_id=?",
                    (sender,message_id)).fetchone()
                ok = bool(row and row[0] == recipient and row[2] > instant and
                          (row[1] is None or row[1] < 0))
                if ok and row[1] is None:
                    self.db.execute("UPDATE messages SET consumed=? WHERE sender=? AND message_id=?",
                                    (-instant,sender,message_id))
                self.db.execute("COMMIT")
                return ok
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def status(self, sender: bytes, message_id: bytes, *, now: float | None = None) -> str:
        if len(sender) != 32 or len(message_id) != 16:
            raise MailboxError("invalid status key")
        instant = time.time() if now is None else now
        with self.lock:
            row = self.db.execute(
                "SELECT expires,consumed FROM messages WHERE sender=? AND message_id=?",
                (sender, message_id)).fetchone()
            if row is None:
                return "UNKNOWN"
            if row[1] is not None:
                return "REJECTED" if row[1] < 0 else "CONSUMED"
            if row[0] <= instant:
                return "EXPIRED"
            return "STORED"

    def prune(self, *, now: float | None = None, retain_seconds: int = 86400) -> int:
        # Pruning removes idempotency history: old IDs must not be reused.
        instant = time.time() if now is None else now
        with self.lock:
            result = self.db.execute("DELETE FROM messages WHERE expires < ?",
                                     (instant - retain_seconds,))
            return result.rowcount


class OutboxStore:
    """Local resumable queue; secure CLI stores ciphertext, legacy CLI stores plaintext."""

    def __init__(self, path: str | Path):
        self.db = _open(path)
        self.lock = threading.RLock()
        self.db.execute("""CREATE TABLE IF NOT EXISTS pending(
            message_id BLOB PRIMARY KEY, recipient BLOB NOT NULL,
            payload BLOB NOT NULL, ttl INTEGER NOT NULL,
            created REAL NOT NULL, status TEXT NOT NULL DEFAULT 'QUEUED'
        )""")

    def enqueue(self, recipient: bytes, payload: bytes, ttl: int = 3600,
                message_id: bytes | None = None) -> bytes:
        if len(recipient) != 32 or not 1 <= len(payload) <= MAX_BODY or not MIN_TTL <= ttl <= MAX_TTL:
            raise MailboxError("invalid queued message")
        msg_id = secrets.token_bytes(16) if message_id is None else message_id
        if len(msg_id) != 16:
            raise MailboxError("invalid message ID")
        with self.lock:
            self.db.execute("INSERT INTO pending VALUES (?,?,?,?,?,?)",
                            (msg_id, recipient, payload, ttl, time.time(), "QUEUED"))
        return msg_id

    def queued(self, *, limit: int = 100) -> list[tuple[bytes, bytes, bytes, int]]:
        if not 1 <= limit <= 100:
            raise MailboxError("invalid outbox fetch limit")
        with self.lock:
            # Do not resend messages whose local outbox lifetime has expired.
            # TTL in the remote protocol is at least 60 s; entries with less
            # than that remaining cannot safely be forwarded.
            now = time.time()
            self.db.execute("UPDATE pending SET status='EXPIRED' WHERE "
                            "status='QUEUED' AND created + ttl < ?", (now + MIN_TTL - 0.5,))
            return self.db.execute(
                "SELECT message_id,recipient,payload,CAST(created+ttl-?+0.999 AS INTEGER) "
                "FROM pending WHERE status='QUEUED' ORDER BY created LIMIT ?",
                (now, limit)).fetchall()

    def mark_stored(self, message_id: bytes) -> None:
        with self.lock:
            self.db.execute("UPDATE pending SET status='STORED' WHERE message_id=?",
                            (message_id,))

    def status(self, message_id: bytes) -> str | None:
        with self.lock:
            row = self.db.execute("SELECT status FROM pending WHERE message_id=?", (message_id,)).fetchone()
        return row[0] if row else None

    def close(self) -> None:
        with self.lock:
            self.db.close()
