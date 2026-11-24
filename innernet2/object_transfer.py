"""IO70 experimental recipient-encrypted object transfer over the IE60 mailbox.

Transfer is bounded (<= 1 MiB), durable at the sender and recipient application,
with independent authenticated, deduplicated chunk receipts. SYNTHETIC data only.
This is not a bulk streaming transport, public API, or independently audited crypto.
"""
from __future__ import annotations

import hashlib
import math
import os
from pathlib import Path
import secrets
import sqlite3
import struct
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .mailbox_e2ee import MAX_TEXT, open_message, seal_message, verify_bundle, inspect_envelope
from .mailbox_store import _open, MAX_TTL, MIN_TTL, OutboxStore
from .mailbox_batch import BatchMailboxClient
from .mailbox_wire import request, store_request
from .native_udp import pub_bytes, NativeTransitError

MAGIC = b"SYNTHETIC:IO70\x01"
# magic + 16-byte transfer id, 4-byte part index, 4-byte number of parts,
# 4-byte total length, 32-byte object checksum (all covered by IE60 signature).
HEADER = struct.Struct(">16sIII32s")
CHUNK_SIZE = MAX_TEXT - len(MAGIC) - HEADER.size
MAX_OBJECT_BYTES = 1_048_576
MAX_CHUNKS = math.ceil(MAX_OBJECT_BYTES / CHUNK_SIZE)
STORE_TTL_SAFETY_SECONDS = 10


class ObjectTransferError(ValueError):
    """An invalid or incomplete authenticated IO70 transfer."""


def chunk_message_id(transfer_id: bytes, index: int) -> bytes:
    if len(transfer_id) != 16 or not 0 <= index < MAX_CHUNKS:
        raise ObjectTransferError("invalid transfer ID / chunk index")
    return hashlib.sha256(b"INNERnet/IO70/chunk-id\x00" + transfer_id + struct.pack(">I", index)).digest()[:16]


def _chunks(data: bytes, transfer_id: bytes):
    if not isinstance(data, bytes) or not data.startswith(b"SYNTHETIC:") or not 1 <= len(data) <= MAX_OBJECT_BYTES:
        raise ObjectTransferError("only 1-byte to 1-MiB SYNTHETIC: objects are supported")
    if len(transfer_id) != 16:
        raise ObjectTransferError("transfer ID must be 16 bytes")
    digest = hashlib.sha256(data).digest()
    count = math.ceil(len(data) / CHUNK_SIZE)
    for index in range(count):
        payload = data[index * CHUNK_SIZE:(index + 1) * CHUNK_SIZE]
        frame = MAGIC + HEADER.pack(transfer_id, index, count, len(data), digest) + payload
        if len(frame) > MAX_TEXT:
            raise AssertionError("invalid chunk sizing")
        yield index, frame


def decode_chunk(frame: bytes) -> dict:
    if not isinstance(frame, bytes) or not frame.startswith(MAGIC) or not len(MAGIC) + HEADER.size < len(frame) <= MAX_TEXT:
        raise ObjectTransferError("invalid IO70 frame")
    transfer_id, index, total, size, digest = HEADER.unpack_from(frame, len(MAGIC))
    data = frame[len(MAGIC) + HEADER.size:]
    if (not 1 <= size <= MAX_OBJECT_BYTES or not 1 <= total <= MAX_CHUNKS
            or total != math.ceil(size / CHUNK_SIZE) or not 0 <= index < total):
        raise ObjectTransferError("invalid IO70 manifest metadata")
    expected = min(CHUNK_SIZE, size - index * CHUNK_SIZE)
    if len(data) != expected:
        raise ObjectTransferError("IO70 chunk size mismatch")
    return {"transfer_id": transfer_id, "index": index, "total": total,
            "size": size, "digest": digest, "data": data}


def queue_object(sender: Ed25519PrivateKey, bundle: dict, outbox: OutboxStore,
                 plaintext: bytes, *, expected_recipient: bytes, ttl: int = 3600, transfer_id: bytes | None = None) -> dict:
    """Seal each chunk individually; local SQLite outbox stores ciphertext only."""
    transfer_id = secrets.token_bytes(16) if transfer_id is None else transfer_id
    if not isinstance(expected_recipient, bytes) or len(expected_recipient) != 32:
        raise ObjectTransferError("independently pinned recipient key required")
    recipient = expected_recipient
    verify_bundle(bundle, recipient)
    if not MIN_TTL <= ttl <= MAX_TTL:
        raise ObjectTransferError("invalid object TTL")
    count = 0
    for index, clear in _chunks(plaintext, transfer_id):
        mid = chunk_message_id(transfer_id, index)
        envelope = seal_message(sender, bundle, mid, clear, ttl=ttl,
                                expected_recipient=recipient)
        outbox.enqueue(recipient, envelope, ttl=ttl, message_id=mid)
        count += 1
    return {"status": "QUEUED", "transfer_id": transfer_id.hex(),
            "chunks": count, "bytes": len(plaintext), "sha256": hashlib.sha256(plaintext).hexdigest(),
            "outbox": "recipient-encrypted IE60 envelopes"}


def _fresh_commit_ttl(envelope: bytes, sender_identity: bytes, recipient: bytes,
                      message_id: bytes, outbox_ttl: int, *, now: int | None = None) -> int:
    """Recompute signed envelope retention immediately before each WAN STORE."""
    instant = int(time.time()) if now is None else now
    record = inspect_envelope(envelope, sender=sender_identity, recipient=recipient,
                              message_id=message_id, now=instant)
    ttl = min(outbox_ttl, record["expires_at"] - instant - STORE_TTL_SAFETY_SECONDS)
    if ttl < MIN_TTL:
        raise ObjectTransferError("IO70 envelope has insufficient remaining signed lifetime for safe STORE; re-seal a fresh synthetic object")
    return ttl


def flush_object_outbox(outbox: OutboxStore, sender: Ed25519PrivateKey, host: str,
                        port: int, server_key: bytes, *, timeout: float = .5,
                        max_messages: int | None = None) -> dict:
    """Sequential authenticated commit receipts; resume from SQLite after an interruption."""
    if max_messages is not None and not 1 <= max_messages <= MAX_CHUNKS:
        raise ObjectTransferError("invalid maximum messages")
    sent = 0
    sender_identity = pub_bytes(sender)
    with BatchMailboxClient(host, port, sender, server_key, timeout=timeout) as link:
        while max_messages is None or sent < max_messages:
            pending = outbox.queued(limit=min(100, (max_messages - sent) if max_messages is not None else 100))
            if not pending:
                break
            for mid, recipient, envelope, ttl in pending:
                code, content = link.call(store_request(recipient, mid, envelope, _fresh_commit_ttl(envelope, sender_identity, recipient, mid, ttl)))
                if (code != "D" or len(content) != 49 or content[:16] != mid
                        or content[16:48] != hashlib.sha256(envelope).digest()
                        or content[48:] not in (b"N", b"I")):
                    raise NativeTransitError(f"server did not confirm matching SQLite commit: code={code!r} len={len(content)} tail={content[-50:]!r} sent={sent}")
                outbox.mark_stored(mid)
                sent += 1
        metrics = link.metrics()
    return {"status": "PASS", "committed_chunks": sent, **metrics,
            "meaning": "authenticated SQLite commit, not recipient consumption"}


class ObjectInbox:
    """Recipient-local persistent, deduplicated plaintext reconstruction checkpoint.

    This database must be on the recipient's own protected device; never on a relay.
    """

    def __init__(self, path: Path | str):
        self.db = _open(path)
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS objects (
          sender BLOB NOT NULL, recipient BLOB NOT NULL, transfer_id BLOB NOT NULL,
          total INTEGER NOT NULL, size INTEGER NOT NULL, digest BLOB NOT NULL,
          created REAL NOT NULL,
          PRIMARY KEY(sender, recipient, transfer_id)
        );
        CREATE TABLE IF NOT EXISTS chunks (
          sender BLOB NOT NULL, recipient BLOB NOT NULL, transfer_id BLOB NOT NULL,
          idx INTEGER NOT NULL, data BLOB NOT NULL,
          PRIMARY KEY(sender, recipient, transfer_id, idx),
          FOREIGN KEY(sender, recipient, transfer_id)
            REFERENCES objects(sender, recipient, transfer_id)
        );
        """)

    def close(self):
        self.db.close()

    def ingest(self, sender: bytes, recipient: bytes, message_id: bytes, clear: bytes) -> dict:
        item = decode_chunk(clear)
        if len(sender) != 32 or len(recipient) != 32 or message_id != chunk_message_id(item["transfer_id"], item["index"]):
            raise ObjectTransferError("message ID or identity does not match IO70 chunk")
        key = (sender, recipient, item["transfer_id"])
        self.db.execute("BEGIN IMMEDIATE")
        try:
            prior = self.db.execute(
                "SELECT total,size,digest FROM objects WHERE sender=? AND recipient=? AND transfer_id=?", key).fetchone()
            meta = (item["total"], item["size"], item["digest"])
            if prior is None:
                self.db.execute("INSERT INTO objects VALUES (?,?,?,?,?,?,?)",
                                (*key, *meta, time.time()))
            elif prior != meta:
                raise ObjectTransferError("transfer metadata changed across chunks")
            prior_chunk = self.db.execute(
                "SELECT data FROM chunks WHERE sender=? AND recipient=? AND transfer_id=? AND idx=?",
                (*key, item["index"])).fetchone()
            if prior_chunk is not None and prior_chunk[0] != item["data"]:
                raise ObjectTransferError("conflicting duplicate chunk")
            if prior_chunk is None:
                self.db.execute("INSERT INTO chunks VALUES (?,?,?,?,?)", (*key, item["index"], item["data"]))
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        return {"transfer_id": item["transfer_id"].hex(), "chunk_index": item["index"],
                "duplicate": prior_chunk is not None}

    def progress(self, sender: bytes, recipient: bytes, transfer_id: bytes) -> dict:
        if len(sender) != 32 or len(recipient) != 32 or len(transfer_id) != 16:
            raise ObjectTransferError("invalid transfer lookup")
        key = (sender, recipient, transfer_id)
        row = self.db.execute(
            "SELECT total,size,digest FROM objects WHERE sender=? AND recipient=? AND transfer_id=?", key).fetchone()
        if row is None:
            return {"status": "UNKNOWN", "received": 0}
        total, size, digest = row
        count = self.db.execute(
            "SELECT COUNT(*) FROM chunks WHERE sender=? AND recipient=? AND transfer_id=?", key).fetchone()[0]
        return {"status": "COMPLETE" if count == total else "INCOMPLETE",
                "received": count, "chunks": total, "bytes": size, "sha256": digest.hex()}

    def assemble(self, sender: bytes, recipient: bytes, transfer_id: bytes) -> bytes:
        state = self.progress(sender, recipient, transfer_id)
        if state["status"] != "COMPLETE":
            raise ObjectTransferError("not all chunks have been received")
        rows = self.db.execute(
            "SELECT idx,data FROM chunks WHERE sender=? AND recipient=? AND transfer_id=? ORDER BY idx",
            (sender, recipient, transfer_id)).fetchall()
        if len(rows) != state["chunks"] or any(index != offset for offset, (index, _) in enumerate(rows)):
            raise ObjectTransferError("missing or incorrect chunk index")
        result = b"".join(data for _, data in rows)
        if len(result) != state["bytes"] or hashlib.sha256(result).hexdigest() != state["sha256"]:
            raise ObjectTransferError("whole-object integrity verification failed")
        if not result.startswith(b"SYNTHETIC:"):
            raise ObjectTransferError("only synthetic objects can be assembled")
        return result


def pull_object_chunks(inbox: ObjectInbox, identity: Ed25519PrivateKey,
                       recipient_secret: X25519PrivateKey, host: str, port: int,
                       server_key: bytes, *, timeout: float = .5,
                       max_messages: int = MAX_CHUNKS,
                       expected_sender: bytes | None = None) -> dict:
    """Commit a decrypted chunk locally *before* acknowledging its consumption on server."""
    if not 1 <= max_messages <= MAX_CHUNKS:
        raise ObjectTransferError("invalid receive limit")
    recipient = pub_bytes(identity)
    received = duplicates = skipped = 0
    identifiers = set()
    cursor = b""
    with BatchMailboxClient(host, port, identity, server_key, timeout=timeout) as link:
        # Fail explicitly against older mailbox servers rather than timing out on
        # a cursor request that they do not recognize. This is version negotiation.
        capability_code, capability_data = link.call(request("P"))
        if capability_code != "P" or b"cursor-v1" not in capability_data.split(b";"):
            raise ObjectTransferError("mailbox server lacks negotiated cursor-v1; upgrade server")
        # A separate bounded scan budget allows poison messages to be skipped
        # without consuming the caller's verified message delivery limit.
        for _ in range(max_messages + 4096):
            if received >= max_messages:
                break
            code, content = link.call(request("F", cursor))
            if code == "N":
                break
            if code != "M" or len(content) < 49:
                raise ObjectTransferError("invalid authenticated inbox response")
            sender, mid, ciphertext = content[:32], content[32:48], content[48:]
            cursor = sender + mid  # Next FETCH advances even if this item is poison.
            if expected_sender is not None and sender != expected_sender:
                skipped += 1
                continue
            try:
                clear = open_message(identity, recipient_secret, ciphertext,
                                     expected_sender=sender, expected_message_id=mid)
                chunk = inbox.ingest(sender, recipient, mid, clear)
            except ValueError:
                # Never acknowledge a message we could not verify/commit.
                skipped += 1
                continue
            identifiers.add(chunk["transfer_id"])
            # Local SQLite commit precedes remote consumed acknowledgement.
            ack_code, ack_data = link.call(request("A", sender + mid))
            if ack_code != "A" or ack_data != mid:
                raise ObjectTransferError("recipient consumption receipt rejected")
            received += 1
            duplicates += int(chunk["duplicate"])
        metrics = link.metrics()
    return {"status": "PASS", "consumed_chunks": received,
            "skipped_unverified_messages": skipped,
            "duplicate_chunks": duplicates, "transfer_ids": sorted(identifiers), **metrics,
            "meaning": "locally committed chunk THEN remote recipient-consumed receipt"}
