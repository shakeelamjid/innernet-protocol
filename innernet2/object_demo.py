"""Reproducible IO70 two-node localhost demonstration with an interrupted transfer."""
from __future__ import annotations
from .version import RELEASE_VERSION

import hashlib
import math
from pathlib import Path
import random
import socket
import tempfile
import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .mailbox_directory import find_route, sign_directory, verify_directory
from .mailbox_e2ee import generate_bundle, load_recipient_secret
from .mailbox_store import MailboxStore, OutboxStore
from .mailbox_client import store_message
from .native_udp import NativeResponder, pub_bytes, serve
from .object_transfer import (CHUNK_SIZE, ObjectInbox, chunk_message_id, flush_object_outbox,
                              pull_object_chunks, queue_object)


class DemoNode:
    def __init__(self, server, allowed, db):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.host, self.port = self.sock.getsockname()
        self.stop_event = threading.Event()
        self.worker = threading.Thread(target=serve, args=(self.sock, NativeResponder(
            server, allowed, mailbox_store=db)), kwargs={"stop": self.stop_event}, daemon=True)
        self.worker.start()

    def close(self):
        self.stop_event.set()
        self.worker.join(timeout=3)
        self.sock.close()
        if self.worker.is_alive():
            raise RuntimeError("loopback node did not shut down")


def synthetic_bytes(size: int, seed: int = 7070) -> bytes:
    prefix = b"SYNTHETIC:INNERnet IO70 object transfer test\n"
    if size < len(prefix):
        raise ValueError("test object size too small")
    r = random.Random(seed)
    return prefix + r.randbytes(size - len(prefix))


def run_demo(*, kib: int = 64) -> dict:
    if not 4 <= kib <= 1024:
        raise ValueError("demo supports 4-1024 KiB synthetic objects")
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="innernet-io70-") as folder:
        base = Path(folder)
        base.chmod(0o700)
        sender = Ed25519PrivateKey.generate()
        recipients = [Ed25519PrivateKey.generate() for _ in range(2)]
        nodes_keys = [Ed25519PrivateKey.generate() for _ in range(2)]
        bundles = [generate_bundle(identity, base / f"recipient-{i}.key")
                   for i, identity in enumerate(recipients)]
        secrets = [load_recipient_secret(base / f"recipient-{i}.key") for i in range(2)]
        allowed = {pub_bytes(sender), *(pub_bytes(r) for r in recipients)}
        serverdbs = [MailboxStore(base / f"server-{i}.sqlite", require_e2ee=True)
                     for i in range(2)]
        live = [DemoNode(nodes_keys[i], allowed, serverdbs[i]) for i in range(2)]
        outboxes = [OutboxStore(base / f"outbox-{i}.sqlite") for i in range(2)]
        inboxes = [ObjectInbox(base / f"inbox-{i}.sqlite") for i in range(2)]
        try:
            now = int(time.time())
            directory = sign_directory({"version": "IN50-STATIC-1", "created_at": now - 1,
                "expires_at": now + 3600,
                "nodes": [{"id": f"io70-node-{i}", "host": live[i].host, "port": live[i].port,
                           "public_ed25519": pub_bytes(nodes_keys[i]).hex(),
                           "failure_domain": "same-local-machine"} for i in range(2)],
                "routes": [{"recipient_ed25519": pub_bytes(recipients[i]).hex(),
                            "node_id": f"io70-node-{i}"} for i in range(2)]}, sender)
            routes = verify_directory(directory, pub_bytes(sender))
            blob_a, blob_b = synthetic_bytes(kib * 1024), synthetic_bytes(8192, seed=7071)
            queued_a = queue_object(sender, bundles[0], outboxes[0], blob_a, expected_recipient=pub_bytes(recipients[0]))
            queued_b = queue_object(sender, bundles[1], outboxes[1], blob_b, expected_recipient=pub_bytes(recipients[1]))
            route_a = find_route(routes, pub_bytes(recipients[0]))
            route_b = find_route(routes, pub_bytes(recipients[1]))
            # A starts, is interrupted, and retains sender outbox and remote SQLite.
            first = max(1, queued_a["chunks"] // 3)
            uploaded_a1 = flush_object_outbox(outboxes[0], sender, route_a["host"], route_a["port"],
                                              pub_bytes(nodes_keys[0]), timeout=.25,
                                              max_messages=first)
            # Node B remains independently operational while node A is stopped.
            live[0].close()
            flushed_b = flush_object_outbox(outboxes[1], sender, route_b["host"], route_b["port"],
                                           pub_bytes(nodes_keys[1]), timeout=.25)
            fetched_b = pull_object_chunks(inboxes[1], recipients[1], secrets[1], route_b["host"],
                                           route_b["port"], pub_bytes(nodes_keys[1]),
                                           timeout=.25, expected_sender=pub_bytes(sender))
            assert fetched_b["consumed_chunks"] == queued_b["chunks"]
            assert inboxes[1].assemble(pub_bytes(sender), pub_bytes(recipients[1]),
                                      bytes.fromhex(queued_b["transfer_id"])) == blob_b
            # Recreate node A from the exact same durable SQLite DB.
            live[0] = DemoNode(nodes_keys[0], allowed, serverdbs[0])
            flushed_a2 = flush_object_outbox(outboxes[0], sender, live[0].host, live[0].port,
                                             pub_bytes(nodes_keys[0]), timeout=.25)
            # Check recipient can checkpoint local progress and resume after process restart.
            partial = pull_object_chunks(inboxes[0], recipients[0], secrets[0], live[0].host,
                                         live[0].port, pub_bytes(nodes_keys[0]), timeout=.25,
                                         max_messages=max(1, queued_a["chunks"] // 2),
                                         expected_sender=pub_bytes(sender))
            inboxes[0].close()
            inboxes[0] = ObjectInbox(base / "inbox-0.sqlite")
            remaining = pull_object_chunks(inboxes[0], recipients[0], secrets[0], live[0].host,
                                           live[0].port, pub_bytes(nodes_keys[0]), timeout=.25,
                                           expected_sender=pub_bytes(sender))
            assert partial["consumed_chunks"] + remaining["consumed_chunks"] == queued_a["chunks"]
            reconstructed = inboxes[0].assemble(pub_bytes(sender), pub_bytes(recipients[0]),
                                                bytes.fromhex(queued_a["transfer_id"]))
            assert reconstructed == blob_a
            assert not outboxes[0].queued() and not outboxes[1].queued()
            assert all(b"SYNTHETIC:IO70" not in payload for db in serverdbs for
                       (payload,) in db.db.execute("SELECT payload FROM messages"))
            # Duplicate store is idempotent even after restart of the server process.
            first_envelope = outboxes[0].db.execute(
                "SELECT message_id,recipient,payload,created,ttl FROM pending ORDER BY created,rowid LIMIT 1").fetchone()
            dmid, dest, cipher, created, signed_ttl = first_envelope
            repeated = store_message(live[0].host, live[0].port, sender, pub_bytes(nodes_keys[0]),
                                     dest, dmid, cipher, ttl=int(created + signed_ttl - time.time()), timeout=.25)
            assert repeated["status"] == "ALREADY_STORED"
            return {"status": "PASS", "release_version": RELEASE_VERSION,
                    "transport": "actual loopback UDP, two localhost nodes, signed recipient routes",
                    "object_a_bytes": len(blob_a), "object_a_chunks": queued_a["chunks"],
                    "object_b_bytes": len(blob_b), "object_b_chunks": queued_b["chunks"],
                    "authenticated_chunk_commits": queued_a["chunks"] + queued_b["chunks"],
                    "recipients_reconstructed_sha256": [hashlib.sha256(blob_a).hexdigest(),
                                                        hashlib.sha256(blob_b).hexdigest()],
                    "node_b_served_during_a_outage": True, "sender_reconnected_after_a_restart": True,
                    "recipient_inbox_resumed_after_restart": True,
                    "duplicate_server_store_detected": True,
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "limits": "synthetic-only; <=1 MiB per object; no WAN test, autonomous forwarding, or security audit"}
        finally:
            for node in live:
                node.close()
            for inbox in inboxes:
                inbox.close()
            for outbox in outboxes:
                outbox.close()
            for db in serverdbs:
                db.close()
