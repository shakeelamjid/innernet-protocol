"""Two localhost socket/SQLite nodes, recipient-only ciphertext demonstration.

Not independent providers, no DHT, no failover claim. For synthetic-data tests.
"""
from __future__ import annotations
from .version import RELEASE_VERSION

import hashlib
from pathlib import Path
import secrets
import socket
import tempfile
import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .mailbox_directory import sign_directory, verify_directory, find_route
from .mailbox_e2ee import generate_bundle, load_recipient_secret, seal_message, open_message
from .mailbox_store import MailboxStore, OutboxStore, MailboxError
from .mailbox_client import store_message, fetch_message, consume_message, query_status
from .native_udp import NativeResponder, pub_bytes, serve


class _Node:
    def __init__(self, key, allowed, db, port=0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", port))
        self.host, self.port = self.sock.getsockname()
        self.stop = threading.Event()
        self.worker = threading.Thread(target=serve, args=(self.sock, NativeResponder(
            key, allowed, mailbox_store=db)), kwargs={"stop": self.stop}, daemon=True)
        self.worker.start()

    def close(self):
        self.stop.set()
        self.worker.join(timeout=2)
        self.sock.close()
        if self.worker.is_alive():
            raise RuntimeError("test mailbox listener failed to exit")


def run_demo(*, messages: int = 4) -> dict:
    if not 1 <= messages <= 24:
        raise ValueError("demo supports 1-24 synthetic messages")
    with tempfile.TemporaryDirectory(prefix="innernet-v060-") as folder:
        base = Path(folder)
        base.chmod(0o700)
        sender = Ed25519PrivateKey.generate()
        recipients = [Ed25519PrivateKey.generate() for _ in range(2)]
        servers = [Ed25519PrivateKey.generate() for _ in range(2)]
        certs = [generate_bundle(identity, base / f"rx-{j}.key") for j, identity in enumerate(recipients)]
        outbox = OutboxStore(base / "encrypted-outbox.sqlite")
        dbs = [MailboxStore(base / f"node-{i}.sqlite", require_e2ee=True) for i in range(2)]
        nodes = []
        try:
            allowed = {pub_bytes(sender), *(pub_bytes(k) for k in recipients)}
            nodes = [_Node(servers[j], allowed, dbs[j]) for j in range(2)]
            now = int(time.time())
            directory = sign_directory({"version": "IN50-STATIC-1", "created_at": now-1,
                "expires_at": now+3600,
                "nodes": [{"id": f"local-node-{j}", "host": nodes[j].host,
                           "port": nodes[j].port, "public_ed25519": pub_bytes(servers[j]).hex(),
                           "failure_domain": "single-local-host"} for j in range(2)],
                "routes": [{"recipient_ed25519": pub_bytes(recipients[j]).hex(),
                            "node_id": f"local-node-{j}"} for j in range(2)]}, sender)
            signed_routes = verify_directory(directory, pub_bytes(sender))
            records = []
            for idx in range(messages):
                target = idx % 2
                recipient_key = pub_bytes(recipients[target])
                mid = secrets.token_bytes(16)
                plaintext = f"SYNTHETIC: node-{target} message {idx}".encode()
                ciphertext = seal_message(sender, certs[target], mid, plaintext, expected_recipient=recipient_key)
                assert plaintext not in ciphertext
                outbox.enqueue(recipient_key, ciphertext, message_id=mid)
                records.append((target, mid, plaintext, ciphertext))
            queued = outbox.queued(limit=messages)
            for mid, recipient, encrypted, ttl in queued:
                route = find_route(signed_routes, recipient)
                receipt = store_message(route["host"], route["port"], sender,
                                        bytes.fromhex(route["public_ed25519"]), recipient,
                                        mid, encrypted, ttl=ttl, timeout=.2)
                assert receipt["status"] == "STORED"
                outbox.mark_stored(mid)
            assert not outbox.queued()
            # The receiver cannot accept a legacy plaintext store in strict mode.
            try:
                dbs[0].store(pub_bytes(sender), pub_bytes(recipients[0]),
                             secrets.token_bytes(16), b"SYNTHETIC:PLAINTEXT")
                raise AssertionError("strict receiver accepted plaintext")
            except MailboxError:
                pass
            # Confirm opaque ciphertext at rest, not merely the protocol response.
            for index, mid, plaintext, ciphertext in records:
                dbrow = dbs[index].db.execute(
                    "SELECT payload FROM messages WHERE sender=? AND message_id=?",
                    (pub_bytes(sender), mid)).fetchone()
                assert dbrow and dbrow[0] == ciphertext and plaintext not in dbrow[0]
            for node in nodes:
                node.close()
            nodes.clear()
            for db in dbs:
                db.close()
            dbs = [MailboxStore(base / f"node-{i}.sqlite", require_e2ee=True) for i in range(2)]
            # Simulate a mailbox process restart while retaining each independent DB.
            nodes = [_Node(servers[j], allowed, dbs[j], port=signed_routes["nodes"][j]["port"])
                     for j in range(2)]
            for index, mid, plaintext, ciphertext in records:
                route = find_route(signed_routes, pub_bytes(recipients[index]))
                addr = (route["host"], route["port"])
                delivery = fetch_message(*addr, recipients[index], pub_bytes(servers[index]), timeout=.2)
                assert delivery["status"] == "AVAILABLE"
                clear = open_message(recipients[index], load_recipient_secret(base / f"rx-{index}.key"),
                                     delivery["payload"], expected_sender=pub_bytes(sender),
                                     expected_message_id=mid)
                assert clear == plaintext
                consume_message(*addr, recipients[index], pub_bytes(servers[index]),
                                pub_bytes(sender), mid, timeout=.2)
                assert query_status(*addr, sender, pub_bytes(servers[index]),
                                    mid, timeout=.2)["status"] == "CONSUMED"
            return {"status": "PASS", "release": RELEASE_VERSION,
                    "messages": messages, "ciphertext_commits": messages,
                    "verified_decryptions": messages, "consumed": messages,
                    "server_restart_records": messages, "separate_local_nodes": 2,
                    "signed_routes_verified": True, "plaintext_rejected": True,
                    "plaintext_not_in_node_databases": True,
                    "scope": "two localhost nodes and synthetic data only; NOT independent hosting/audit"}
        finally:
            for node in nodes:
                node.close()
            for db in dbs:
                try:
                    db.close()
                except Exception:
                    pass
            outbox.close()
