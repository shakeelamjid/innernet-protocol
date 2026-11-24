"""INNERnet v0.5.0-alpha: pinned native-UDP mailbox RPC and resumable outbox.

Experimental, synthetic-data-only. UDP reconnect uses fresh authenticated
sessions; message ID idempotency is enforced in the remote SQLite journal.
"""
from __future__ import annotations
from .version import RELEASE_VERSION

import argparse
import hashlib
import json
from pathlib import Path
import secrets
import socket
import sys
import tempfile
import threading
import time
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .live import LiveSession, ReplayError
from .native_udp import (DEFAULT_PORT, HANDSHAKE_DOMAIN, SERVER_DOMAIN, PROTOCOL,
                         REPLY_LEN, REPLY_TAG, MAX_DATAGRAM, NativeResponder,
                         NativeTransitError, _secret, ephemeral_pub, hello_packet,
                         load_identity, parse_public_hex, pub_bytes, serve)
from .mailbox_store import MailboxStore, OutboxStore
from .mailbox_wire import PATH_ID, WireError, parse_response, request, store_request
from .mailbox_directory import (DirectoryError, find_route, load_verified,
                                sign_directory, verify_directory)

VERSION = RELEASE_VERSION


def rpc(host: str, port: int, identity: Ed25519PrivateKey,
        expected_server: bytes, frame: bytes, *, timeout: float = 0.5,
        attempts: int = 3, fresh_sessions: int = 2) -> tuple[str, bytes, dict]:
    """One authenticated request; bounded retries and fresh-session recovery.

    Application request ID stays constant across retransmissions. A fresh
    session after a lost receipt is safe only for idempotent mailbox commands.
    """
    if (len(expected_server) != 32 or not 1 <= port <= 65535 or
            not 0.05 <= timeout <= 10 or not 1 <= attempts <= 6 or
            not 1 <= fresh_sessions <= 4 or not 21 <= len(frame) <= 1152):
        raise ValueError("invalid RPC argument or limits")
    request_id = frame[5:21]
    try:
        address = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
    except socket.gaierror as exc:
        raise NativeTransitError("mailbox target could not be resolved") from exc
    handshake_retries = 0
    data_retries = 0
    for session_num in range(fresh_sessions):
        sid = secrets.token_bytes(16)
        eph = X25519PrivateKey.generate()
        hello = hello_packet(identity, expected_server, sid, ephemeral_pub(eph), secrets.token_bytes(16))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(address)
            sock.settimeout(timeout)
            established: LiveSession | None = None
            for i in range(attempts):
                if i:
                    handshake_retries += 1
                try:
                    sock.send(hello)
                    reply = sock.recv(MAX_DATAGRAM)
                except (socket.timeout, ConnectionRefusedError, OSError):
                    continue
                if len(reply) != REPLY_LEN or reply[:5] != PROTOCOL + REPLY_TAG or reply[5:21] != sid:
                    continue
                if reply[53:85] != expected_server:
                    raise NativeTransitError("mailbox server public identity mismatch")
                try:
                    Ed25519PublicKey.from_public_bytes(expected_server).verify(
                        reply[-64:], SERVER_DOMAIN + hello + reply[:-64])
                    secret = _secret(eph, reply[21:53], hello + reply)
                except (InvalidSignature, ValueError) as exc:
                    raise NativeTransitError("mailbox handshake authenticity failed") from exc
                established = LiveSession(secret, sid, "initiator")
                break
            if established is None:
                continue
            encrypted = established.encrypt_packet(frame, path_id=PATH_ID)
            for j in range(attempts):
                if j:
                    data_retries += 1
                try:
                    sock.send(encrypted)
                except (ConnectionRefusedError, OSError):
                    continue
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    sock.settimeout(max(0.001, deadline - time.monotonic()))
                    try:
                        reply = sock.recv(MAX_DATAGRAM)
                    except (socket.timeout, ConnectionRefusedError, OSError):
                        break
                    try:
                        path, clear = established.decrypt_packet(reply)
                    except (ValueError, InvalidTag, ReplayError):
                        continue
                    if path != PATH_ID:
                        continue
                    try:
                        code, body = parse_response(clear, request_id)
                    except WireError:
                        continue
                    return code, body, {"handshake_retries": handshake_retries,
                                        "data_retries": data_retries,
                                        "fresh_session_retries": session_num}
    raise NativeTransitError("mailbox request timed out across authenticated session attempts")


def store_message(host: str, port: int, client_key: Ed25519PrivateKey, server_key: bytes,
                  recipient: bytes, message_id: bytes, payload: bytes,
                  *, ttl: int = 3600, timeout: float = 0.5) -> dict:
    code, content, metrics = rpc(host, port, client_key, server_key,
                                 store_request(recipient, message_id, payload, ttl),
                                 timeout=timeout)
    if code != "D" or len(content) != 49 or content[:16] != message_id or content[16:48] != hashlib.sha256(payload).digest():
        raise NativeTransitError("server did not confirm matching SQLite store receipt")
    return {"status": "STORED" if content[48:] == b"N" else "ALREADY_STORED",
            "message_id": message_id.hex(), "receipt": "SQLITE_COMMITTED_NOT_CONSUMED",
            **metrics}


def fetch_message(host: str, port: int, client_key: Ed25519PrivateKey,
                  server_key: bytes, *, timeout: float = 0.5,
                  after: tuple[bytes,bytes] | None = None) -> dict:
    if after is not None and (len(after) != 2 or len(after[0]) != 32 or len(after[1]) != 16):
        raise ValueError("invalid recipient-scoped inbox cursor")
    code, content, metrics = rpc(host, port, client_key, server_key,
                                 request("F",b"" if after is None else after[0]+after[1]),
                                 timeout=timeout)
    if code == "N":
        return {"status": "EMPTY", **metrics}
    if code != "M" or len(content) < 49:
        raise NativeTransitError("invalid authenticated inbox response")
    return {"status": "AVAILABLE", "sender": content[:32].hex(),
            "message_id": content[32:48].hex(), "payload": content[48:], **metrics}


def consume_message(host: str, port: int, client_key: Ed25519PrivateKey,
                    server_key: bytes, sender: bytes, message_id: bytes, *,
                    timeout: float = 0.5) -> dict:
    if len(sender) != 32 or len(message_id) != 16:
        raise ValueError("invalid sender or message ID")
    code, body, metrics = rpc(host, port, client_key, server_key,
                              request("A", sender + message_id), timeout=timeout)
    if code != "A" or body != message_id:
        raise NativeTransitError("recipient consumption acknowledgement rejected")
    return {"status": "CONSUMED", "message_id": message_id.hex(), **metrics}


def reject_message(host: str, port: int, client_key: Ed25519PrivateKey,
                   server_key: bytes, sender: bytes, message_id: bytes, *,
                   timeout: float = 0.5) -> dict:
    if len(sender) != 32 or len(message_id) != 16:
        raise ValueError("invalid rejection key")
    code, body, metrics = rpc(host, port, client_key, server_key,
                              request("R", sender+message_id), timeout=timeout)
    if code != "R" or body != message_id:
        raise NativeTransitError("recipient rejection receipt not confirmed")
    return {"status":"REJECTED", "message_id":message_id.hex(), **metrics}


def query_status(host: str, port: int, client_key: Ed25519PrivateKey,
                 server_key: bytes, message_id: bytes, *, timeout: float = 0.5) -> dict:
    if len(message_id) != 16:
        raise ValueError("invalid message ID")
    code, body, metrics = rpc(host, port, client_key, server_key,
                              request("Q", message_id), timeout=timeout)
    if code != "Q" or body not in (b"S", b"C", b"R", b"U", b"X"):
        raise NativeTransitError("invalid authenticated message status")
    return {"status": {b"S": "STORED", b"C": "CONSUMED",
                       b"R": "REJECTED", b"U": "UNKNOWN", b"X": "EXPIRED"}[body],
            "message_id": message_id.hex(), **metrics}


def resolve_endpoint(args, recipient: bytes) -> tuple[str, int, bytes]:
    if args.directory:
        if not args.directory_key:
            raise ValueError("--directory-key is required for signed directory verification")
        directory = load_verified(args.directory, args.directory_key)
        node = find_route(directory, recipient)
        return node["host"], node["port"], parse_public_hex(node["public_ed25519"])
    if not args.host or not args.server_key:
        raise ValueError("provide --directory + --directory-key OR --host + --server-key")
    return args.host, args.port, parse_public_hex(args.server_key)


def demo(*, messages: int = 8) -> dict:
    if not 1 <= messages <= 32:
        raise ValueError("demo supports 1-32 messages")
    sender, recipient, server = [Ed25519PrivateKey.generate() for _ in range(3)]
    with tempfile.TemporaryDirectory(prefix="innernet-v050-") as raw:
        base = Path(raw)
        base.chmod(0o700)
        maildb, outdb = base / "mail.sqlite", base / "out.sqlite"
        outbox = OutboxStore(outdb)
        queued = [outbox.enqueue(pub_bytes(recipient), b"SYNTHETIC-TEST-" + bytes([i]))
                  for i in range(messages)]
        journal = MailboxStore(maildb)
        responder = NativeResponder(server, {pub_bytes(sender), pub_bytes(recipient)},
                                    mailbox_store=journal)
        halt = threading.Event()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        address = sock.getsockname()
        worker = threading.Thread(target=serve, args=(sock, responder),
                                  kwargs={"stop": halt}, daemon=True)
        worker.start()
        try:
            for mid, dest, body, ttl in outbox.queued(limit=messages):
                store_message(*address, sender, pub_bytes(server), dest, mid, body,
                              ttl=ttl, timeout=0.15)
                outbox.mark_stored(mid)
            assert not outbox.queued()
            first = fetch_message(*address, recipient, pub_bytes(server), timeout=0.15)
            assert first["status"] == "AVAILABLE"
            consume_message(*address, recipient, pub_bytes(server),
                            bytes.fromhex(first["sender"]), bytes.fromhex(first["message_id"]),
                            timeout=0.15)
            assert query_status(*address, sender, pub_bytes(server),
                                bytes.fromhex(first["message_id"]), timeout=0.15)["status"] == "CONSUMED"
        finally:
            halt.set()
            worker.join(timeout=2)
            sock.close()
            journal.close()
        # Reload database to establish restart survival (not a live crash test).
        reloaded = MailboxStore(maildb)
        persisted = [reloaded.status(pub_bytes(sender), mid) for mid in queued]
        reloaded.close()
        outbox.close()
        assert persisted.count("CONSUMED") == 1
        assert persisted.count("STORED") == messages - 1
        signed_payload = {"version": "IN50-STATIC-1", "created_at": int(time.time()) - 1,
                          "expires_at": int(time.time()) + 3600,
                          "nodes": [{"id": "local-test-node", "host": "127.0.0.1", "port": address[1],
                                     "public_ed25519": pub_bytes(server).hex(),
                                     "failure_domain": "single-host-test"}],
                          "routes": [{"recipient_ed25519": pub_bytes(recipient).hex(),
                                      "node_id": "local-test-node"}]}
        signed = sign_directory(signed_payload, sender)
        assert verify_directory(signed, pub_bytes(sender)) == signed_payload
    return {"status": "PASS", "release_version": VERSION, "queued": messages,
            "sqlite_receipts": messages, "recipient_consumed": 1,
            "post_restart_records": messages, "signed_directory_verified": True,
            "scope": "synthetic localhost, single host, no production security audit"}
