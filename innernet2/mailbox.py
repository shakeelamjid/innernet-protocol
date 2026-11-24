"""INNERnet experimental IN50 mailbox CLI, localhost default, synthetic-only.

Not a production messenger: legacy SQLite plaintext (strict IE60 ciphertext), operator-signed static
routes, no independent hosting validation, no peer-to-peer NAT traversal.
"""
from __future__ import annotations
from .version import RELEASE_VERSION

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import time

from .native_udp import (NativeResponder, DEFAULT_PORT, NativeTransitError,
                         load_identity, parse_public_hex, pub_bytes, serve)
from .mailbox_store import MailboxError, MailboxStore, OutboxStore, MAX_BODY
from .mailbox_wire import WireError
from .mailbox_client import (demo, store_message, fetch_message, consume_message,
                             reject_message, query_status, resolve_endpoint, rpc)
from .mailbox_directory import (DirectoryError, find_route, load_verified,
                                sign_directory)
from .mailbox_e2ee import (E2EEError, generate_bundle, verify_bundle, seal_message,
                          open_message, load_recipient_secret)


def _add_endpoint(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--server-key", help="pinned Ed25519 mailbox server key")
    parser.add_argument("--directory", type=Path, help="operator-signed routes JSON")
    parser.add_argument("--directory-key", help="pinned signing key for signed routes")
    parser.add_argument("--timeout", type=float, default=0.5)


def _write_new_json(path: Path, data: dict) -> None:
    if path.is_symlink() or path.exists():
        raise ValueError("refusing to overwrite existing directory file")
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise ValueError("directory parent missing or symlink")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        json.dump(data, out, indent=2)
        out.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=f"INNERnet {RELEASE_VERSION} experimental synthetic mailbox")
    sub = parser.add_subparsers(dest="command", required=True)
    local = sub.add_parser("demo", help="safe localhost send/fetch/consume/restart qualification")
    local.add_argument("--messages", type=int, default=8)

    listener = sub.add_parser("serve", help="run pinned mailbox UDP listener; localhost default")
    listener.add_argument("--identity", type=Path, required=True)
    listener.add_argument("--db", type=Path, required=True)
    listener.add_argument("--allow-client", action="append", required=True)
    listener.add_argument("--bind", default="127.0.0.1")
    listener.add_argument("--port", type=int, default=DEFAULT_PORT)
    listener.add_argument("--max-seconds", type=float, default=600)
    listener.add_argument("--acknowledge-public-udp", action="store_true")
    listener.add_argument("--require-e2ee", action="store_true",
                          help="deprecated compatibility flag: strict IE60 is now the default")
    listener.add_argument("--legacy-plaintext", action="store_true",
                          help="UNSAFE synthetic-only legacy mode; strict IE60 ciphertext is default")

    queued = sub.add_parser("queue", help="queue a SYNTHETIC test message in local SQLite outbox")
    queued.add_argument("--outbox", type=Path, required=True)
    queued.add_argument("--recipient", required=True)
    queued.add_argument("--synthetic-text", required=True,
                        help='must begin with "SYNTHETIC:"; not for actual messages')
    queued.add_argument("--ttl", type=int, default=3600)

    rxinit = sub.add_parser("recipient-init", help="create a signed X25519 recipient certificate")
    rxinit.add_argument("--identity", type=Path, required=True)
    rxinit.add_argument("--secret", type=Path, required=True)
    rxinit.add_argument("--bundle", type=Path, required=True)
    rxinit.add_argument("--ttl", type=int, default=86400)

    encq = sub.add_parser("queue-encrypted", help="queue recipient-only IE60 synthetic ciphertext")
    encq.add_argument("--outbox", type=Path, required=True)
    encq.add_argument("--identity", type=Path, required=True)
    encq.add_argument("--recipient", required=True, help="pinned Ed25519 recipient identity")
    encq.add_argument("--bundle", type=Path, required=True, help="recipient-signed public encryption bundle")
    encq.add_argument("--synthetic-text", required=True)
    encq.add_argument("--ttl", type=int, default=3600)

    dec = sub.add_parser("fetch-decrypted", help="retrieve and verify recipient-only IE60 ciphertext")
    dec.add_argument("--identity", type=Path, required=True)
    dec.add_argument("--recipient-secret", type=Path, required=True)
    dec.add_argument("--consume", action="store_true", help="ack only after authenticated decrypt")
    dec.add_argument("--reject-undecryptable", action="store_true",
                     help="DESTRUCTIVE: explicitly discard messages this reader cannot decrypt")
    dec.add_argument("--max-scan", type=int, default=256,
                     help="limit cursor scans per command (1..2000)")
    dec.add_argument("--after", help="optional 96-hex-character sender+message ID cursor")
    _add_endpoint(dec)

    secure_demo = sub.add_parser("demo-secure", help="two-node localhost ciphertext + signed routes demo")
    secure_demo.add_argument("--messages", type=int, default=4)

    objdemo = sub.add_parser("object-demo", help="IO70 two-node resumable encrypted synthetic object transfer")
    objdemo.add_argument("--kib", type=int, default=64, help="synthetic object size, 4-1024 KiB")

    objqueue = sub.add_parser("object-queue", help="queue encrypted chunks from a bounded SYNTHETIC: file")
    objqueue.add_argument("--outbox", type=Path, required=True)
    objqueue.add_argument("--identity", type=Path, required=True)
    objqueue.add_argument("--bundle", type=Path, required=True)
    objqueue.add_argument("--recipient", required=True, help="independently verified recipient Ed25519 key")
    objqueue.add_argument("--synthetic-file", type=Path, required=True)
    objqueue.add_argument("--ttl", type=int, default=3600)

    objflush = sub.add_parser("object-flush", help="resume sending all queued encrypted IO70 chunks")
    objflush.add_argument("--outbox", type=Path, required=True)
    objflush.add_argument("--identity", type=Path, required=True)
    _add_endpoint(objflush)
    objflush.add_argument("--max-messages", type=int)

    objpull = sub.add_parser("object-pull", help="retrieve/decrypt into local persistent IO70 checkpoint")
    objpull.add_argument("--inbox", type=Path, required=True)
    objpull.add_argument("--identity", type=Path, required=True)
    objpull.add_argument("--recipient-secret", type=Path, required=True)
    objpull.add_argument("--expected-sender", required=True)
    objpull.add_argument("--max-messages", type=int, default=1587)
    _add_endpoint(objpull)

    objexport = sub.add_parser("object-export", help="export COMPLETE synthetic object from checkpoint")
    objexport.add_argument("--inbox", type=Path, required=True)
    objexport.add_argument("--sender", required=True)
    objexport.add_argument("--recipient", required=True)
    objexport.add_argument("--transfer-id", required=True)
    objexport.add_argument("--output", type=Path, required=True)

    flush = sub.add_parser("flush", help="reconnect, send queued messages; idempotent across lost receipts")
    flush.add_argument("--outbox", type=Path, required=True)
    flush.add_argument("--identity", type=Path, required=True)
    _add_endpoint(flush)

    fetch = sub.add_parser("fetch", help="fetch own pending message without consuming it")
    fetch.add_argument("--identity", type=Path, required=True)
    _add_endpoint(fetch)

    ack = sub.add_parser("ack", help="recipient explicitly marks one message consumed")
    ack.add_argument("--identity", type=Path, required=True)
    ack.add_argument("--sender", required=True)
    ack.add_argument("--message-id", required=True)
    _add_endpoint(ack)

    status = sub.add_parser("status", help="sender checks if message is stored or consumed")
    status.add_argument("--identity", type=Path, required=True)
    status.add_argument("--message-id", required=True)
    status.add_argument("--recipient", help="required only when resolving signed routes")
    _add_endpoint(status)

    dsign = sub.add_parser("directory-sign", help="sign a static bootstrap directory JSON")
    dsign.add_argument("--identity", type=Path, required=True)
    dsign.add_argument("--input", type=Path, required=True)
    dsign.add_argument("--out", type=Path, required=True)

    droute = sub.add_parser("directory-route", help="validate publisher signature, then resolve recipient")
    droute.add_argument("--directory", type=Path, required=True)
    droute.add_argument("--directory-key", required=True)
    droute.add_argument("--recipient", required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            output = demo(messages=args.messages)
        elif args.command == "serve":
            if not 1 <= args.port <= 65535 or not 0 < args.max_seconds <= 3600:
                raise ValueError("invalid port or test duration")
            if args.bind not in ("127.0.0.1", "localhost") and not args.acknowledge_public_udp:
                raise ValueError("public binding requires explicit acknowledgement and firewall review")
            allow = {parse_public_hex(k) for k in args.allow_client}
            if args.require_e2ee and args.legacy_plaintext:
                raise ValueError("strict and legacy modes cannot be combined")
            store = MailboxStore(args.db, require_e2ee=not args.legacy_plaintext)
            try:
                responder = NativeResponder(load_identity(args.identity), allow, mailbox_store=store)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.bind((args.bind, args.port))
                    print(json.dumps({"ready": True, "release": RELEASE_VERSION,
                                      "address": sock.getsockname()[0], "port": sock.getsockname()[1],
                                      "public_ed25519": responder.public.hex(),
                                      "allowed_clients": len(allow),
                                      "receipt_semantics": "SQLite committed; recipient consumption separate",
                                      "require_e2ee": not args.legacy_plaintext,
                                      "caution": "synthetic-only; strict mode stores IE60 ciphertext; unaudited"}), flush=True)
                    serve(sock, responder, max_seconds=args.max_seconds)
            finally:
                store.close()
            return 0
        elif args.command == "object-demo":
            from .object_demo import run_demo
            output = run_demo(kib=args.kib)
        elif args.command == "object-queue":
            from .object_transfer import queue_object, MAX_OBJECT_BYTES
            if args.synthetic_file.is_symlink() or not args.synthetic_file.is_file():
                raise ValueError("refusing missing/symlink input file")
            if args.synthetic_file.stat().st_size > MAX_OBJECT_BYTES:
                raise ValueError("object exceeds 1 MiB")
            bundle = json.loads(args.bundle.read_text(encoding="utf-8"))
            out = OutboxStore(args.outbox)
            try:
                output = queue_object(load_identity(args.identity), bundle, out,
                                      args.synthetic_file.read_bytes(), ttl=args.ttl,
                                      expected_recipient=parse_public_hex(args.recipient))
            finally:
                out.close()
        elif args.command == "object-flush":
            from .mailbox_batch import BatchMailboxClient
            from .mailbox_wire import store_request
            sender = load_identity(args.identity)
            if args.max_messages is not None and not 1 <= args.max_messages <= 1587:
                raise ValueError("invalid chunk flush limit")
            out = OutboxStore(args.outbox)
            connections = {}
            commits = 0
            try:
                while out.queued(limit=1) and (args.max_messages is None or commits < args.max_messages):
                    mid, recipient, envelope, ttl = out.queued(limit=1)[0]
                    host, port, key = resolve_endpoint(args, recipient)
                    locator = (host, port, key)
                    if locator not in connections:
                        connections[locator] = BatchMailboxClient(host, port, sender, key,
                                                                  timeout=args.timeout)
                    from .object_transfer import _fresh_commit_ttl
                    effective_ttl = _fresh_commit_ttl(envelope, pub_bytes(sender), recipient, mid, ttl)
                    code, body = connections[locator].call(store_request(recipient, mid, envelope, effective_ttl))
                    if (code != "D" or len(body) != 49 or body[:16] != mid or
                            body[16:48] != hashlib.sha256(envelope).digest() or
                            body[48:] not in (b"N", b"I")):
                        raise NativeTransitError("node did not confirm matching SQLite commit")
                    out.mark_stored(mid)
                    commits += 1
                metrics = {"authenticated_handshakes": sum(c.handshakes for c in connections.values()),
                           "data_retransmissions": sum(c.data_retries for c in connections.values())}
                output = {"status": "PASS", "committed_chunks": commits, **metrics,
                          "meaning": "SQLite commit, not recipient consumption"}
            finally:
                for conn in connections.values():
                    conn.close()
                out.close()
        elif args.command == "object-pull":
            from .object_transfer import ObjectInbox, pull_object_chunks
            identity = load_identity(args.identity)
            host, port, key = resolve_endpoint(args, pub_bytes(identity))
            inbox = ObjectInbox(args.inbox)
            try:
                output = pull_object_chunks(inbox, identity, load_recipient_secret(args.recipient_secret),
                                            host, port, key, timeout=args.timeout,
                                            max_messages=args.max_messages,
                                            expected_sender=parse_public_hex(args.expected_sender))
            finally:
                inbox.close()
        elif args.command == "object-export":
            from .object_transfer import ObjectInbox
            target = args.output.expanduser().absolute()
            if target.is_symlink() or target.exists() or target.parent.is_symlink():
                raise ValueError("output already exists or uses a symlink; refusing overwrite")
            inbox = ObjectInbox(args.inbox)
            try:
                data = inbox.assemble(parse_public_hex(args.sender), parse_public_hex(args.recipient),
                                      bytes.fromhex(args.transfer_id))
            finally:
                inbox.close()
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as fp:
                fp.write(data)
                fp.flush()
                os.fsync(fp.fileno())
            output = {"status": "EXPORTED", "bytes": len(data),
                      "sha256": hashlib.sha256(data).hexdigest(), "file": str(target)}
        elif args.command == "demo-secure":
            from .mailbox_secure_demo import run_demo
            output = run_demo(messages=args.messages)
        elif args.command == "recipient-init":
            if args.bundle.is_symlink() or args.bundle.exists():
                raise ValueError("bundle output already exists; refusing orphaned private key")
            bundle = generate_bundle(load_identity(args.identity), args.secret, ttl=args.ttl)
            _write_new_json(args.bundle, bundle)
            output = {"status": "CREATED", "identity_ed25519": bundle["payload"]["identity_ed25519"],
                      "encryption_x25519": bundle["payload"]["encryption_x25519"],
                      "bundle": str(args.bundle), "secret": str(args.secret),
                      "warning": "KEEP private recipient seed SECRET; do not share or commit"}
        elif args.command == "queue-encrypted":
            sender = load_identity(args.identity)
            recipient = parse_public_hex(args.recipient)
            bundle = json.loads(args.bundle.read_text(encoding="utf-8"))
            verify_bundle(bundle, recipient)
            mid = os.urandom(16)
            encrypted = seal_message(sender, bundle, mid,
                                     args.synthetic_text.encode("utf-8"), ttl=args.ttl,
                                     expected_recipient=recipient)
            out = OutboxStore(args.outbox)
            try:
                out.enqueue(recipient, encrypted, ttl=args.ttl, message_id=mid)
            finally:
                out.close()
            output = {"status": "QUEUED_ENCRYPTED", "message_id": mid.hex(),
                      "ciphertext_bytes": len(encrypted), "note": "local outbox stores ciphertext"}
        elif args.command == "fetch-decrypted":
            recipient = load_identity(args.identity)
            secret = load_recipient_secret(args.recipient_secret)
            host, port, key = resolve_endpoint(args, pub_bytes(recipient))
            from .mailbox_e2ee import E2EEError
            from .mailbox_wire import request
            if not 1 <= args.max_scan <= 2000:
                raise ValueError("--max-scan must be 1..2000")
            cursor = None
            if args.after:
                if len(args.after) != 96:
                    raise ValueError("--after must be 96 hexadecimal characters")
                raw = bytes.fromhex(args.after)
                cursor = raw[:32], raw[32:]
            code, capabilities, _ = rpc(host,port,recipient,key,request("P"),timeout=args.timeout)
            if code != "P" or b"cursor-v1" not in capabilities.split(b";"):
                raise ValueError("mailbox server does not negotiate cursor-v1; upgrade for safe poison skip")
            if args.reject_undecryptable and b"reject-v1" not in capabilities.split(b";"):
                raise ValueError("server does not support authenticated reject-v1")
            skipped = 0
            for _ in range(args.max_scan):
                received = fetch_message(host, port, recipient, key, timeout=args.timeout, after=cursor)
                if received["status"] == "EMPTY":
                    output = {"status":"EMPTY", "skipped_undecryptable":skipped}
                    break
                mid = bytes.fromhex(received["message_id"])
                sender = bytes.fromhex(received["sender"])
                try:
                    clear = open_message(recipient, secret, received["payload"],
                                         expected_sender=sender, expected_message_id=mid)
                except E2EEError:
                    skipped += 1
                    if args.reject_undecryptable:
                        reject_message(host,port,recipient,key,sender,mid,timeout=args.timeout)
                    cursor = sender, mid
                    continue
                output = {"status": "DECRYPTED", "message_id": mid.hex(),
                          "sender": sender.hex(), "synthetic_text": clear.decode("utf-8", "replace"),
                          "verified_sender_signature": True, "skipped_undecryptable":skipped}
                if args.consume:
                    confirmed = consume_message(host, port, recipient, key, sender, mid,
                                                timeout=args.timeout)
                    output["receipt"] = confirmed["status"]
                break
            else:
                output = {"status":"SCAN_LIMIT", "skipped_undecryptable":skipped,
                          "after": (cursor[0]+cursor[1]).hex() if cursor else None,
                          "warning":"continue with --after or opt in to --reject-undecryptable"}
        elif args.command == "queue":
            payload = args.synthetic_text.encode("utf-8")
            if not payload.startswith(b"SYNTHETIC:") or len(payload) > MAX_BODY:
                raise ValueError("only bounded SYNTHETIC: test messages are accepted")
            out = OutboxStore(args.outbox)
            try:
                msgid = out.enqueue(parse_public_hex(args.recipient), payload, args.ttl)
            finally:
                out.close()
            output = {"status": "QUEUED", "message_id": msgid.hex(),
                      "scope": "local synthetic plaintext outbox"}
        elif args.command == "flush":
            sender = load_identity(args.identity)
            out = OutboxStore(args.outbox)
            sent = []
            try:
                for message_id, recipient, payload, ttl in out.queued():
                    host, port, key = resolve_endpoint(args, recipient)
                    if payload.startswith(b"IE60"):
                        from .object_transfer import _fresh_commit_ttl
                        ttl = _fresh_commit_ttl(payload, pub_bytes(sender), recipient, message_id, ttl)
                    reply = store_message(host, port, sender, key, recipient, message_id, payload,
                                          ttl=ttl, timeout=args.timeout)
                    out.mark_stored(message_id)
                    sent.append(reply)
            finally:
                out.close()
            output = {"status": "PASS", "stored_count": len(sent), "receipts": sent,
                      "meaning": "server SQLite commit, NOT recipient consumption"}
        elif args.command in ("fetch", "ack", "status"):
            client = load_identity(args.identity)
            # Recipient's mailbox route is keyed by their own public identity.
            if args.command == "status" and args.directory and not args.recipient:
                raise ValueError("status with signed directory requires --recipient")
            lookup_key = (pub_bytes(client) if args.command in ("fetch", "ack") else
                          parse_public_hex(args.recipient) if args.recipient else pub_bytes(client))
            host, port, key = resolve_endpoint(args, lookup_key)
            if args.command == "fetch":
                output = fetch_message(host, port, client, key, timeout=args.timeout)
                if output.get("payload") is not None:
                    payload = output.pop("payload")
                    output["payload_sha256"] = hashlib.sha256(payload).hexdigest()
                    output["synthetic_text"] = payload.decode("utf-8", "replace") if payload.startswith(b"SYNTHETIC:") else None
            elif args.command == "ack":
                output = consume_message(host, port, client, key,
                                         parse_public_hex(args.sender), bytes.fromhex(args.message_id),
                                         timeout=args.timeout)
            else:
                output = query_status(host, port, client, key,
                                      bytes.fromhex(args.message_id), timeout=args.timeout)
        elif args.command == "directory-sign":
            payload = json.loads(args.input.read_text(encoding="utf-8"))
            record = sign_directory(payload, load_identity(args.identity))
            _write_new_json(args.out, record)
            output = {"status": "SIGNED", "out": str(args.out),
                      "signer_ed25519": record["signer_ed25519"]}
        elif args.command == "directory-route":
            verified = load_verified(args.directory, args.directory_key)
            output = {"status": "VERIFIED", "node": find_route(verified, parse_public_hex(args.recipient)),
                      "note": "operator assertion only; not proof of independent hosting"}
        else:
            raise ValueError("unsupported mailbox command")
        print(json.dumps(output, indent=2))
        return 0
    except (NativeTransitError, WireError, DirectoryError, MailboxError,
            E2EEError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"INNERnet mailbox refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
