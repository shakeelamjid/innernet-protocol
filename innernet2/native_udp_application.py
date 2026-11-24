"""INNERnet v0.4.2 VOLATILE application-message experiment.

Application path 1 is a new optional payload convention inside the existing
IN40/INL2 encrypted UDP wire. Old peers and path 0 are unaffected. A receipt
means an allowed server accepted the frame into *bounded RAM*; it does not mean
persistence, end-user delivery, exactly-once effects or durable queueing.
SYNTHETIC DATA ONLY. Not a general-purpose chat service.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import socket
import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .live import MAX_PAYLOAD

APP_MAGIC = b"IM42"
APP_HEADER_LEN = 20  # four-byte magic, 16-byte application ID
MAX_APP_PAYLOAD = MAX_PAYLOAD - APP_HEADER_LEN


def encode_frame(message_id: bytes, payload: bytes) -> bytes:
    """Generate a bounded application frame with caller-specified idempotency ID."""
    if not isinstance(message_id, bytes) or len(message_id) != 16:
        raise ValueError("application message ID must contain exactly 16 bytes")
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_APP_PAYLOAD:
        raise ValueError("application payload must be nonempty and within packet MTU")
    return APP_MAGIC + message_id + payload


def parse_frame(frame: bytes) -> tuple[bytes, bytes]:
    if not isinstance(frame, bytes) or not APP_HEADER_LEN + 1 <= len(frame) <= MAX_PAYLOAD:
        raise ValueError("malformed or oversized application frame")
    if not frame.startswith(APP_MAGIC):
        raise ValueError("invalid application frame magic")
    return frame[4:20], frame[20:]


def synthetic_frames(count: int, payload_bytes: int = 128) -> list[bytes]:
    """Random, uninterpreted test bytes only; no user-entered content."""
    if not 1 <= count <= 200 or not 1 <= payload_bytes <= MAX_APP_PAYLOAD:
        raise ValueError("invalid application qualification limits")
    return [encode_frame(secrets.token_bytes(16), secrets.token_bytes(payload_bytes))
            for _ in range(count)]


def application_qualification(messages: int = 12, payload_bytes: int = 128) -> dict:
    """End-to-end encrypted, authenticated application frames over loopback UDP."""
    from .native_udp import NativeResponder, native_probe, pub_bytes, serve, RELEASE_VERSION

    server_key = Ed25519PrivateKey.generate()
    client_key = Ed25519PrivateKey.generate()
    responder = NativeResponder(server_key, {pub_bytes(client_key)},
                                accept_synthetic_application=True)
    frames = synthetic_frames(messages, payload_bytes)
    halt = threading.Event()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        thread = threading.Thread(target=serve, args=(sock, responder),
                                  kwargs={"stop": halt}, daemon=True)
        thread.start()
        try:
            result = native_probe("127.0.0.1", sock.getsockname()[1], client_key,
                                  pub_bytes(server_key), samples=messages,
                                  payload_bytes=payload_bytes, messages=frames,
                                  path_id=1, timeout=0.1, attempts=4)
        finally:
            halt.set()
            thread.join(timeout=3)
        if thread.is_alive():
            raise RuntimeError("application qualifier UDP worker did not stop")

    seen = {message_id: hashlib.sha256(payload).digest()
            for message_id, payload in responder.application_inbox}
    expected = {frame[4:20]: hashlib.sha256(frame[20:]).digest() for frame in frames}
    good = (result["status"] == "PASS" and seen == expected and
            responder.application_accepted == messages and
            responder.accepted_messages == messages)
    return {
        "status": "PASS" if good else "FAIL",
        "release_version": RELEASE_VERSION,
        "transport": "actual IPv4 loopback UDP with pinned identity and IN40/INL2 encryption",
        "application_path": 1,
        "message_format": "IM42 inside encrypted payload; legacy path 0 unchanged",
        "requested_messages": messages,
        "authenticated_receipts": result["authenticated_receipts"],
        "volatile_application_accepted": responder.application_accepted,
        "volatile_message_digests_match": seen == expected,
        "application_duplicate_ids": responder.application_duplicate_ids,
        "packet_retransmissions": result["datagram_retransmissions"],
        "scope": "synthetic data, localhost only; bounded RAM, no persistence, no external delivery",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="INNERnet 0.4.2 volatile application test (local only)")
    parser.add_argument("--messages", type=int, default=12)
    parser.add_argument("--bytes", type=int, default=128)
    args = parser.parse_args(argv)
    try:
        result = application_qualification(args.messages, args.bytes)
    except (OSError, RuntimeError, ValueError) as exc:
        parser.exit(2, f"application test refused: {type(exc).__name__}: {exc}\n")
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
