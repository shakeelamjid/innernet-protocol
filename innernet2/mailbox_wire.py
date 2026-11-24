"""INNERnet v0.5.0 experimental mailbox commands *inside* authenticated INL2 UDP.

This is an additive application path (2), NOT a new handshake or security audit.
Legacy stores are plaintext; strict IE60 stores authenticated ciphertext only.
"""
from __future__ import annotations

import hashlib
import secrets
import struct

from .mailbox_store import MailboxError, MailboxStore, MAX_BODY, MIN_TTL, MAX_TTL
from .live import MAX_PAYLOAD

REQUEST_MAGIC = b"IM50"
RESPONSE_MAGIC = b"IR50"
PATH_ID = 2
MAX_RESPONSE_BODY = MAX_PAYLOAD - 21


class WireError(ValueError):
    pass


def request(op: str, payload: bytes = b"", *, request_id: bytes | None = None) -> bytes:
    rid = secrets.token_bytes(16) if request_id is None else request_id
    if not isinstance(rid, bytes) or len(rid) != 16 or op not in {"S", "F", "A", "R", "Q", "P"}:
        raise WireError("invalid request metadata")
    packet = REQUEST_MAGIC + op.encode("ascii") + rid + payload
    if len(packet) > MAX_PAYLOAD:
        raise WireError("request exceeds encrypted UDP payload limit")
    return packet


def response(request_id: bytes, code: str, payload: bytes = b"") -> bytes:
    if not isinstance(request_id, bytes) or len(request_id) != 16 or len(code) != 1:
        raise WireError("invalid response header")
    frame = RESPONSE_MAGIC + request_id + code.encode("ascii") + payload
    if len(frame) > MAX_PAYLOAD:
        raise WireError("response exceeds encrypted UDP payload limit")
    return frame


def parse_response(frame: bytes, expected_id: bytes) -> tuple[str, bytes]:
    if (not isinstance(frame, bytes) or not 21 <= len(frame) <= MAX_PAYLOAD
            or frame[:4] != RESPONSE_MAGIC or frame[4:20] != expected_id):
        raise WireError("unexpected or unauthenticated response correlation")
    return chr(frame[20]), frame[21:]


def store_request(recipient: bytes, message_id: bytes, body: bytes, ttl: int = 3600,
                  *, request_id: bytes | None = None) -> bytes:
    if (len(recipient) != 32 or len(message_id) != 16 or
            not isinstance(body, bytes) or not 1 <= len(body) <= MAX_BODY or
            not MIN_TTL <= ttl <= MAX_TTL):
        raise WireError("invalid store request")
    return request("S", recipient + message_id + struct.pack(">I", ttl) + body,
                   request_id=request_id)


def handle_request(store: MailboxStore, client_identity: bytes, packet: bytes) -> bytes:
    """Only invoked AFTER a pinned identity and AEAD packet have been verified."""
    if (not isinstance(packet, bytes) or not 21 <= len(packet) <= MAX_PAYLOAD
            or packet[:4] != REQUEST_MAGIC or len(client_identity) != 32):
        raise WireError("invalid mailbox request frame")
    op, rid, body = chr(packet[4]), packet[5:21], packet[21:]
    if op == "S":
        if len(body) < 53:
            raise WireError("truncated STORE")
        recipient, message_id, ttl = body[:32], body[32:48], struct.unpack(">I", body[48:52])[0]
        payload = body[52:]
        try:
            outcome, digest = store.store(client_identity, recipient, message_id, payload, ttl)
            return response(rid, "D", message_id + digest + (b"N" if outcome == "STORED" else b"I"))
        except MailboxError:
            return response(rid, "E", b"S")
    if op == "F":
        if len(body) not in (0,48):
            raise WireError("FETCH requires empty body or 48-byte cursor")
        try:
            row = store.fetch(client_identity,after=(body[:32],body[32:]) if body else None)
        except MailboxError:
            return response(rid, "E", b"F")
        if row is None:
            return response(rid, "N")
        sender, msg_id, payload = row
        return response(rid, "M", sender + msg_id + payload)
    if op == "A":
        if len(body) != 48:
            raise WireError("ACK requires sender identity and message ID")
        try:
            ok = store.consume(client_identity, body[:32], body[32:48])
        except MailboxError:
            return response(rid, "E", b"A")
        return response(rid, "A" if ok else "E", body[32:48] if ok else b"A")
    if op == "R":
        if len(body) != 48:
            raise WireError("REJECT requires sender identity and message ID")
        try:
            ok = store.reject(client_identity,body[:32],body[32:48])
        except MailboxError:
            return response(rid,"E",b"R")
        return response(rid,"R" if ok else "E",body[32:48] if ok else b"R")
    if op == "Q":
        if len(body) != 16:
            raise WireError("STATUS requires message ID")
        try:
            state = store.status(client_identity, body)
        except MailboxError:
            return response(rid, "E", b"Q")
        return response(rid, "Q", {"UNKNOWN": b"U", "EXPIRED": b"X", "STORED": b"S", "CONSUMED": b"C", "REJECTED": b"R"}[state])
    if op == "P":
        if body:
            raise WireError("PING takes no body")
        return response(rid, "P", b"IN50;cursor-v1;reject-v1")
    raise WireError("unrecognized mailbox operation")
