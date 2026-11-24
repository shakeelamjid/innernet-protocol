"""INNERnet RC5 experimental IN40/IN41 native UDP: *synthetic-data-only* peer transit.

Wire v0.4.0 is deliberately retained for interoperability and is separate from v2 durable storage, and continues to
use the existing INL2 per-packet AEAD/replay codec. A mutually pinned Ed25519
handshake authenticates ephemeral X25519 public keys before session traffic.
No third-party security audit, QUIC/MASQUE, NAT traversal, VPN/TUN, relay,
forward secrecy against endpoint compromise, or production hardening is claimed.

All public listeners REQUIRE an explicit acknowledgment AND a pinned client
allowlist. Invalid handshakes receive no response. No plaintext message content,
identity private key, or session secret is included in the JSON report.
"""
from __future__ import annotations

import argparse
from collections import OrderedDict, deque
from dataclasses import dataclass, field
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import logging
import statistics
import struct
import sys
import threading
import time
from typing import Any, Sequence

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .live import LiveSession, MAX_PAYLOAD, ReplayError

PROTOCOL = b"IN40"
FRESH_PROTOCOL = b"IN41"
HELLO_TAG = b"C"
REPLY_TAG = b"S"
HANDSHAKE_DOMAIN = b"INNERnet/native-udp/0.4.0-alpha/handshake"
SERVER_DOMAIN = b"INNERnet/native-udp/0.4.0-alpha/server-proof"
SECRET_DOMAIN = b"INNERnet/native-udp/0.4.0-alpha/hkdf"
# Type(5) + sid(16) + ephemeral(32) + initiator(32) + target(32) + nonce(16) + sig(64)
HELLO_LEN = 197
FRESH_HELLO_LEN = HELLO_LEN + 8
FRESH_HANDSHAKE_DOMAIN = b"INNERnet/native-udp/IN41/handshake"
FRESH_SERVER_DOMAIN = b"INNERnet/native-udp/IN41/server-proof"
FRESH_WINDOW_SECONDS = 90
# Type(5) + sid(16) + ephemeral(32) + signing pub(32) + sig(64)
REPLY_LEN = 149
MAX_DATAGRAM = 2048
MAX_SESSIONS = 128
SESSION_LIFETIME = 120.0
MAX_RECEIPTS = 256
DEFAULT_PORT = 29410
MAX_APPLICATION_RECORDS = 256
MAX_APPLICATION_DEDUP = 1024
from .version import RELEASE_VERSION  # wire profiles remain IN40 and IN41


class NativeTransitError(RuntimeError):
    """Avoid exposing private key material, plaintext, or raw packets in messages."""


def pub_bytes(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(serialization.Encoding.Raw,
                                             serialization.PublicFormat.Raw)


def ephemeral_pub(private: X25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(serialization.Encoding.Raw,
                                             serialization.PublicFormat.Raw)


def parse_public_hex(raw: str) -> bytes:
    if not isinstance(raw, str) or len(raw) != 64:
        raise ValueError("expected exactly 32-byte Ed25519 public key as 64 hex characters")
    try:
        return bytes.fromhex(raw)
    except ValueError as exc:
        raise ValueError("public key must be hexadecimal") from exc


def generate_identity_file(path: Path) -> str:
    """Create, never overwrite, a private Ed25519 seed file (0600)."""
    path = path.expanduser().absolute()
    if path.is_symlink() or path.exists():
        raise NativeTransitError("identity already exists or is a symlink; refusing overwrite")
    if path.parent.is_symlink():
        raise NativeTransitError("refusing symlink identity directory")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    secret = Ed25519PrivateKey.generate()
    raw = secret.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                               serialization.NoEncryption())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return pub_bytes(secret).hex()


def load_identity(path: Path) -> Ed25519PrivateKey:
    path = path.expanduser().absolute()
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise NativeTransitError("private identity missing or unsafe permissions; expected mode 0600")
    data = path.read_bytes()
    if len(data) != 32:
        raise NativeTransitError("private identity must contain a 32-byte Ed25519 seed")
    return Ed25519PrivateKey.from_private_bytes(data)


def _secret(private: X25519PrivateKey, peer_pub: bytes, transcript: bytes) -> bytes:
    shared = private.exchange(X25519PublicKey.from_public_bytes(peer_pub))
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=hashlib.sha256(transcript).digest(), info=SECRET_DOMAIN).derive(shared)


def hello_packet(identity: Ed25519PrivateKey, server_pub: bytes,
                 sid: bytes, eph_pub: bytes, nonce: bytes) -> bytes:
    if any(len(x) != n for x, n in [(server_pub, 32), (sid, 16), (eph_pub, 32), (nonce, 16)]):
        raise ValueError("invalid handshake parameters")
    unsigned = PROTOCOL + HELLO_TAG + sid + eph_pub + pub_bytes(identity) + server_pub + nonce
    return unsigned + identity.sign(HANDSHAKE_DOMAIN + unsigned)


def hello_packet_v041(identity: Ed25519PrivateKey, server_pub: bytes,
                       sid: bytes, eph_pub: bytes, nonce: bytes,
                       *, timestamp: int | None = None) -> bytes:
    """Timestamped IN41 HELLO, signed over server identity and expiration context."""
    if any(len(x) != n for x, n in [(server_pub, 32), (sid, 16), (eph_pub, 32), (nonce, 16)]):
        raise ValueError("invalid handshake parameters")
    if timestamp is None:
        timestamp = int(time.time())
    if type(timestamp) is not int or not 0 <= timestamp < 2**64:
        raise ValueError("invalid handshake timestamp")
    unsigned = (FRESH_PROTOCOL + HELLO_TAG + sid + eph_pub + pub_bytes(identity) +
                server_pub + nonce + timestamp.to_bytes(8, 'big'))
    return unsigned + identity.sign(FRESH_HANDSHAKE_DOMAIN + unsigned)


class PersistentHelloJournal:
    """Bounded expiry journal, fsynced SQLite commits survive clean restarts.

    IN41 uses signed wall-time freshness AND durable fingerprint deduplication.
    This is not a defense against a malicious peer generating new signed hellos.
    """
    def __init__(self, path: str | Path):
        self.path = Path(path)
        if self.path.is_symlink():
            raise ValueError("replay database may not be a symlink")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.parent.stat().st_mode & 0o077:
            raise ValueError("replay journal directory must be private (0700)")
        if self.path.exists() and self.path.stat().st_mode & 0o077:
            raise ValueError("replay journal file must be private (0600)")
        self._lock = threading.Lock()
        self.db = sqlite3.connect(str(self.path), timeout=3, check_same_thread=False)
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS seen (digest BLOB PRIMARY KEY, owner BLOB NOT NULL, expires INTEGER NOT NULL)')
        self.db.execute('CREATE INDEX IF NOT EXISTS seen_exp ON seen(expires)')
        self.db.execute('CREATE INDEX IF NOT EXISTS seen_owner ON seen(owner)')
        self.db.commit()
        try:
            self.path.chmod(0o600)
        except OSError:
            self.db.close()
            raise

    def accept(self, packet_digest: bytes, now: int, expires: int, owner: bytes) -> bool:
        if len(packet_digest) != 32 or len(owner) != 32 or expires < now:
            return False
        try:
            with self._lock, self.db:
                self.db.execute('DELETE FROM seen WHERE expires < ?', (now,))
                if self.db.execute('SELECT COUNT(*) FROM seen WHERE owner=?', (owner,)).fetchone()[0] >= 512:
                    return False
                if self.db.execute('SELECT COUNT(*) FROM seen').fetchone()[0] >= 8192:
                    return False
                cur = self.db.execute('INSERT OR IGNORE INTO seen(digest,owner,expires) VALUES(?,?,?)',
                                      (packet_digest, owner, expires))
                return cur.rowcount == 1
        except sqlite3.Error:
            return False

    def close(self) -> None:
        self.db.close()


@dataclass
class _ServerSession:
    session: LiveSession
    address: tuple
    hello_digest: bytes
    server_reply: bytes
    created: float
    client_identity: bytes = b""
    confirmed: bool = False
    acknowledgments: OrderedDict[bytes, bytes] = field(default_factory=OrderedDict)


class NativeResponder:
    """In-memory, bounded, allowlisted UDP responder; no data persistence."""
    def __init__(self, identity: Ed25519PrivateKey, allowed_clients: set[bytes],
                 lifetime: float = SESSION_LIFETIME, *, accept_synthetic_application: bool = False,
                 mailbox_store=None, fresh_journal: PersistentHelloJournal | None = None):
        if not allowed_clients or any(len(item) != 32 for item in allowed_clients):
            raise ValueError("at least one pinned 32-byte client identity is required")
        if not 1 <= lifetime <= 3600:
            raise ValueError("invalid session lifetime")
        self.identity = identity
        self.public = pub_bytes(identity)
        self.allowed = frozenset(allowed_clients)
        self.lifetime = lifetime
        self.accept_synthetic_application = accept_synthetic_application
        self.mailbox_store = mailbox_store
        self.fresh_journal = fresh_journal
        # Bounded, VOLATILE inspection queue. Never durable storage or delivery to an end user.
        self.application_inbox: deque[tuple[bytes, bytes]] = deque(maxlen=MAX_APPLICATION_RECORDS)
        self._application_seen: OrderedDict[tuple[bytes, bytes], bytes] = OrderedDict()
        self.application_accepted = 0
        self.application_duplicate_ids = 0
        self.sessions: OrderedDict[bytes, _ServerSession] = OrderedDict()
        # A replayed signed IN40 hello must not create a fresh session after
        # its earlier session expires. This cache is volatile and bounded;
        # persistent replay resistance requires a versioned timestamped wire handshake.
        self._hello_seen: OrderedDict[bytes,tuple[float,bytes]] = OrderedDict()
        self.accepted_handshakes = 0
        self.duplicate_handshakes = 0
        self.expired_sessions = 0
        self.accepted_messages = 0
        self.duplicate_datagrams = 0
        self.rejected_datagrams = 0

    def _prune(self) -> None:
        now = time.monotonic()
        while self._hello_seen and now-next(iter(self._hello_seen.values()))[0] > 3600:
            self._hello_seen.popitem(last=False)
        for sid, item in tuple(self.sessions.items()):
            if now - item.created >= self.lifetime:
                del self.sessions[sid]
                self.expired_sessions += 1

    def process(self, packet: bytes, address: tuple) -> bytes | None:
        """Never respond to invalid/unauthorized packets. Does not raise to caller."""
        if not isinstance(packet, bytes) or not 1 <= len(packet) <= MAX_DATAGRAM:
            self.rejected_datagrams += 1
            return None
        self._prune()
        if packet.startswith(FRESH_PROTOCOL + HELLO_TAG):
            return self._hello(packet, address, fresh=True)
        if packet.startswith(PROTOCOL + HELLO_TAG):
            if self.fresh_journal is not None:
                # Secure mode never silently downgrades to replayable IN40.
                self.rejected_datagrams += 1
                return None
            return self._hello(packet, address)
        if packet.startswith(b"INL2"):
            return self._data(packet, address)
        self.rejected_datagrams += 1
        return None

    def _hello(self, packet: bytes, address: tuple, *, fresh: bool = False) -> bytes | None:
        if fresh and self.fresh_journal is None:
            self.rejected_datagrams += 1
            return None
        if len(packet) != (FRESH_HELLO_LEN if fresh else HELLO_LEN):
            self.rejected_datagrams += 1
            return None
        sid = packet[5:21]
        peer_ephemeral = packet[21:53]
        peer_identity = packet[53:85]
        target_identity = packet[85:117]
        if peer_identity not in self.allowed or target_identity != self.public:
            self.rejected_datagrams += 1
            return None
        try:
            Ed25519PublicKey.from_public_bytes(peer_identity).verify(
                packet[-64:], (FRESH_HANDSHAKE_DOMAIN if fresh else HANDSHAKE_DOMAIN) + packet[:-64])
        except (ValueError, InvalidSignature):
            self.rejected_datagrams += 1
            return None
        if fresh:
            timestamp = int.from_bytes(packet[-72:-64], 'big')
            now = int(time.time())
            if abs(now - timestamp) > FRESH_WINDOW_SECONDS:
                self.rejected_datagrams += 1
                return None
        digest = hashlib.sha256(packet).digest()
        old = self.sessions.get(sid)
        if old is not None:
            if old.hello_digest == digest and old.address == address:
                self.duplicate_handshakes += 1
                return old.server_reply  # byte-exact handshake retry, no session reset
            self.rejected_datagrams += 1
            return None
        if digest in self._hello_seen:
            self.rejected_datagrams += 1
            return None
        # Unconfirmed sessions do not consume an identity's authenticated quota.
        # Replace an old unconfirmed slot under pressure so captured hellos cannot
        # indefinitely lock an identity out. This mitigates but does NOT provide
        # durable replay protection across process restarts.
        confirmed = sum(s.client_identity == peer_identity and s.confirmed
                        for s in self.sessions.values())
        # Reserve replay-history capacity for other allowlisted identities.
        # A single identity may exhaust its own admission budget, but not the
        # global cache used to protect the other clients against replays.
        per_identity_history = min(512, max(32, 8192 // len(self.allowed)))
        history_used = sum(owner == peer_identity for _, owner in self._hello_seen.values())
        if (confirmed >= 32 or history_used >= per_identity_history or
                len(self._hello_seen) >= 8192):
            self.rejected_datagrams += 1
            return None
        # IN41 journal rejects known replays before any costly X25519, session
        # eviction or authentication response. Recording is transactional.
        if fresh:
            assert self.fresh_journal is not None
            try:
                accepted = self.fresh_journal.accept(digest, int(time.time()),
                                                     timestamp + FRESH_WINDOW_SECONDS, peer_identity)
            except sqlite3.Error:
                self.rejected_datagrams += 1
                return None
            if not accepted:
                self.rejected_datagrams += 1
                return None
        if len(self.sessions) >= MAX_SESSIONS:
            candidate = next((sid for sid, item in self.sessions.items()
                              if not item.confirmed), None)
            if candidate is None:
                self.rejected_datagrams += 1
                return None
            del self.sessions[candidate]
        try:
            ephemeral = X25519PrivateKey.generate()
            unsigned = (FRESH_PROTOCOL if fresh else PROTOCOL) + REPLY_TAG + sid + ephemeral_pub(ephemeral) + self.public
            reply = unsigned + self.identity.sign((FRESH_SERVER_DOMAIN if fresh else SERVER_DOMAIN) + packet + unsigned)
            secret = _secret(ephemeral, peer_ephemeral, packet + reply)
        except (ValueError, InvalidTag):
            self.rejected_datagrams += 1
            return None
        if self.mailbox_store is not None and hasattr(self.mailbox_store, "mark_udp_hello"):
            # Durable mailbox journals reject previously accepted hellos even
            # after a responder process restart, within the retention window.
            try:
                if not self.mailbox_store.mark_udp_hello(digest):
                    self.rejected_datagrams += 1
                    return None
            except sqlite3.Error:
                self.rejected_datagrams += 1
                return None
        self.sessions[sid] = _ServerSession(LiveSession(secret, sid, "responder"),
                                             address, digest, reply, time.monotonic(),
                                             client_identity=peer_identity)
        self._hello_seen[digest] = (time.monotonic(),peer_identity)
        self.accepted_handshakes += 1
        return reply

    def _data(self, packet: bytes, address: tuple) -> bytes | None:
        if len(packet) < 20:
            self.rejected_datagrams += 1
            return None
        state = self.sessions.get(packet[4:20])
        if state is None or state.address != address:
            self.rejected_datagrams += 1
            return None
        digest = hashlib.sha256(packet).digest()
        if digest in state.acknowledgments:
            self.duplicate_datagrams += 1
            return state.acknowledgments[digest]
        try:
            path, message = state.session.decrypt_packet(packet)
            if path not in (0, 1, 2) or not 1 <= len(message) <= MAX_PAYLOAD:
                raise ValueError("unsupported path or payload")
            if path == 1:
                if not self.accept_synthetic_application:
                    raise ValueError("application mode not enabled")
                # Import lazily so the existing v0.4.0 wire codec stays separate.
                from .native_udp_application import parse_frame
                message_id, payload = parse_frame(message)
                key = (state.client_identity, message_id)
                body_hash = hashlib.sha256(payload).digest()
                if key in self._application_seen:
                    if self._application_seen[key] != body_hash:
                        raise ValueError("application message ID reused with different content")
                    self.application_duplicate_ids += 1
                else:
                    # Acknowledging means received into bounded *memory*, never persisted.
                    self.application_inbox.append((message_id, payload))
                    self._application_seen[key] = body_hash
                    self.application_accepted += 1
                    if len(self._application_seen) > MAX_APPLICATION_DEDUP:
                        self._application_seen.popitem(last=False)
            if path == 2:
                if self.mailbox_store is None:
                    raise ValueError("mailbox path not enabled")
                from .mailbox_wire import handle_request
                mailbox_reply = handle_request(self.mailbox_store, state.client_identity, message)
        except (ValueError, InvalidTag, ReplayError, sqlite3.Error, OSError):
            self.rejected_datagrams += 1
            return None
        # Only a valid AEAD record proves possession of the negotiated session
        # key. A signed but replayed IN40 hello alone must not reserve quota.
        state.confirmed = True
        response = (state.session.encrypt_packet(mailbox_reply, path_id=2) if path == 2 else
                    state.session.encrypt_packet(b"\x01" + hashlib.sha256(message).digest()))
        state.acknowledgments[digest] = response
        if len(state.acknowledgments) > MAX_RECEIPTS:
            state.acknowledgments.popitem(last=False)
        self.accepted_messages += 1
        return response


def serve(sock: socket.socket, responder: NativeResponder, *, stop: threading.Event | None = None,
          max_seconds: float = 0.0) -> None:
    """Run a bounded-memory standalone listener. No forwarding or disk writes."""
    sock.settimeout(0.2)
    end = time.monotonic() + max_seconds if max_seconds else float("inf")
    while not (stop is not None and stop.is_set()) and time.monotonic() < end:
        try:
            packet, addr = sock.recvfrom(MAX_DATAGRAM + 1)
        except socket.timeout:
            continue
        try:
            response = responder.process(packet, addr)
            if response is not None:
                sock.sendto(response, addr)
        except (OSError, sqlite3.Error, ValueError):
            # Never include packet content, keys, or ciphertext in logs.
            logging.getLogger(__name__).exception("UDP request processing failure")


def _percentile(samples: list[float], fraction: float) -> float:
    return sorted(samples)[math.ceil(len(samples) * fraction) - 1]


def native_probe(host: str, port: int, identity: Ed25519PrivateKey,
                 expected_server: bytes, *, samples: int = 30, payload_bytes: int = 256,
                 timeout: float = 0.5, attempts: int = 3,
                 interval_ms: float = 0.0, messages: Sequence[bytes] | None = None,
                 path_id: int = 0, wire_version: int = 40) -> dict[str, Any]:
    if wire_version not in (40, 41):
        raise ValueError("unsupported wire version")
    if not (1 <= samples <= 200 and 1 <= payload_bytes <= MAX_PAYLOAD and
            0.05 <= timeout <= 10 and 1 <= attempts <= 6 and 1 <= port <= 65535
            and 0 <= interval_ms <= 1000):
        raise ValueError("invalid probe limits")
    if path_id not in (0, 1):
        raise ValueError("probe supports only path 0 (synthetic) or 1 (volatile application)")
    if messages is not None and (len(messages) != samples or
                                 any(not isinstance(m, bytes) or not 1 <= len(m) <= MAX_PAYLOAD
                                     for m in messages)):
        raise ValueError("messages must be exactly samples nonempty bounded byte payloads")
    if path_id == 1 and messages is None:
        raise ValueError("application path requires explicit framed messages")
    if len(expected_server) != 32:
        raise ValueError("server public key must be pinned")
    # The endpoint address may be untrusted; server Ed25519 identity is pinned.
    try:
        address = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
    except socket.gaierror as exc:
        raise NativeTransitError("unable to resolve UDP destination") from exc
    sid = secrets.token_bytes(16)
    eph = X25519PrivateKey.generate()
    nonce = secrets.token_bytes(16)
    hello = (hello_packet_v041(identity, expected_server, sid, ephemeral_pub(eph), nonce)
             if wire_version == 41 else hello_packet(identity, expected_server, sid, ephemeral_pub(eph), nonce))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(address)
        sock.settimeout(timeout)
        established = None
        started = time.perf_counter()
        handshake_attempts = 0
        for _ in range(attempts):
            handshake_attempts += 1
            sock.send(hello)
            try:
                response = sock.recv(MAX_DATAGRAM)
            except socket.timeout:
                continue
            reply_protocol = FRESH_PROTOCOL if wire_version == 41 else PROTOCOL
            if len(response) != REPLY_LEN or response[:5] != reply_protocol + REPLY_TAG or response[5:21] != sid:
                raise NativeTransitError("unexpected handshake response")
            server_ephemeral, server_identity = response[21:53], response[53:85]
            if server_identity != expected_server:
                raise NativeTransitError("peer identity mismatch; abort without trusting endpoint")
            try:
                Ed25519PublicKey.from_public_bytes(expected_server).verify(
                    response[-64:], (FRESH_SERVER_DOMAIN if wire_version == 41 else SERVER_DOMAIN) + hello + response[:-64])
                secret = _secret(eph, server_ephemeral, hello + response)
            except (InvalidSignature, ValueError) as exc:
                raise NativeTransitError("server handshake signature invalid") from exc
            established = LiveSession(secret, sid, "initiator")
            break
        if established is None:
            raise NativeTransitError("signed native UDP handshake timed out; check firewall and allowed client")
        handshake_ms = (time.perf_counter() - started) * 1000
        latencies = []
        failed = 0
        late_authenticated_receipts = 0
        ack_timeouts = 0
        completed_digests: set[bytes] = set()
        probe_started = time.perf_counter()
        retransmissions = 0
        first_hash = None
        for i in range(samples):
            if i and interval_ms:
                time.sleep(interval_ms / 1000)
            message = messages[i] if messages is not None else secrets.token_bytes(payload_bytes)
            digest = hashlib.sha256(message).digest()
            if first_hash is None:
                first_hash = digest.hex()
            encoded = established.encrypt_packet(message, path_id=path_id)
            began = time.perf_counter_ns()
            acknowledged = False
            for j in range(attempts):
                if j:
                    retransmissions += 1
                sock.send(encoded)  # byte-exact retry: same nonce/seq, no new encryption
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    sock.settimeout(max(0.001, deadline - time.monotonic()))
                    try:
                        reply = sock.recv(MAX_DATAGRAM)
                    except socket.timeout:
                        break
                    try:
                        path, content = established.decrypt_packet(reply)
                    except (ValueError, InvalidTag, ReplayError):
                        continue  # stale/forged responses cannot count as success
                    if path == 0 and content == b"\x01" + digest:
                        latencies.append((time.perf_counter_ns() - began) / 1_000_000)
                        acknowledged = True
                        break
                    # A delayed, valid receipt for an earlier message can arrive
                    # while awaiting a newer one. It is not an authentication
                    # failure and must not abort the newer message.
                    if path == 0 and len(content) == 33 and content[:1] == b"\x01" \
                            and content[1:] in completed_digests:
                        late_authenticated_receipts += 1
                        continue
                    raise NativeTransitError("authenticated receipt mismatch")
                if not acknowledged:
                    ack_timeouts += 1
                if acknowledged:
                    break
            if not acknowledged:
                failed += 1
            completed_digests.add(digest)
        probe_elapsed_ms = (time.perf_counter() - probe_started) * 1000
        if not latencies:
            raise NativeTransitError("no authenticated native UDP receipts")
        absolute_changes = [abs(b - a) for a, b in zip(latencies, latencies[1:])]
        return {
            "status": "PASS" if failed == 0 else "PARTIAL",
            "transport": "native UDP over IPv4 (NOT SSH, QUIC or VPN)",
            "peer_authentication": "mutually allowlisted / pinned Ed25519 identities",
            "key_agreement": "ephemeral X25519 + transcript-bound HKDF-SHA256",
            "payload_bytes": payload_bytes,
            "requested_messages": samples,
            "release_version": RELEASE_VERSION,
            "application_receipt_scope": "volatile in-memory only" if path_id == 1 else "digest receipt only",
            "wire_version": "IN41 / 0.4.1-fresh" if wire_version == 41 else "IN40 / 0.4.0-alpha (legacy)",
            "handshake_attempts": handshake_attempts,
            "handshake_retransmissions": handshake_attempts - 1,
            "authenticated_receipts": len(latencies),
            "unacknowledged_messages": failed,
            "datagram_retransmissions": retransmissions,
            "ack_timeouts": ack_timeouts,
            "late_authenticated_receipts": late_authenticated_receipts,
            "delivery_ratio": round(len(latencies) / samples, 6),
            "probe_elapsed_ms": round(probe_elapsed_ms, 3),
            "acknowledged_payload_bytes": len(latencies) * payload_bytes,
            "application_goodput_kib_s": round((len(latencies) * payload_bytes / 1024) / (probe_elapsed_ms / 1000), 3),
            "interval_ms": interval_ms,
            "wire_packet_loss": "not measurable exactly; ack timeouts/retries are application-level indicators",
            "handshake_ms": round(handshake_ms, 3),
            "rtt_p50_ms": round(statistics.median(latencies), 3),
            "rtt_p95_ms": round(_percentile(latencies, .95), 3),
            "rtt_min_ms": round(min(latencies), 3),
            "rtt_max_ms": round(max(latencies), 3),
            "successive_rtt_delta_median_ms": round(statistics.median(absolute_changes), 3) if absolute_changes else None,
            "first_message_sha256": first_hash,
            "durability": "none; receiver returns only authenticated digest receipt",
            "session": "expires server-side; per-direction AEAD keys rotate by seq epoch",
            "caution": "Unaudited experimental Python UDP protocol for SYNTHETIC data only. Not a VPN, QUIC, NAT traversal, production data confidentiality, or independently verified infrastructure.",
        }


def local_qualification(*, samples: int = 30, payload_bytes: int = 256) -> dict:
    server_private = Ed25519PrivateKey.generate()
    client_private = Ed25519PrivateKey.generate()
    responder = NativeResponder(server_private, {pub_bytes(client_private)})
    halt = threading.Event()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        host, port = sock.getsockname()
        worker = threading.Thread(target=serve, args=(sock, responder),
                                  kwargs={"stop": halt}, daemon=True)
        worker.start()
        try:
            report = native_probe(host, port, client_private, pub_bytes(server_private),
                                  samples=samples, payload_bytes=payload_bytes)
        finally:
            halt.set()
            worker.join(timeout=2)
        if worker.is_alive():
            raise NativeTransitError("local responder failed to stop")
    report["scope"] = "127.0.0.1 loopback only; NOT cross-host performance"
    report["server_accepted_unique_messages"] = responder.accepted_messages
    return report


def main(argv: list[str] | None = None) -> int:
    from .version import RELEASE_VERSION
    parser = argparse.ArgumentParser(description=f"INNERnet {RELEASE_VERSION} experimental native UDP pilot (IN40/IN41)")
    cmd = parser.add_subparsers(dest="command", required=True)
    init = cmd.add_parser("init-identity", help="create private 0600 Ed25519 seed")
    init.add_argument("--file", type=Path, required=True)
    inspect = cmd.add_parser("show-identity", help="print only public identity")
    inspect.add_argument("--file", type=Path, required=True)
    listener = cmd.add_parser("serve", help="start separate experimental native UDP server")
    listener.add_argument("--identity", type=Path, required=True)
    listener.add_argument("--allow-client", required=True, action="append",
                          help="pinned Ed25519 client public key in hex; repeat for each allowed client")
    listener.add_argument("--bind", default="127.0.0.1")
    listener.add_argument("--port", type=int, default=DEFAULT_PORT)
    listener.add_argument("--acknowledge-public-udp", action="store_true")
    listener.add_argument("--max-seconds", type=float, default=0.0)
    listener.add_argument("--fresh-replay-db", type=Path,
                          help="enable IN41-only signed timestamps and persistent replay journal")
    listener.add_argument("--accept-synthetic-app", action="store_true",
                          help="opt in to volatile synthetic application frames; no persistence")
    probe = cmd.add_parser("probe", help="send synthetic authenticated messages to pinned peer")
    probe.add_argument("--identity", type=Path, required=True)
    probe.add_argument("--server-key", required=True)
    probe.add_argument("--host", required=True)
    probe.add_argument("--port", type=int, default=DEFAULT_PORT)
    probe.add_argument("--samples", type=int, default=30)
    probe.add_argument("--wire-version", choices=[40, 41], type=int, default=40)
    probe.add_argument("--bytes", type=int, default=256)
    probe.add_argument("--timeout", type=float, default=0.5)
    probe.add_argument("--attempts", type=int, default=3)
    probe.add_argument("--interval-ms", type=float, default=0.0,
                       help="synthetic inter-message pacing (0 to 1000 ms)")
    local = cmd.add_parser("local-qualify", help="safe localhost native UDP full qualification")
    local.add_argument("--samples", type=int, default=30)
    local.add_argument("--bytes", type=int, default=256)
    reliable = cmd.add_parser("reliability-qualify",
                              help="isolated loopback fault-injection and concurrent-client suite")
    reliable.add_argument("--samples", type=int, default=12)
    reliable.add_argument("--clients", type=int, default=4)
    reliable.add_argument("--timeout", type=float, default=0.08)
    reliable.add_argument("--attempts", type=int, default=4)
    args = parser.parse_args(argv)
    try:
        if args.command == "init-identity":
            print(json.dumps({"created": True, "file": str(args.file),
                              "public_ed25519": generate_identity_file(args.file),
                              "warning": "NEVER commit/share the seed file"}, indent=2))
        elif args.command == "show-identity":
            print(json.dumps({"public_ed25519": pub_bytes(load_identity(args.file)).hex()}, indent=2))
        elif args.command == "serve":
            if not 1 <= args.port <= 65535 or args.max_seconds < 0:
                raise ValueError("invalid port/duration")
            if args.bind not in ("127.0.0.1", "localhost") and not args.acknowledge_public_udp:
                raise ValueError("public UDP binding requires explicit --acknowledge-public-udp")
            allowed = {parse_public_hex(key) for key in args.allow_client}
            journal = PersistentHelloJournal(args.fresh_replay_db) if args.fresh_replay_db else None
            instance = NativeResponder(load_identity(args.identity), allowed,
                                       accept_synthetic_application=args.accept_synthetic_app,
                                       fresh_journal=journal)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind((args.bind, args.port))
                print(json.dumps({"ready": True, "bind": args.bind,
                                  "udp_port": sock.getsockname()[1],
                                  "public_ed25519": instance.public.hex(),
                                  "allowed_clients": len(allowed),
                                  "synthetic_application_enabled": args.accept_synthetic_app,
                                  "caution": "SYNTHETIC data only; unaudited public listener"}), flush=True)
                serve(sock, instance, max_seconds=args.max_seconds)
        elif args.command == "probe":
            print(json.dumps(native_probe(args.host, args.port, load_identity(args.identity),
                                          parse_public_hex(args.server_key),
                                          samples=args.samples, payload_bytes=args.bytes,
                                          timeout=args.timeout, attempts=args.attempts,
                                          interval_ms=args.interval_ms,
                                          wire_version=args.wire_version), indent=2))
        elif args.command == "reliability-qualify":
            from .native_udp_reliability import reliability_qualification
            report = reliability_qualification(samples=args.samples, clients=args.clients,
                                              timeout=args.timeout, attempts=args.attempts)
            print(json.dumps(report, indent=2))
            if report["status"] != "PASS":
                return 1
        elif args.command == "local-qualify":
            print(json.dumps(local_qualification(samples=args.samples,
                                                 payload_bytes=args.bytes), indent=2))
        return 0
    except (NativeTransitError, OSError, ValueError) as exc:
        print(f"INNERnet native UDP error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
