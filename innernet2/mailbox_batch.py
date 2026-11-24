"""IO70 bounded sequential authenticated UDP session reuse.

Compatible with the IN40 handshake and IE60 mailbox. Request frames use the
same IM50 format. Reconnects use a fresh X25519 handshake and retain the exact
request ID so SQLite mutations remain idempotent after uncertain acknowledgements.
"""
from __future__ import annotations

import secrets
import socket
import time

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .live import LiveSession, ReplayError
from .native_udp import (PROTOCOL, REPLY_TAG, REPLY_LEN, SERVER_DOMAIN, MAX_DATAGRAM,
                         NativeTransitError, _secret, ephemeral_pub, hello_packet)
from .mailbox_wire import PATH_ID, parse_response


class BatchMailboxClient:
    """100 sequential RPCs per authenticated session, then a fresh key exchange."""

    def __init__(self, host: str, port: int, identity: Ed25519PrivateKey,
                 server_identity: bytes, *, timeout: float = .5,
                 max_requests_per_session: int = 100):
        if (len(server_identity) != 32 or not 1 <= port <= 65535
                or not 0.05 <= timeout <= 10 or not 1 <= max_requests_per_session <= 128):
            raise ValueError("invalid batch mailbox parameters")
        self.address = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
        self.identity = identity
        self.server_identity = server_identity
        self.timeout = timeout
        self.max_requests = max_requests_per_session
        self.session: LiveSession | None = None
        self.sock: socket.socket | None = None
        self.session_started = 0.0
        self.requests = 0
        self.handshakes = 0
        self.handshake_retries = 0
        self.data_retries = 0
        self.reconnections = 0

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        if self.sock is not None:
            self.sock.close()
        self.sock = None
        self.session = None

    def _connect(self):
        self.close()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(self.address)
        sock.settimeout(self.timeout)
        try:
            for attempt in range(3):
                sid = secrets.token_bytes(16)
                eph = X25519PrivateKey.generate()
                hello = hello_packet(self.identity, self.server_identity, sid,
                                     ephemeral_pub(eph), secrets.token_bytes(16))
                # When a server reply is lost, resend the *same* signed HELLO.
                for tries in range(3):
                    if tries:
                        self.handshake_retries += 1
                    try:
                        sock.send(hello)
                        reply = sock.recv(MAX_DATAGRAM)
                    except (socket.timeout, ConnectionRefusedError, OSError):
                        continue
                    if len(reply) != REPLY_LEN or reply[:5] != PROTOCOL + REPLY_TAG or reply[5:21] != sid:
                        continue
                    if reply[53:85] != self.server_identity:
                        raise NativeTransitError("unexpected mailbox server identity")
                    try:
                        Ed25519PublicKey.from_public_bytes(self.server_identity).verify(
                            reply[-64:], SERVER_DOMAIN + hello + reply[:-64])
                        secret = _secret(eph, reply[21:53], hello + reply)
                    except (InvalidSignature, ValueError) as exc:
                        raise NativeTransitError("mailbox handshake verification failed") from exc
                    self.session = LiveSession(secret, sid, "initiator")
                    self.session_started = time.monotonic()
                    self.requests = 0
                    self.sock = sock
                    self.handshakes += 1
                    return
            raise NativeTransitError("batch mailbox handshake timed out")
        except BaseException:
            sock.close()
            raise

    def call(self, frame: bytes) -> tuple[str, bytes]:
        if not isinstance(frame, bytes) or not 21 <= len(frame) <= 1152:
            raise ValueError("invalid mailbox request")
        rid = frame[5:21]
        for reconnect in range(2):
            if (self.session is None or self.requests >= self.max_requests
                    or time.monotonic() - self.session_started >= 50):
                self._connect()
            assert self.session is not None and self.sock is not None
            encrypted = self.session.encrypt_packet(frame, path_id=PATH_ID)
            for attempt in range(3):
                if attempt:
                    self.data_retries += 1
                try:
                    self.sock.send(encrypted)
                except (ConnectionRefusedError, OSError):
                    continue
                deadline = time.monotonic() + self.timeout
                while time.monotonic() < deadline:
                    self.sock.settimeout(max(.001, deadline - time.monotonic()))
                    try:
                        response = self.sock.recv(MAX_DATAGRAM)
                    except (socket.timeout, ConnectionRefusedError, OSError):
                        break
                    try:
                        path, clear = self.session.decrypt_packet(response)
                    except (InvalidTag, ReplayError, ValueError):
                        continue
                    if path != PATH_ID:
                        continue
                    try:
                        code, data = parse_response(clear, rid)
                    except ValueError:
                        continue
                    self.requests += 1
                    return code, data
            self.reconnections += 1
            self.close()
        raise NativeTransitError("authenticated batch mailbox request timed out after reconnect")

    def metrics(self) -> dict:
        return {"authenticated_handshakes": self.handshakes,
                "handshake_retransmissions": self.handshake_retries,
                "data_retransmissions": self.data_retries,
                "session_reconnections_after_timeout": self.reconnections}
