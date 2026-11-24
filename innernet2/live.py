"""Experimental INNERnet Live packet codec, NOT an operating-system VPN.

Uses an out-of-band authenticated, high-entropy 32-byte session secret.
No key exchange, routing, transport, NAT traversal, anonymity or real VPN yet.
This intentionally separates per-packet security from the user-mode network stack.
"""
from __future__ import annotations

import hmac
import struct

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .crypto import DOMAIN, derive, deinterleave, interleave

MAGIC = b"INL2"
HEADER_FORMAT = "!4s16sIQBBH"
HEADER_LEN = struct.calcsize(HEADER_FORMAT)
MAX_PAYLOAD = 1152
MIX_CELL = 8
REKEY_INTERVAL = 65536
WINDOW_BITS = 1024
MAX_SKIP = 1_000_000


class ReplayError(ValueError):
    pass


class ReplayWindow:
    def __init__(self):
        self.highest = -1
        self.bitmap = 0

    def check(self, seq: int):
        if not 0 <= seq < 2**64:
            raise ReplayError("invalid sequence")
        if self.highest >= 0 and seq > self.highest + MAX_SKIP:
            raise ReplayError("excessive sequence jump")
        if self.highest >= 0 and self.highest - seq >= WINDOW_BITS:
            raise ReplayError("packet too old")
        offset = self.highest - seq
        if offset >= 0 and self.bitmap & (1 << offset):
            raise ReplayError("replayed packet")

    def commit(self, seq: int):
        # Call ONLY after successful AEAD authentication.
        self.check(seq)
        if seq > self.highest:
            shift = seq - self.highest
            self.bitmap = ((self.bitmap << shift) | 1) & ((1 << WINDOW_BITS) - 1)
            self.highest = seq
        else:
            self.bitmap |= 1 << (self.highest - seq)


class LiveSession:
    """Pre-established symmetric secret, two independent traffic directions.

    role='initiator' or 'responder'. For each epoch, one derived AEAD key per
    direction; packet nonces are distinct 64-bit sequence values.
    """
    def __init__(self, session_secret: bytes, session_id: bytes, role: str, mixing: bool = True):
        if len(session_secret) != 32 or len(session_id) != 16 or role not in ("initiator", "responder"):
            raise ValueError("invalid live session parameters")
        self.secret = session_secret
        self.session_id = session_id
        self.role = role
        self.mixing = mixing
        self.send_seq = 0
        self.received = ReplayWindow()

    def _role_direction(self, sending: bool) -> str:
        if (self.role == "initiator") == sending:
            return "initiator-to-responder"
        return "responder-to-initiator"

    def _key(self, direction: str, epoch: int, purpose: str) -> bytes:
        # Domain-separated by session, direction, epoch and purpose.
        return derive(self.secret, f"live/{purpose}/{self.session_id.hex()}/{direction}/{epoch}")

    def _mix_key(self, direction: str, epoch: int, seq: int) -> bytes:
        return hmac.digest(self._key(direction, epoch, "mix"), seq.to_bytes(8, "big"), "sha256")

    def encrypt_packet(self, plaintext: bytes, path_id: int = 0) -> bytes:
        if len(plaintext) > MAX_PAYLOAD or not 0 <= path_id <= 255:
            raise ValueError("invalid packet payload or path")
        seq = self.send_seq
        if seq >= REKEY_INTERVAL * (2**32):
            raise OverflowError("session epoch limit exhausted; re-handshake required")
        epoch = seq // REKEY_INTERVAL
        direction = self._role_direction(True)
        flags = int(self.mixing)
        cipher_len = len(plaintext) + 16
        header = struct.pack(HEADER_FORMAT, MAGIC, self.session_id, epoch, seq, path_id, flags, cipher_len)
        key = self._key(direction, epoch, "aead")
        nonce = b"INL2" + seq.to_bytes(8, "big")
        ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, header)
        if self.mixing:
            ciphertext = interleave(ciphertext, self._mix_key(direction, epoch, seq), MIX_CELL)
        self.send_seq += 1
        return header + ciphertext

    def decrypt_packet(self, packet: bytes) -> tuple[int, bytes]:
        if len(packet) < HEADER_LEN + 16:
            raise ValueError("truncated live packet")
        header, payload = packet[:HEADER_LEN], packet[HEADER_LEN:]
        magic, session, epoch, seq, path_id, flags, cipher_len = struct.unpack(HEADER_FORMAT, header)
        if magic != MAGIC or session != self.session_id or flags not in (0, 1):
            raise ValueError("unsupported packet header")
        if epoch != seq // REKEY_INTERVAL or not 16 <= cipher_len <= MAX_PAYLOAD + 16:
            raise ValueError("invalid packet epoch or length")
        if len(payload) != ((cipher_len + MIX_CELL - 1)//MIX_CELL * MIX_CELL if flags else cipher_len):
            raise ValueError("invalid packet body length")
        self.received.check(seq)
        direction = self._role_direction(False)
        if flags:
            payload = deinterleave(payload, self._mix_key(direction, epoch, seq), MIX_CELL, cipher_len)
        nonce = b"INL2" + seq.to_bytes(8, "big")
        plain = ChaCha20Poly1305(self._key(direction, epoch, "aead")).decrypt(nonce, payload, header)
        self.received.commit(seq)
        return path_id, plain
