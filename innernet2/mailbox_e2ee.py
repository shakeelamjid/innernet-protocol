"""Experimental IE60 recipient-only message encryption for the IN50 mailbox.

This is a documented research profile, NOT audited E2EE or a substitute for a
reviewed group-messaging protocol. Forward secrecy on long-term key compromise,
metadata privacy, key transparency and multi-device support are not provided.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import struct
import time

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .native_udp import pub_bytes, parse_public_hex
from .mailbox_store import MAX_BODY, MAX_TTL, MIN_TTL

MAGIC = b"IE60"
BUNDLE_VERSION = "IE60-KEY-1"
BUNDLE_DOMAIN = b"INNERnet/IE60/recipient-bundle\x00"
SIGN_DOMAIN = b"INNERnet/IE60/envelope\x00"
KDF_DOMAIN = b"INNERnet/IE60/X25519-HKDF-SHA256\x00"
# 4 magic, 32 sender, 32 recipient, 16 id, 32 ephemeral, 12 nonce,
# 8 created, 8 expires, >=17 encrypted bytes, 64 sender signature.
HEADER_LEN = 144
MIN_LEN = HEADER_LEN + 17 + 64
MAX_TEXT = MAX_BODY - HEADER_LEN - 16 - 64


class E2EEError(ValueError):
    """Invalid/expired/mismatched recipient material or ciphertext."""


def canonical(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _new_secret(path: Path, raw: bytes) -> None:
    path = path.expanduser().absolute()
    if path.exists() or path.is_symlink() or path.parent.is_symlink():
        raise E2EEError("refusing to overwrite existing private key or symlink")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.stat().st_mode & 0o077:
        raise E2EEError("private key directory must be owner-only (0700)")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def load_recipient_secret(path: Path) -> X25519PrivateKey:
    path = path.expanduser().absolute()
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise E2EEError("private recipient key missing or unsafe (expected 0600)")
    raw = path.read_bytes()
    if len(raw) != 32:
        raise E2EEError("recipient key must be exactly 32 bytes")
    return X25519PrivateKey.from_private_bytes(raw)


def generate_bundle(identity: Ed25519PrivateKey, secret_path: Path, *, ttl: int = 86400,
                    now: int | None = None) -> dict:
    if not 60 <= ttl <= 7 * 86400:
        raise E2EEError("recipient bundle TTL outside 60 seconds to 7 days")
    instant = int(time.time()) if now is None else now
    private = X25519PrivateKey.generate()
    key = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    payload = {"version": BUNDLE_VERSION, "identity_ed25519": pub_bytes(identity).hex(),
               "encryption_x25519": key.hex(), "created_at": instant,
               "expires_at": instant + ttl}
    signed = {"payload": payload, "signature_ed25519": identity.sign(BUNDLE_DOMAIN + canonical(payload)).hex()}
    _new_secret(secret_path, private.private_bytes(serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw, serialization.NoEncryption()))
    return signed


def verify_bundle(bundle: dict, expected_identity: bytes, *, now: int | None = None) -> bytes:
    instant = int(time.time()) if now is None else now
    try:
        if set(bundle) != {"payload", "signature_ed25519"}:
            raise ValueError("wrapper fields")
        p = bundle["payload"]
        if set(p) != {"version", "identity_ed25519", "encryption_x25519", "created_at", "expires_at"}:
            raise ValueError("bundle fields")
        if p["version"] != BUNDLE_VERSION or p["identity_ed25519"] != expected_identity.hex():
            raise ValueError("recipient identity mismatch")
        if type(p["created_at"]) is not int or type(p["expires_at"]) is not int:
            raise ValueError("timestamp type")
        if not (p["created_at"] <= instant + 300 and instant < p["expires_at"]
                and 60 <= p["expires_at"] - p["created_at"] <= 7 * 86400):
            raise ValueError("expired or invalid bundle")
        pub = parse_public_hex(p["encryption_x25519"])
        sig = bytes.fromhex(bundle["signature_ed25519"])
        if len(sig) != 64:
            raise ValueError("signature length")
        Ed25519PublicKey.from_public_bytes(expected_identity).verify(sig, BUNDLE_DOMAIN + canonical(p))
        return pub
    except (KeyError, ValueError, TypeError, InvalidSignature, AttributeError) as exc:
        raise E2EEError("recipient encryption bundle not valid for pinned identity") from exc


def _derive(private: X25519PrivateKey, public: bytes, header: bytes) -> bytes:
    try:
        shared = private.exchange(X25519PublicKey.from_public_bytes(public))
    except ValueError as exc:
        raise E2EEError("invalid X25519 peer public key") from exc
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=hashlib.sha256(header).digest(), info=KDF_DOMAIN).derive(shared)


def seal_message(sender: Ed25519PrivateKey, bundle: dict, message_id: bytes,
                 plaintext: bytes, *, expected_recipient: bytes, ttl: int = 3600, now: int | None = None) -> bytes:
    if len(message_id) != 16 or not isinstance(plaintext, bytes) or not plaintext.startswith(b"SYNTHETIC:"):
        raise E2EEError("only bounded SYNTHETIC: test messages with 16-byte IDs")
    if not 1 <= len(plaintext) <= MAX_TEXT or not MIN_TTL <= ttl <= MAX_TTL:
        raise E2EEError("message size or TTL outside limits")
    instant = int(time.time()) if now is None else now
    if not isinstance(expected_recipient, bytes) or len(expected_recipient) != 32:
        raise E2EEError("explicit independently pinned recipient Ed25519 key required")
    identity = expected_recipient
    recipient_pub = verify_bundle(bundle, identity, now=instant)
    ephemeral = X25519PrivateKey.generate()
    eph_pub = ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    nonce = secrets.token_bytes(12)
    header = (MAGIC + pub_bytes(sender) + identity + message_id + eph_pub + nonce
              + struct.pack(">QQ", instant, instant + ttl))
    ciphertext = ChaCha20Poly1305(_derive(ephemeral, recipient_pub, header)).encrypt(nonce, plaintext, header)
    signed_payload = header + ciphertext
    result = signed_payload + sender.sign(SIGN_DOMAIN + signed_payload)
    if len(result) > MAX_BODY:
        raise E2EEError("encrypted envelope exceeds mailbox limit")
    return result


def inspect_envelope(envelope: bytes, *, sender: bytes | None = None,
                     recipient: bytes | None = None, message_id: bytes | None = None,
                     ttl: int | None = None, now: int | None = None) -> dict:
    instant = int(time.time()) if now is None else now
    if not isinstance(envelope, bytes) or not MIN_LEN <= len(envelope) <= MAX_BODY or envelope[:4] != MAGIC:
        raise E2EEError("not a valid IE60 encrypted envelope")
    from_sender, to_recipient, mid = envelope[4:36], envelope[36:68], envelope[68:84]
    created, expires = struct.unpack(">QQ", envelope[128:144])
    if ((sender is not None and sender != from_sender) or
        (recipient is not None and recipient != to_recipient) or
        (message_id is not None and message_id != mid)):
        raise E2EEError("envelope metadata is not bound to mailbox request")
    if not (created <= instant + 300 and expires > instant and MIN_TTL <= expires-created <= MAX_TTL):
        raise E2EEError("envelope expired or timestamps outside limits")
    if ttl is not None and (ttl < MIN_TTL or ttl > MAX_TTL or ttl > expires - instant + 2):
        raise E2EEError("mailbox TTL would exceed signed envelope lifetime")
    try:
        Ed25519PublicKey.from_public_bytes(from_sender).verify(
            envelope[-64:], SIGN_DOMAIN + envelope[:-64])
    except (InvalidSignature, ValueError) as exc:
        raise E2EEError("sender envelope signature invalid") from exc
    return {"sender": from_sender, "recipient": to_recipient, "message_id": mid,
            "created_at": created, "expires_at": expires}


def open_message(recipient_identity: Ed25519PrivateKey, recipient_private: X25519PrivateKey,
                 envelope: bytes, *, expected_sender: bytes | None = None,
                 expected_message_id: bytes | None = None, now: int | None = None) -> bytes:
    inspect_envelope(envelope, sender=expected_sender, recipient=pub_bytes(recipient_identity),
                     message_id=expected_message_id, now=now)
    header, ciphertext = envelope[:HEADER_LEN], envelope[HEADER_LEN:-64]
    nonce = header[116:128]
    try:
        clear = ChaCha20Poly1305(_derive(recipient_private, header[84:116], header)).decrypt(nonce, ciphertext, header)
    except (ValueError, InvalidTag) as exc:
        raise E2EEError("recipient decryption/authentication failed") from exc
    if not clear.startswith(b"SYNTHETIC:"):
        raise E2EEError("decrypted content is not synthetic test data")
    return clear
