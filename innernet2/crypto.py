"""INNERnet v0.2 cryptographic envelope. Research reference, NOT audited.

256-bit uniformly random per-object read capability, domain-separated HKDF,
ChaCha20-Poly1305 per chunk, signed public discovery records.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PREFIX = "inn2_"
DOMAIN = b"INNERnet/research-v0.2/"


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False, ensure_ascii=True).encode("utf-8")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def derive(root: bytes, purpose: str, length: int = 32) -> bytes:
    if len(root) != 32 or not re.fullmatch(r"[a-z0-9/_.-]+", purpose):
        raise ValueError("invalid key-derivation parameters")
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None,
                info=DOMAIN + purpose.encode("ascii")).derive(root)


def new_root() -> bytes:
    return secrets.token_bytes(32)


def encode_root(root: bytes) -> str:
    if len(root) != 32:
        raise ValueError("root must be 32 bytes")
    return PREFIX + base64.urlsafe_b64encode(root).rstrip(b"=").decode("ascii")


def parse_root(value: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"inn2_[A-Za-z0-9_-]{43}", value):
        raise ValueError("invalid v0.2 read capability")
    root = base64.urlsafe_b64decode(value[len(PREFIX):] + "=")
    if len(root) != 32 or encode_root(root) != value:
        raise ValueError("noncanonical read capability")
    return root


# Version 3: a reader receives an encryption root and a *public* directory key.
# The directory writer holds an independently generated Ed25519 private seed.
# IMPORTANT: legacy inn2_ capabilities still derive signing authority and cannot
# be retroactively downgraded into read-only capabilities.
READ_V3_PREFIX = "inn3_"
ADMIN_V3_PREFIX = "inna_"


def _encode32(value: bytes) -> str:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError("expected 32 bytes")
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode32(value: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        raise ValueError("invalid encoded key")
    raw = base64.urlsafe_b64decode(value + "=")
    if len(raw) != 32 or _encode32(raw) != value:
        raise ValueError("noncanonical encoded key")
    return raw


def new_v3_capabilities() -> tuple[str, str]:
    """Returns (read capability, separate admin seed). Never log the admin seed."""
    root = new_root()
    administrator = Ed25519PrivateKey.generate()
    seed = administrator.private_bytes(serialization.Encoding.Raw,
                                      serialization.PrivateFormat.Raw,
                                      serialization.NoEncryption())
    pub = public_key_bytes(administrator.public_key())
    return READ_V3_PREFIX + _encode32(root) + "." + _encode32(pub), ADMIN_V3_PREFIX + _encode32(seed)


def parse_read_capability(value: str) -> tuple[bytes, str, bool]:
    """Return (encryption root, lookup identifier, is_v3). Read-only for v3."""
    if isinstance(value, str) and value.startswith(READ_V3_PREFIX):
        parts = value[len(READ_V3_PREFIX):].split(".")
        if len(parts) != 2:
            raise ValueError("malformed v3 reader capability")
        root, pub = _decode32(parts[0]), _decode32(parts[1])
        # A valid Ed25519 public point encoding is required by the verifier.
        Ed25519PublicKey.from_public_bytes(pub)
        return root, lookup_id_from_public(pub), True
    root = parse_root(value)
    return root, root_lookup(root), False


def v3_admin_sign(admin_capability: str, entry: dict, read_capability: str) -> dict:
    if not isinstance(admin_capability, str) or not admin_capability.startswith(ADMIN_V3_PREFIX):
        raise ValueError("v3 directory update requires an administrator capability")
    seed = _decode32(admin_capability[len(ADMIN_V3_PREFIX):])
    key = Ed25519PrivateKey.from_private_bytes(seed)
    root, lookup, is_v3 = parse_read_capability(read_capability)
    if not is_v3 or lookup_id_from_public(public_key_bytes(key.public_key())) != lookup:
        raise ValueError("administrator key does not match reader directory")
    unsigned = dict(entry, public_key=public_key_bytes(key.public_key()).hex())
    unsigned.pop("signature", None)
    unsigned["signature"] = key.sign(canonical(unsigned)).hex()
    return unsigned


def public_key_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def signing_key(root: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(derive(root, "directory/signing"))


def lookup_id_from_public(pub: bytes) -> str:
    if len(pub) != 32:
        raise ValueError("incorrect directory key length")
    return digest(DOMAIN + b"directory/lookup/" + pub)


def root_lookup(root: bytes) -> str:
    return lookup_id_from_public(public_key_bytes(signing_key(root).public_key()))


def sign_directory(root: bytes, entry: dict) -> dict:
    key = signing_key(root)
    raw_pub = public_key_bytes(key.public_key())
    unsigned = dict(entry, public_key=raw_pub.hex())
    unsigned.pop("signature", None)
    unsigned["signature"] = key.sign(canonical(unsigned)).hex()
    return unsigned


def verify_directory(lookup: str, entry: dict) -> bool:
    try:
        if not isinstance(entry, dict):
            return False
        pub = bytes.fromhex(entry["public_key"])
        signature = bytes.fromhex(entry["signature"])
        if lookup_id_from_public(pub) != lookup or len(signature) != 64:
            return False
        unsigned = dict(entry)
        unsigned.pop("signature")
        Ed25519PublicKey.from_public_bytes(pub).verify(signature, canonical(unsigned))
        return True
    except (KeyError, TypeError, ValueError, InvalidSignature):
        return False


def _chunk_key(root: bytes, object_id: bytes) -> bytes:
    # Bind the AEAD key to the object ID so that a root accidentally reused
    # across objects still yields a DISTINCT key per object. Combined with the
    # per-index nonce this makes (key, nonce) reuse impossible without a
    # 128-bit object-ID collision, closing the HTTP-v3 low-level reuse hole
    # documented in SECURITY.md #1 rather than merely warning against it.
    return derive(root, "data/aead/v2/" + object_id.hex())


def encrypt_chunk(root: bytes, object_id: bytes, index: int, plaintext: bytes) -> bytes:
    if len(object_id) != 16 or not 0 <= index < 2**32 or len(plaintext) > 2**21:
        raise ValueError("invalid data chunk")
    key = _chunk_key(root, object_id)
    nonce = b"INN2" + index.to_bytes(8, "big")
    aad = DOMAIN + b"data/" + object_id + index.to_bytes(8, "big") + len(plaintext).to_bytes(4, "big")
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def decrypt_chunk(root: bytes, object_id: bytes, index: int, ciphertext: bytes, expected_plain_size: int) -> bytes:
    if len(object_id) != 16 or not 0 <= index < 2**32 or not 0 <= expected_plain_size <= 2**21:
        raise ValueError("invalid chunk envelope")
    nonce = b"INN2" + index.to_bytes(8, "big")
    aad = DOMAIN + b"data/" + object_id + index.to_bytes(8, "big") + expected_plain_size.to_bytes(4, "big")
    return ChaCha20Poly1305(_chunk_key(root, object_id)).decrypt(nonce, ciphertext, aad)


def encrypt_metadata(root: bytes, manifest: dict, sequence: int = 0) -> bytes:
    if not 0 <= sequence < 2**32:
        raise ValueError("invalid metadata generation")
    # Each signed manifest generation uses a distinct, domain-separated AEAD key.
    nonce = b"INNMETA00000"  # 12 bytes, safe ONLY because each sequence has a distinct key.
    version = sequence.to_bytes(4, "big")
    return ChaCha20Poly1305(derive(root, f"metadata/aead/{sequence}")).encrypt(
        nonce, canonical(manifest), DOMAIN + b"metadata" + version)


def decrypt_metadata(root: bytes, ciphertext: bytes, sequence: int = 0) -> dict:
    if not 0 <= sequence < 2**32:
        raise ValueError("invalid metadata generation")
    nonce = b"INNMETA00000"
    raw = ChaCha20Poly1305(derive(root, f"metadata/aead/{sequence}")).decrypt(
        nonce, ciphertext, DOMAIN + b"metadata" + sequence.to_bytes(4, "big"))
    if len(raw) > 8_000_000:
        raise ValueError("metadata exceeds limit")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("metadata must be a JSON object")
    return value


def keyed_permutation(count: int, key: bytes) -> list[int]:
    """Bounded per-stripe Fisher-Yates over keyed HMAC draws (NOT a new cipher)."""
    if not (0 <= count <= 65536):
        raise ValueError("too many cells")
    perm = list(range(count))
    ctr = 0
    for i in range(count - 1, 0, -1):
        limit = (1 << 64) - (1 << 64) % (i + 1)
        while True:
            ctr += 1
            r = int.from_bytes(hmac.digest(key, ctr.to_bytes(8, "big"), "sha256")[:8], "big")
            if r < limit:
                break
        j = r % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    return perm


def interleave(data: bytes, key: bytes, cell: int) -> bytes:
    if cell < 1 or len(data) > 2**24:
        raise ValueError("invalid stripe")
    count = (len(data) + cell - 1) // cell
    padded = data.ljust(count * cell, b"\0")
    return b"".join(padded[i * cell:(i + 1) * cell] for i in keyed_permutation(count, key))


def deinterleave(mixed: bytes, key: bytes, cell: int, cipher_len: int) -> bytes:
    if cell < 1 or len(mixed) % cell or not 0 <= cipher_len <= len(mixed):
        raise ValueError("invalid stripe envelope")
    output = bytearray(len(mixed))
    for at, before in enumerate(keyed_permutation(len(mixed) // cell, key)):
        output[before * cell:(before + 1) * cell] = mixed[at * cell:(at + 1) * cell]
    if any(output[cipher_len:]):
        raise ValueError("noncanonical padding in interleaved data")
    return bytes(output[:cipher_len])
