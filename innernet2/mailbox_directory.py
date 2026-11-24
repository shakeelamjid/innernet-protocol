"""Operator-signed static bootstrap routes for INNERnet 0.5.0-alpha.

Signature establishes publisher authenticity, not topology truth, node uptime,
independence, revocation or globally decentralized discovery.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .native_udp import load_identity, parse_public_hex, pub_bytes

DOMAIN = b"INNERnet/v0.5.0-alpha/static-directory\x00"
VERSION = "IN50-STATIC-1"
MAX_NODES = 64
MAX_ROUTES = 512


class DirectoryError(ValueError):
    pass


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True,
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _check_payload(payload: dict, *, now: int) -> None:
    if not isinstance(payload, dict) or set(payload) != {"version", "created_at", "expires_at", "nodes", "routes"}:
        raise DirectoryError("directory field mismatch")
    if payload["version"] != VERSION:
        raise DirectoryError("directory version unsupported")
    start, end = payload["created_at"], payload["expires_at"]
    if (type(start) is not int or type(end) is not int or
            end <= start or end - start > 7 * 86400 or end <= now or start > now + 300):
        raise DirectoryError("invalid, expired or future-dated directory")
    nodes, routes = payload["nodes"], payload["routes"]
    if not isinstance(nodes, list) or not 1 <= len(nodes) <= MAX_NODES:
        raise DirectoryError("invalid node count")
    if not isinstance(routes, list) or not 1 <= len(routes) <= MAX_ROUTES:
        raise DirectoryError("invalid route count")
    node_ids: set[str] = set()
    keys: set[str] = set()
    for n in nodes:
        if not isinstance(n, dict) or set(n) != {"id", "host", "port", "public_ed25519", "failure_domain"}:
            raise DirectoryError("invalid node fields")
        if not isinstance(n["id"], str) or not 1 <= len(n["id"]) <= 64 or n["id"] in node_ids:
            raise DirectoryError("duplicate or malformed node name")
        if not isinstance(n["host"], str) or not 1 <= len(n["host"]) <= 253 or any(c.isspace() for c in n["host"]):
            raise DirectoryError("invalid host")
        if type(n["port"]) is not int or not 1 <= n["port"] <= 65535:
            raise DirectoryError("invalid port")
        if not isinstance(n["failure_domain"], str) or len(n["failure_domain"]) > 128:
            raise DirectoryError("invalid declared failure domain")
        parse_public_hex(n["public_ed25519"])
        if n["public_ed25519"] in keys:
            raise DirectoryError("same signing key used by multiple nodes")
        keys.add(n["public_ed25519"])
        node_ids.add(n["id"])
    recipients: set[str] = set()
    for r in routes:
        if not isinstance(r, dict) or set(r) != {"recipient_ed25519", "node_id"}:
            raise DirectoryError("invalid route fields")
        if not isinstance(r["recipient_ed25519"], str):
            raise DirectoryError("invalid recipient key")
        parse_public_hex(r["recipient_ed25519"])
        if (not isinstance(r["node_id"], str) or r["recipient_ed25519"] in recipients
                or r["node_id"] not in node_ids):
            raise DirectoryError("duplicate recipient or missing node route")
        recipients.add(r["recipient_ed25519"])


def sign_directory(payload: dict, private_key, *, now: int | None = None) -> dict:
    instant = int(time.time() if now is None else now)
    _check_payload(payload, now=instant)
    signature = private_key.sign(DOMAIN + _canonical(payload)).hex()
    return {"payload": payload, "signature_ed25519": signature,
            "signer_ed25519": pub_bytes(private_key).hex()}


def verify_directory(record: dict, pinned_signer: bytes, *, now: int | None = None) -> dict:
    if not isinstance(record, dict) or set(record) != {"payload", "signature_ed25519", "signer_ed25519"}:
        raise DirectoryError("signed directory wrapper malformed")
    if len(pinned_signer) != 32 or record["signer_ed25519"] != pinned_signer.hex():
        raise DirectoryError("directory publisher not pinned")
    try:
        signature = bytes.fromhex(record["signature_ed25519"])
        if len(signature) != 64:
            raise ValueError("signature size")
        Ed25519PublicKey.from_public_bytes(pinned_signer).verify(
            signature, DOMAIN + _canonical(record["payload"]))
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise DirectoryError("signed directory authenticity failed") from exc
    _check_payload(record["payload"], now=int(time.time() if now is None else now))
    return record["payload"]


def find_route(payload: dict, recipient: bytes) -> dict:
    if len(recipient) != 32:
        raise DirectoryError("invalid recipient key")
    for route in payload["routes"]:
        if route["recipient_ed25519"] == recipient.hex():
            return next(n for n in payload["nodes"] if n["id"] == route["node_id"])
    raise DirectoryError("recipient not present in signed bootstrap directory")


def load_verified(path: str | Path, signer_hex: str) -> dict:
    data = Path(path).read_bytes()
    if len(data) > 200_000:
        raise DirectoryError("directory too large")
    return verify_directory(json.loads(data), parse_public_hex(signer_hex))
