"""Read-only, operator-pinned HTTP peer auditing for the INNERnet v2 pilot.

This verifies cryptographic node identity, the freshness and Ed25519 signature
of its storage advertisement, and public fragment retrieval. It is not storage
proof, independent ownership certification, or decentralized discovery.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import canonical
from .network import HEX, NODE_PATTERN, DOMAIN_PATTERN, _check_url

MAX_JSON_BYTES = 16_384
MAX_FRAGMENT_BYTES = 4 * 1024 * 1024


class AuditError(ValueError):
    """A remote node did not satisfy the signed-identity checks."""


def _fetch_json(client: httpx.Client, url: str) -> dict[str, Any]:
    # Limit response BEFORE decoding JSON. Disable redirects in the CLI client.
    with client.stream("GET", url, headers={"Accept": "application/json"}) as response:
        response.raise_for_status()
        buffer = bytearray()
        for chunk in response.iter_bytes(4096):
            buffer.extend(chunk)
            if len(buffer) > MAX_JSON_BYTES:
                raise AuditError("node JSON response exceeds 16 KiB")
    result = json.loads(buffer)
    if not isinstance(result, dict):
        raise AuditError("node returned non-object JSON")
    return result


def validate_registry_entry(entry: dict) -> dict:
    if not isinstance(entry, dict):
        raise AuditError("peer entry is not an object")
    node_id = entry.get("id")
    url = entry.get("url")
    pub = entry.get("public_key")
    if not isinstance(node_id, str) or not NODE_PATTERN.fullmatch(node_id):
        raise AuditError("invalid peer ID")
    if not isinstance(url, str):
        raise AuditError("missing peer URL")
    try:
        _check_url(url)
    except ValueError as exc:
        raise AuditError(f"unsafe peer URL: {exc}") from exc
    if not isinstance(pub, str) or not re.fullmatch(r"[0-9a-f]{64}", pub):
        raise AuditError("invalid pinned Ed25519 public key")
    failure_domain = entry.get("failure_domain")
    if failure_domain is not None and (not isinstance(failure_domain, str)
            or not DOMAIN_PATTERN.fullmatch(failure_domain)):
        raise AuditError("invalid failure_domain")
    result = {"id": node_id, "url": url.rstrip("/"), "public_key": pub}
    if failure_domain is not None:
        result["failure_domain"] = failure_domain
    return result


def audit_node(entry: dict, client: httpx.Client, *, now: int | None = None,
               sample_sha256: str | None = None) -> dict:
    """Verify a pinned node's read-only public endpoints; raises on failure.

    sample_sha256, if given, verifies public ciphertext bytes hash to their CID.
    Nothing is written to the remote node, and no upload tokens are requested.
    """
    node = validate_registry_entry(entry)
    now = int(time.time()) if now is None else now
    base = node["url"]
    info = _fetch_json(client, base + "/.well-known/innernet-node")
    if (info.get("node_id") != node["id"]
            or info.get("public_key") != node["public_key"]
            or type(info.get("protocol_version")) is not int or info["protocol_version"] != 2
            or info.get("public_read") is not True
            or type(info.get("max_fragment_bytes")) is not int
            or not 0 < info["max_fragment_bytes"] <= MAX_FRAGMENT_BYTES):
        raise AuditError("identity endpoint does not match pinned peer or protocol capabilities")
    offer = _fetch_json(client, base + "/v2/offer")
    signature_hex = offer.get("signature")
    if not isinstance(signature_hex, str) or not re.fullmatch(r"[0-9a-f]{128}", signature_hex):
        raise AuditError("signed storage offer missing valid signature encoding")
    unsigned = dict(offer)
    unsigned.pop("signature")
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(node["public_key"]))
        key.verify(bytes.fromhex(signature_hex), canonical(unsigned))
    except (ValueError, InvalidSignature) as exc:
        raise AuditError("storage offer signature verification failed") from exc
    if (offer.get("node_id") != node["id"] or offer.get("public_key") != node["public_key"]
            or type(offer.get("protocol_version")) is not int or offer["protocol_version"] != 2):
        raise AuditError("signed storage offer is for a different peer or protocol")
    expiry = offer.get("expires_at_unix")
    if type(expiry) is not int or expiry <= now - 10 or expiry > now + 300:
        raise AuditError("storage offer is expired or has an implausible expiry")
    capacity = offer.get("capacity_bytes")
    available = offer.get("available_bytes_reported")
    max_shard = offer.get("max_fragment_bytes")
    if (type(capacity) is not int or type(available) is not int
            or type(max_shard) is not int or capacity < 0
            or not 0 <= available <= capacity or not 0 < max_shard <= MAX_FRAGMENT_BYTES):
        raise AuditError("signed storage offer has invalid capacity or fragment limits")
    if sample_sha256 is not None:
        if not HEX.fullmatch(sample_sha256):
            raise AuditError("invalid sample SHA-256 digest")
        hasher = hashlib.sha256()
        received = 0
        with client.stream("GET", base + "/v2/fragments/" + sample_sha256) as response:
            response.raise_for_status()
            for chunk in response.iter_bytes(65536):
                received += len(chunk)
                if received > max_shard:
                    raise AuditError("sample fragment exceeds advertised maximum")
                hasher.update(chunk)
        if hasher.hexdigest() != sample_sha256:
            raise AuditError("public sample fragment does not match its SHA-256 digest")
    else:
        received = None
    return {"node_id": node["id"], "url": base, "identity_verified": True,
            "offer_signature_verified": True, "offer_expires_at_unix": expiry,
            "capacity_bytes_reported": capacity, "available_bytes_reported": available,
            "public_sample_verified": sample_sha256 is not None, "public_sample_bytes": received,
            "warning": "Offers report capacity, not proof of continuous retention or operator independence."}


def audit_registry(public_registry: dict, client: httpx.Client, *, now: int | None = None) -> dict:
    if not isinstance(public_registry, dict) or not isinstance(public_registry.get("nodes"), list):
        raise AuditError("registry must contain a nodes list")
    entries = public_registry["nodes"]
    if len(entries) > 256:
        raise AuditError("too many peers for the audit")
    reports = []
    seen_ids, seen_urls, seen_keys = set(), set(), set()
    by_host: dict[str, int] = {}
    by_domain: dict[str, int] = {}
    for i, raw in enumerate(entries):
        try:
            entry = validate_registry_entry(raw)
            if entry["id"] in seen_ids or entry["url"] in seen_urls or entry["public_key"] in seen_keys:
                raise AuditError("duplicate ID, URL, or public key in registry")
            seen_ids.add(entry["id"])
            seen_urls.add(entry["url"])
            seen_keys.add(entry["public_key"])
            hostname = urlsplit(entry["url"]).hostname or ""
            by_host[hostname] = by_host.get(hostname, 0) + 1
            if entry.get("failure_domain"):
                dom = entry["failure_domain"]
                by_domain[dom] = by_domain.get(dom, 0) + 1
            report = audit_node(entry, client, now=now)
            report["ok"] = True
        except (AuditError, ValueError, KeyError, httpx.HTTPError, json.JSONDecodeError) as exc:
            report = {"index": i, "node_id": raw.get("id") if isinstance(raw, dict) else None,
                      "ok": False, "reason": f"{type(exc).__name__}: {exc}"}
        reports.append(report)
    duplicate_hosts = sorted(h for h, count in by_host.items() if count > 1)
    return {"checked": len(reports), "passed": sum(x["ok"] for x in reports),
            "failed": sum(not x["ok"] for x in reports),
            "nodes": reports, "repeated_hostnames": duplicate_hosts,
            "repeated_failure_domains": sorted(d for d, count in by_domain.items() if count > 1),
            "note": "Distinct failure_domain labels are self-reported and do not prove independent owners, regions, or hardware."}
