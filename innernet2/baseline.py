"""One-node authorized plaintext-bytes HTTP transport baseline over the SAME tunnel.

This is deliberately not equivalent to INNERnet: no encryption, metadata
protection, Reed-Solomon redundancy, provider diversity or recovery. Caller
should pass synthetic bytes only; the server retains uploaded fragments.
"""
from __future__ import annotations

import hashlib
import time
from pathlib import Path

from .network import MAX_CHUNK, MeshClient


def one_node_baseline(client: MeshClient, source: str | Path, *, node_id: str,
                      chunk_size: int = MAX_CHUNK) -> dict:
    if node_id not in client.nodes:
        raise ValueError("unknown baseline node")
    if node_id not in client.writers:
        raise ValueError("baseline node has no writer token")
    if not 1 <= chunk_size <= MAX_CHUNK:
        raise ValueError("invalid baseline chunk size")
    source = Path(source)
    if source.is_symlink() or not source.is_file():
        raise ValueError("baseline requires an existing regular, non-symlink file")
    locators = []
    file_hash = hashlib.sha256()
    sent = 0
    start = time.monotonic()
    with source.open("rb") as f:
        while block := f.read(chunk_size):
            file_hash.update(block)
            sent += len(block)
            locators.append(client.put_fragment(node_id, block))
    upload_ms = round((time.monotonic() - start) * 1000)
    obtained = hashlib.sha256()
    total = 0
    start = time.monotonic()
    for locator in locators:
        raw = client.get_fragment(locator)
        obtained.update(raw)
        total += len(raw)
    download_ms = round((time.monotonic() - start) * 1000)
    if sent != total or file_hash.digest() != obtained.digest():
        raise ValueError("one-node baseline failed SHA-256 file integrity")
    return {"status": "PASS", "node_id": node_id, "bytes": sent,
            "fragments": len(locators), "upload_ms": upload_ms,
            "download_ms": download_ms, "sha256_verified": True,
            "transport": "HTTP through SSH tunnel (SSH encrypted)",
            "storage": "One node with no redundancy or data-at-rest encryption in baseline",
            "caution": "Baseline ciphertext storage from INNERnet is NOT equivalent; this synthetic "
                       "baseline stores test bytes directly at one lab node and persists on the VPS."}
