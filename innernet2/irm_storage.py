"""IRM-1 draft: STO-1 proof-of-storage over OB80-2 ciphertext chunks.

Status: DRAFT reference implementation of docs/IRM1_RESOURCE_MARKET_SPEC.md
section 5.4. Not part of the v1.0.0 core.

Each ciphertext chunk is cut into 1 KiB blocks (the last one may be shorter)
and hashed into a Merkle tree built like RFC 6962 (Certificate Transparency):

    leaf  = SHA-256(0x00 || "STO-1" || block)
    node  = SHA-256(0x01 || "STO-1" || left || right)
    MTH(n blocks) splits at k = largest power of two < n.
    root  = SHA-256(0x02 || "STO-1" || uint32_be(n) || MTH)

The final step commits the block count into the stored root, so a proof is
only valid for the exact chunk size the client recorded.

The client keeps (root, block_count) per chunk. A challenge names a chunk and
a block; the provider answers with that block and its audit path; the client
recomputes the root. This is a proof-of-retrievability style check, not a
zero-knowledge proof.
"""
from __future__ import annotations

import hashlib
import secrets

from .bulk_v080 import BulkError

BLOCK_SIZE = 1024
MAX_CHUNK = 2 * 1024 * 1024          # generous upper bound on one ciphertext chunk
_TAG = b"STO-1"


def _leaf(block: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + _TAG + block).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + _TAG + left + right).digest()


def _commit(mth: bytes, count: int) -> bytes:
    return hashlib.sha256(b"\x02" + _TAG + count.to_bytes(4, "big") + mth).digest()


def split_blocks(chunk: bytes) -> list[bytes]:
    if not isinstance(chunk, (bytes, bytearray)) or not 0 < len(chunk) <= MAX_CHUNK:
        raise BulkError("invalid chunk for proof of storage")
    return [bytes(chunk[i:i + BLOCK_SIZE]) for i in range(0, len(chunk), BLOCK_SIZE)]


def _split_point(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _mth(leaves: list[bytes]) -> bytes:
    n = len(leaves)
    if n == 1:
        return leaves[0]
    k = _split_point(n)
    return _node(_mth(leaves[:k]), _mth(leaves[k:]))


def _path(leaves: list[bytes], index: int) -> list[bytes]:
    n = len(leaves)
    if n == 1:
        return []
    k = _split_point(n)
    if index < k:
        return _path(leaves[:k], index) + [_mth(leaves[k:])]
    return _path(leaves[k:], index - k) + [_mth(leaves[:k])]


def chunk_root(chunk: bytes) -> tuple[bytes, int]:
    """Return (merkle_root, block_count) for one ciphertext chunk."""
    blocks = split_blocks(chunk)
    return _commit(_mth([_leaf(b) for b in blocks]), len(blocks)), len(blocks)


def prove(chunk: bytes, block_index: int) -> tuple[bytes, list[bytes]]:
    """Provider side: return (block, audit_path) for block_index."""
    blocks = split_blocks(chunk)
    if type(block_index) is not int or not 0 <= block_index < len(blocks):
        raise BulkError("block index out of range")
    return blocks[block_index], _path([_leaf(b) for b in blocks], block_index)


def verify(root: bytes, block_count: int, block_index: int, block: bytes, path: list[bytes]) -> bool:
    """Client side: recompute the root from the block and its audit path (RFC 6962 2.1.1)."""
    if len(root) != 32 or type(block_count) is not int or block_count < 1:
        return False
    if type(block_index) is not int or not 0 <= block_index < block_count:
        return False
    expected_len = BLOCK_SIZE if block_index < block_count - 1 else None
    if not isinstance(block, (bytes, bytearray)) or not 0 < len(block) <= BLOCK_SIZE:
        return False
    if expected_len is not None and len(block) != expected_len:
        return False
    if not isinstance(path, list) or any(not isinstance(p, (bytes, bytearray)) or len(p) != 32 for p in path):
        return False
    fn, sn = block_index, block_count - 1
    r = _leaf(bytes(block))
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = _node(bytes(p), r)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = _node(r, bytes(p))
        fn >>= 1
        sn >>= 1
    return sn == 0 and secrets.compare_digest(_commit(r, block_count), bytes(root))


# ---- lease-level helpers ---------------------------------------------------

def lease_roots(chunks: list[bytes]) -> list[dict]:
    """Client keeps this list (32-byte root + block count per chunk), not the data."""
    out = []
    for chunk in chunks:
        root, count = chunk_root(chunk)
        out.append({"root": root.hex(), "blocks": count})
    return out


def make_challenge(roots: list[dict], rng=secrets.SystemRandom()) -> dict:
    if not roots:
        raise BulkError("empty lease")
    chunk = rng.randrange(len(roots))
    return {"chunk": chunk, "block": rng.randrange(roots[chunk]["blocks"])}


def answer_challenge(chunks: list[bytes], challenge: dict) -> dict:
    chunk = challenge.get("chunk")
    if type(chunk) is not int or not 0 <= chunk < len(chunks):
        raise BulkError("challenge chunk out of range")
    block, path = prove(chunks[chunk], challenge.get("block"))
    return {"chunk": chunk, "block": challenge["block"], "data": block.hex(), "path": [p.hex() for p in path]}


def check_answer(roots: list[dict], challenge: dict, answer: dict) -> bool:
    try:
        if answer.get("chunk") != challenge["chunk"] or answer.get("block") != challenge["block"]:
            return False
        entry = roots[challenge["chunk"]]
        return verify(bytes.fromhex(entry["root"]), entry["blocks"], challenge["block"],
                      bytes.fromhex(answer["data"]), [bytes.fromhex(p) for p in answer["path"]])
    except (KeyError, TypeError, ValueError, IndexError, AttributeError):
        return False
