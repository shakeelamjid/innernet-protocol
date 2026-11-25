"""Deterministic IRM-1 draft test vectors (REG-1, PAY-1 ticket, STO-1 proof).

Run:  python -m tools.create_irm1_vectors > docs/TEST_VECTORS_IRM1_DRAFT.json
All keys and data are synthetic and derived from fixed labels; never use them for anything real.
"""
from __future__ import annotations

import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from innernet2 import irm_registry as reg
from innernet2 import irm_storage as sto
from innernet2.native_udp import pub_bytes

NOW = 1_764_000_000


def _key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"IRM1-VECTOR-KEY/" + label.encode()).digest())


def _stream(label: str, size: int) -> bytes:
    out, i = b"", 0
    while len(out) < size:
        out += hashlib.sha256(f"IRM1-VECTOR-DATA/{label}/{i}".encode()).digest()
        i += 1
    return out[:size]


def create() -> dict:
    registry, backup, new_registry = _key("registry"), _key("registry-backup"), _key("registry-new")
    provider, client = _key("provider"), _key("client")
    entry = {
        "id": pub_bytes(provider).hex(), "name": "vector-provider", "region": "eu-central",
        "endpoints": [{"host": "provider.example.test", "port": 9443}],
        "services": ["STO-1"], "payto": {"eip155:84532": "0x" + "5a" * 20},
        "prices": {"STO-1": {"asset": "USDC", "unit": "GiB-day", "amount": "0.0010"}},
    }
    payload = {"version": "REG-1", "sequence": 7, "issued_at": NOW, "expires_at": NOW + 3600, "fee_bps": 100,
               "fee_payto": {"eip155:84532": "0x" + "fe" * 20}, "providers": [dict(entry, listed_at=NOW)]}
    chunk = _stream("chunk", 65_552)
    root, count = sto.chunk_root(chunk)
    block, path = sto.prove(chunk, 13)
    ticket = reg.sign_ticket({"client": pub_bytes(client).hex(), "service": "STO-1", "lease": "ab" * 16,
                              "units": "10.0", "unit": "GiB-day", "payment_tx": "0x" + "11" * 32,
                              "expires_at": NOW + 600}, provider)
    return {
        "warning": "Synthetic IRM-1 DRAFT vectors. Keys are public test keys; never use them.",
        "vector_version": "IRM1-DRAFT-1",
        "now": NOW,
        "keys": {"registry_public": pub_bytes(registry).hex(), "registry_backup_public": pub_bytes(backup).hex(),
                 "provider_public": pub_bytes(provider).hex(), "client_public": pub_bytes(client).hex()},
        "registry_document": reg.sign_registry(payload, registry, now=NOW),
        "rotation_record": reg.sign_rotation(pub_bytes(new_registry), 1, backup_key=backup, old_key=registry, now=NOW),
        "descriptor": reg.sign_descriptor(entry, provider),
        "service_ticket": ticket,
        "storage_proof": {
            "block_size": sto.BLOCK_SIZE,
            "chunk_sha256": hashlib.sha256(chunk).hexdigest(),
            "chunk_length": len(chunk),
            "chunk_generator": "concatenate SHA-256('IRM1-VECTOR-DATA/chunk/<i>') for i=0,1,2,... and truncate",
            "root": root.hex(), "block_count": count,
            "challenge": {"chunk": 0, "block": 13},
            "block_sha256": hashlib.sha256(block).hexdigest(),
            "path": [p.hex() for p in path],
        },
    }


if __name__ == "__main__":
    print(json.dumps(create(), indent=2))
