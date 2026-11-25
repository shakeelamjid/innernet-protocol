"""Regression tests for the v1.0.x hardening updates:

- OB80/HTTP-v3 chunk key is bound to object_id (root reuse across objects no
  longer reuses ChaCha20-Poly1305 key+nonce).
- R90-ROUTE-2 sequenced plans with client-side anti-rollback.
"""
from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from innernet2.crypto import new_root, encrypt_chunk, decrypt_chunk
from innernet2 import routing_v090 as r90
from innernet2.bulk_v080 import BulkError
from innernet2.native_udp import pub_bytes


def test_chunk_key_bound_to_object_id():
    root = new_root()
    oid_a = bytes(16)
    oid_b = bytes([1]) + bytes(15)
    # Same root, same index, same plaintext, different object -> different ciphertext,
    # because the derived key now differs per object (no key/nonce reuse).
    ca = encrypt_chunk(root, oid_a, 0, b"SYNTHETIC-A")
    cb = encrypt_chunk(root, oid_b, 0, b"SYNTHETIC-A")
    assert ca != cb
    assert decrypt_chunk(root, oid_a, 0, ca, len(b"SYNTHETIC-A")) == b"SYNTHETIC-A"
    # A ciphertext made for object A must not authenticate under object B's key.
    with pytest.raises(Exception):
        decrypt_chunk(root, oid_b, 0, ca, len(b"SYNTHETIC-A"))


def _plan(version, sequence=None, *, ttl=3600):
    node_key = pub_bytes(Ed25519PrivateKey.generate())
    recipient = pub_bytes(Ed25519PrivateKey.generate())
    now = int(time.time())
    payload = {"version": version, "issued_at": now, "expires_at": now + ttl,
               "nodes": [{"id": "n1", "host": "example.test", "port": 9000,
                          "public_ed25519": node_key.hex(), "failure_domain": "dc-a"}],
               "routes": [{"recipient": recipient.hex(), "ordered_nodes": ["n1"]}]}
    if sequence is not None:
        payload["sequence"] = sequence
    return payload


def test_route2_roundtrip_and_rollback(tmp_path):
    publisher = Ed25519PrivateKey.generate()
    pin = pub_bytes(publisher)
    store = r90.SequenceStore(tmp_path / "seq" / "seen.json")

    p5 = r90.sign_plan(_plan(r90.VERSION2, 5), publisher)
    assert r90.verify_plan(p5, pin, sequence_store=store)["sequence"] == 5

    # A newer sequence is accepted.
    p6 = r90.sign_plan(_plan(r90.VERSION2, 6), publisher)
    assert r90.verify_plan(p6, pin, sequence_store=store)["sequence"] == 6

    # Replaying the older (still unexpired) plan is now rejected.
    with pytest.raises(BulkError):
        r90.verify_plan(p5, pin, sequence_store=store)

    # Equal sequence is also a rollback.
    with pytest.raises(BulkError):
        r90.verify_plan(p6, pin, sequence_store=store)


def test_route2_requires_sequence_field():
    publisher = Ed25519PrivateKey.generate()
    with pytest.raises(BulkError):
        r90.sign_plan(_plan(r90.VERSION2, None), publisher)  # missing sequence


def test_legacy_route1_still_works_but_cannot_use_store(tmp_path):
    publisher = Ed25519PrivateKey.generate()
    pin = pub_bytes(publisher)
    p = r90.sign_plan(_plan(r90.VERSION, None), publisher)
    # ROUTE-1 verifies with no store (unchanged behaviour, no anti-rollback).
    assert r90.verify_plan(p, pin)["version"] == r90.VERSION
    # But asking for anti-rollback on a ROUTE-1 plan is an explicit error.
    store = r90.SequenceStore(tmp_path / "seq" / "seen.json")
    with pytest.raises(BulkError):
        r90.verify_plan(p, pin, sequence_store=store)


def test_sequence_store_reloads_after_update(tmp_path):
    """Regression: the store must stay owner-only after an update, or it cannot be reopened."""
    import os
    from innernet2.routing_v090 import SequenceStore
    d = tmp_path / "state"
    d.mkdir(mode=0o700)
    old = os.umask(0o022)
    try:
        s = SequenceStore(d / "seq.json")
        s.check_and_update("aa" * 32, 5)
        assert (d / "seq.json").stat().st_mode & 0o077 == 0
        s2 = SequenceStore(d / "seq.json")
        import pytest
        from innernet2.bulk_v080 import BulkError
        with pytest.raises(BulkError):
            s2.check_and_update("aa" * 32, 5)
        s2.check_and_update("aa" * 32, 6)
    finally:
        os.umask(old)
