"""IE60 security, ciphertext persistence, backwards compatibility and local routes."""
from __future__ import annotations

import json
from pathlib import Path
import secrets
import subprocess
import sys
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from innernet2.mailbox_e2ee import (E2EEError, generate_bundle, verify_bundle,
    seal_message, open_message, inspect_envelope, load_recipient_secret, MAX_TEXT)
from innernet2.mailbox_secure_demo import run_demo
from innernet2.mailbox_store import MailboxStore, OutboxStore, MailboxError
from innernet2.native_udp import pub_bytes


@pytest.fixture
def fixture(tmp_path):
    tmp_path.chmod(0o700)
    sender, receiver, other = [Ed25519PrivateKey.generate() for _ in range(3)]
    bundle = generate_bundle(receiver, tmp_path / 'recipient.key')
    secret = load_recipient_secret(tmp_path / 'recipient.key')
    mid = secrets.token_bytes(16)
    envelope = seal_message(sender, bundle, mid, b'SYNTHETIC:PRIVATE-PAYLOAD', expected_recipient=bytes.fromhex((bundle)["payload"]["identity_ed25519"]))
    return tmp_path, sender, receiver, other, bundle, secret, mid, envelope


def test_recipient_only_roundtrip_and_no_plaintext(fixture):
    _, s, r, _, bundle, secret, mid, encrypted = fixture
    assert encrypted.startswith(b'IE60')
    assert b'SYNTHETIC:PRIVATE-PAYLOAD' not in encrypted
    assert inspect_envelope(encrypted, sender=pub_bytes(s), recipient=pub_bytes(r),
                            message_id=mid)['message_id'] == mid
    assert open_message(r, secret, encrypted, expected_sender=pub_bytes(s),
                        expected_message_id=mid) == b'SYNTHETIC:PRIVATE-PAYLOAD'
    assert verify_bundle(bundle, pub_bytes(r)).hex() == bundle["payload"]["encryption_x25519"]


def test_pinned_bundle_signature_tamper_expiry(fixture):
    _, _, r, o, bundle, _, _, _ = fixture
    verify_bundle(bundle, pub_bytes(r))
    with pytest.raises(E2EEError):
        verify_bundle(bundle, pub_bytes(o))
    broken = json.loads(json.dumps(bundle))
    broken['payload']['encryption_x25519'] = '00' * 32
    with pytest.raises(E2EEError):
        verify_bundle(broken, pub_bytes(r))
    with pytest.raises(E2EEError):
        verify_bundle(bundle, pub_bytes(r), now=bundle['payload']['expires_at'])
    with pytest.raises(E2EEError):
        verify_bundle(bundle, pub_bytes(r), now=bundle['payload']['created_at']-301)


def test_envelope_sender_signature_and_metadata_binding(fixture):
    _, s, r, o, _, secret, mid, encrypted = fixture
    with pytest.raises(E2EEError):
        inspect_envelope(encrypted, recipient=pub_bytes(o))
    with pytest.raises(E2EEError):
        inspect_envelope(encrypted, sender=pub_bytes(o))
    with pytest.raises(E2EEError):
        inspect_envelope(encrypted, message_id=secrets.token_bytes(16))
    bad = bytearray(encrypted)
    bad[93] ^= 1
    with pytest.raises(E2EEError):
        inspect_envelope(bytes(bad))
    bad = bytearray(encrypted)
    bad[-1] ^= 1
    with pytest.raises(E2EEError):
        inspect_envelope(bytes(bad))
    with pytest.raises(E2EEError):
        open_message(o, secret, encrypted)
    with pytest.raises(E2EEError):
        open_message(r, X25519PrivateKey.generate(), encrypted)
    assert len(mid) == 16


def test_envelope_expiration_and_ttl_not_extended(fixture):
    _, _, _, _, bundle, _, mid, encrypted = fixture
    created = inspect_envelope(encrypted)['created_at']
    with pytest.raises(E2EEError):
        inspect_envelope(encrypted, now=created + 3601)
    with pytest.raises(E2EEError):
        inspect_envelope(encrypted, ttl=7200, now=created)
    with pytest.raises(E2EEError):
        inspect_envelope(encrypted, now=created - 301)
    with pytest.raises(E2EEError):
        seal_message(Ed25519PrivateKey.generate(), bundle, mid, b'SYNTHETIC:no', ttl=30, expected_recipient=bytes.fromhex((bundle)["payload"]["identity_ed25519"]))
    with pytest.raises(E2EEError):
        seal_message(Ed25519PrivateKey.generate(), bundle, mid, b'non-synthetic', expected_recipient=bytes.fromhex((bundle)["payload"]["identity_ed25519"]))


def test_strict_mailbox_rejects_plaintext_and_swapped_identity(fixture):
    path, s, r, other, _, _, mid, encrypted = fixture
    db = MailboxStore(path / 'secure.sqlite', require_e2ee=True)
    try:
        with pytest.raises(MailboxError):
            db.store(pub_bytes(s), pub_bytes(r), mid, b'SYNTHETIC:plaintext')
        with pytest.raises(MailboxError):
            db.store(pub_bytes(other), pub_bytes(r), mid, encrypted)
        with pytest.raises(MailboxError):
            db.store(pub_bytes(s), pub_bytes(other), mid, encrypted)
        with pytest.raises(MailboxError):
            db.store(pub_bytes(s), pub_bytes(r), secrets.token_bytes(16), encrypted)
        assert db.store(pub_bytes(s), pub_bytes(r), mid, encrypted)[0] == 'STORED'
        assert db.store(pub_bytes(s), pub_bytes(r), mid, encrypted)[0] == 'DUPLICATE'
    finally:
        db.close()
    db = MailboxStore(path / 'secure.sqlite', require_e2ee=True)
    try:
        assert db.fetch(pub_bytes(r))[2] == encrypted
        assert db.status(pub_bytes(s), mid) == 'STORED'
    finally:
        db.close()


def test_encrypted_outbox_only_contains_ciphertext(fixture):
    path, sender, recipient, _, _, _, mid, envelope = fixture
    out = OutboxStore(path / 'encrypted-outbox.sqlite')
    try:
        out.enqueue(pub_bytes(recipient), envelope, message_id=mid)
        queued = out.queued()
        assert queued[0][2] == envelope
        out.mark_stored(mid)
        assert out.queued() == []
    finally:
        out.close()
    rawdb = (path / 'encrypted-outbox.sqlite').read_bytes()
    assert b'SYNTHETIC:PRIVATE-PAYLOAD' not in rawdb


def test_key_storage_permissions_and_no_overwrite(fixture):
    path, _, receiver, _, _, _, _, _ = fixture
    keyfile = path / 'recipient.key'
    assert keyfile.stat().st_mode & 0o777 == 0o600
    with pytest.raises(E2EEError):
        generate_bundle(receiver, keyfile)
    keyfile.chmod(0o644)
    with pytest.raises(E2EEError):
        load_recipient_secret(keyfile)


def test_bounds_and_truncations(fixture):
    path, s, r, _, bundle, secret, mid, envelope = fixture
    assert MAX_TEXT > 0
    seal_message(s, bundle, mid, b'SYNTHETIC:' + b'a'*(MAX_TEXT-10), expected_recipient=bytes.fromhex((bundle)["payload"]["identity_ed25519"]))
    with pytest.raises(E2EEError):
        seal_message(s, bundle, mid, b'SYNTHETIC:' + b'a'*MAX_TEXT, expected_recipient=bytes.fromhex((bundle)["payload"]["identity_ed25519"]))
    with pytest.raises(E2EEError):
        inspect_envelope(envelope[:-65])
    with pytest.raises(E2EEError):
        inspect_envelope(envelope + b'j')


def test_two_node_local_end_to_end():
    result = run_demo(messages=6)
    assert result['status'] == 'PASS'
    assert result['verified_decryptions'] == 6
    assert result['separate_local_nodes'] == 2
    assert result['plaintext_not_in_node_databases'] is True


def test_secure_demo_cli(tmp_path):
    run = subprocess.run([sys.executable, '-m', 'innernet2.mailbox', 'demo-secure',
                          '--messages', '4'], capture_output=True, text=True, timeout=30)
    assert run.returncode == 0, run.stderr
    assert json.loads(run.stdout)['status'] == 'PASS'
