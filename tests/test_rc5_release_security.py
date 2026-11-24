"""RC5 security upgrade and migration regressions: loopback/local disk only."""
import hashlib
import json
import secrets
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from innernet2.bulk_v080 import (VERSION, LEGACY_VERSION, DOMAIN, ID_DOMAIN,
                                 ChunkStore, BulkError, prepare_file, verify_manifest)
from innernet2.mailbox_e2ee import generate_bundle
from innernet2.mailbox_store import MailboxStore, MailboxError
from innernet2.mailbox_wire import handle_request, request, parse_response
from innernet2.native_udp import NativeResponder, hello_packet, ephemeral_pub, pub_bytes

K = Ed25519PrivateKey.generate


def _prepared(tmp_path, sender=None, recipient=None):
    sender = sender or K()
    recipient = recipient or K()
    secret = tmp_path / (secrets.token_hex(4) + '.key')
    bundle = generate_bundle(recipient, secret)
    src = tmp_path / (secrets.token_hex(4) + '.bin')
    src.write_bytes(b'SYNTHETIC:RC5-' + secrets.token_bytes(1024))
    return sender, recipient, prepare_file(src, sender, bundle, expected_recipient=bytes.fromhex((bundle)["payload"]["identity_ed25519"]))


def test_rc5_new_manifest_id_is_sender_bound(tmp_path):
    sender, _, obj = _prepared(tmp_path)
    p = obj.payload
    assert p['version'] == VERSION == 'OB80-2'
    expected = hashlib.sha256(ID_DOMAIN + pub_bytes(sender) +
            bytes.fromhex(p['ephemeral_x25519'])).digest()[:16].hex()
    assert p['object_id'] == expected
    # Attacker can sign their own object with a copied victim identifier, but
    # the strict v2 namespace check rejects it before a store can claim it.
    attacker, _, other = _prepared(tmp_path)
    altered = dict(other.payload, object_id=p['object_id'])
    forged = {'payload':altered, 'signature':attacker.sign(DOMAIN +
        json.dumps(altered, sort_keys=True, separators=(',',':')).encode()).hex()}
    with pytest.raises(BulkError, match='sender-scoped namespace'):
        verify_manifest(forged)


def test_rc5_existing_legacy_manifest_readable_but_new_legacy_rejected(tmp_path):
    sender, _, obj = _prepared(tmp_path)
    payload = dict(obj.payload, version=LEGACY_VERSION)
    record = {'payload':payload, 'signature':sender.sign(DOMAIN +
        json.dumps(payload, sort_keys=True, separators=(',',':')).encode()).hex()}
    assert verify_manifest(record)['version'] == LEGACY_VERSION
    store = ChunkStore(tmp_path/'db.sqlite')
    try:
        with pytest.raises(BulkError, match='read-only'):
            store.manifest(record)
        # Simulates an existing pre-upgrade persisted legacy manifest, with a
        # proper timestamp and quota state, not an unsafe new legacy upload.
        store.db.execute('INSERT INTO objects VALUES (?,?,?,?,?)',
            (payload['object_id'],json.dumps(record,sort_keys=True,separators=(',',':')),
             payload['sender'],payload['recipient'],payload['expires_at']))
        assert store.get_manifest(payload['object_id'])['payload']['version']==LEGACY_VERSION
    finally:
        store.close()


def test_rc5_cursor_survives_expiration_and_is_recipient_scoped(tmp_path):
    tmp_path.chmod(0o700)
    db = MailboxStore(tmp_path/'mail.db')
    a,b,r,outsider = [pub_bytes(K()) for _ in range(4)]
    try:
        first,second,third = [i.to_bytes(16,'big') for i in (1,2,3)]
        db.store(a,r,first,b'SYNTHETIC:a',ttl=60,now=100)
        db.store(a,r,second,b'SYNTHETIC:b',ttl=3600,now=101)
        assert db.fetch(r,now=120)[1] == first
        db.store(b,r,third,b'SYNTHETIC:c',ttl=3600,now=200)
        assert db.fetch(r,now=200,after=(a,first))[1] == second
        with pytest.raises(MailboxError,match='unknown mailbox cursor'):
            db.fetch(outsider,now=200,after=(a,first))
    finally:
        db.close()


def test_rc5_per_recipient_quota_protects_inbox(tmp_path):
    tmp_path.chmod(0o700)
    db=MailboxStore(tmp_path/'mail.db',max_rows=10)
    recipient=pub_bytes(K())
    try:
        for i in range(8):
            db.store(pub_bytes(K()),recipient,i.to_bytes(16,'big'),b'SYNTHETIC:test',now=100+i)
        with pytest.raises(MailboxError,match='recipient mailbox quota'):
            db.store(pub_bytes(K()),recipient,(9).to_bytes(16,'big'),b'SYNTHETIC:x',now=109)
    finally:db.close()


def test_rc5_mailbox_hello_replay_persists_restart(tmp_path):
    tmp_path.chmod(0o700)
    client,server=K(),K()
    db=MailboxStore(tmp_path/'journal.db')
    hello=hello_packet(client,pub_bytes(server),secrets.token_bytes(16),
         ephemeral_pub(X25519PrivateKey.generate()),secrets.token_bytes(16))
    addr=('127.0.0.1',45200)
    try:
        first=NativeResponder(server,{pub_bytes(client)},mailbox_store=db)
        assert first.process(hello,addr) is not None
    finally:db.close()
    reopened=MailboxStore(tmp_path/'journal.db')
    try:
        second=NativeResponder(server,{pub_bytes(client)},mailbox_store=reopened)
        assert second.process(hello,addr) is None
    finally:reopened.close()


def test_rc5_mailbox_advertises_cursor_capability(tmp_path):
    tmp_path.chmod(0o700)
    db=MailboxStore(tmp_path/'mail.db')
    try:
        rid=b'0'*16
        code,payload=parse_response(handle_request(db,pub_bytes(K()),
                                  request('P',request_id=rid)),rid)
        assert code=='P' and b'cursor-v1' in payload.split(b';')
    finally:db.close()
