"""Adversarial regressions for Claude RC5 dev3 re-audit; synthetic and local only."""
from __future__ import annotations
import os
import socket
import struct
import json
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from innernet2.network import MeshClient
from innernet2.stream_v080 import Session, StreamError
from innernet2.bulk_v080 import ChunkStore
from innernet2.mailbox_store import MailboxStore
from innernet2.native_udp import pub_bytes


def test_ar01_no_external_reusable_v3_capability_pair(mesh, tmp_path):
    client, directory, _ = mesh
    source = tmp_path / "sample.bin"
    source.write_bytes(b"SYNTHETIC" * 900)
    with pytest.raises(TypeError):
        client.upload_file(source, capability_pair=("reader", "admin"))


def test_ar01_callback_before_first_remote_write(mesh, tmp_path, monkeypatch):
    client, directory, _ = mesh
    source = tmp_path / "sample.bin"
    source.write_bytes(b"SYNTHETIC" * 900)
    recorded = []
    events = []
    original_put = client.put_fragment
    def guarded_put(node, blob):
        events.append("remote_put")
        assert events[0] == "persist"  # first action for THIS upload
        return original_put(node, blob)
    monkeypatch.setattr(client, "put_fragment", guarded_put)
    def persist(reader, admin):
        assert reader.startswith('inn3_') and admin.startswith('inna_')
        events.append("persist")
        recorded.append((reader, admin))
    one = client.upload_file(source, persist_capabilities=persist)
    assert events[0] == "persist" and events.count("persist") == 1 and "remote_put" in events
    events.clear()
    two = client.upload_file(source, persist_capabilities=persist)
    assert events[0] == "persist" and events.count("persist") == 1 and "remote_put" in events
    assert one['capability'] != two['capability']
    assert one['admin_capability'] != two['admin_capability']
    assert len(recorded) == 2


def test_ar01_failed_callback_does_not_upload(mesh, tmp_path, monkeypatch):
    client, directory, _ = mesh
    source = tmp_path / "sample.bin"
    source.write_bytes(b"SYNTHETIC" * 900)
    monkeypatch.setattr(client, 'put_fragment', lambda *a, **k: pytest.fail('remote PUT before persistence'))
    def fail(reader, admin):
        raise RuntimeError('persistent store unavailable')
    with pytest.raises(RuntimeError, match='persistent store unavailable'):
        client.upload_file(source, persist_capabilities=fail)


def _frame_with_header(raw):
    a, b = socket.socketpair()
    s = Session(b, b"X"*32, b"2"*32, b"1"*32, initiator=False)
    clear = struct.pack('>I', len(raw)) + raw
    blob = ChaCha20Poly1305(b'1'*32).encrypt(struct.pack('>IQ', 0, 0), clear, b'C'+struct.pack('>Q', 0))
    a.sendall(struct.pack('>I', len(blob))+blob)
    return s, a, b


@pytest.mark.parametrize('raw', [
    b'{"cmd":"ping","cmd":"forward","rid":1}',
    b'{"cmd":"ping","rid":1,"value":NaN}',
    b'{"cmd":"ping","rid":1,"value":Infinity}',
    b'{"cmd":"ping","rid":' + b'9'*5000 + b'}',
    b'{"cmd":"ping","rid":9223372036854775808}',
    (b'{"a":'*70)+b'0'+(b'}'*70),
])
def test_ar02_reject_unauthorized_json_grammar(raw):
    session,a,b = _frame_with_header(raw)
    try:
        with pytest.raises(StreamError,match='invalid JSON'):
            session.read()
    finally:
        a.close(); b.close()


def test_ar02_valid_canonical_frame_accepted():
    session,a,b = _frame_with_header(b'{"cmd":"ping","rid":1}')
    try:
        header,data=session.read()
        assert header == {'cmd':'ping','rid':1} and data==b''
    finally:
        a.close(); b.close()


def test_n2_database_schema_migration_runs_once(tmp_path):
    p = tmp_path / 'objects.sqlite'
    p.parent.chmod(0o700)
    s=ChunkStore(p,max_storage_bytes=4096,max_objects=1)
    try:
        assert s.db.execute('PRAGMA user_version').fetchone()[0] == 1
        assert s.usage()['objects']==0
    finally: s.close()
    s=ChunkStore(p,max_storage_bytes=4096,max_objects=1)
    try:
        assert s.db.execute('PRAGMA user_version').fetchone()[0] == 1
    finally: s.close()


def test_n4_rejected_mail_is_not_acknowledged(tmp_path):
    p=tmp_path/'mail.sqlite';p.parent.chmod(0o700)
    db=MailboxStore(p)
    sender,rcpt=pub_bytes(Ed25519PrivateKey.generate()),pub_bytes(Ed25519PrivateKey.generate())
    ident=b'M'*16
    try:
        assert db.store(sender,rcpt,ident,b'synthetic',now=100)[0]=='STORED'
        assert db.reject(rcpt,sender,ident,now=101)
        assert not db.consume(rcpt,sender,ident,now=102)
    finally: db.close()


def test_n3_wrong_recipient_checkpoint_fails_before_ping(tmp_path, monkeypatch):
    from innernet2.bulk_v080 import BulkError, prepare_file
    from innernet2.mailbox_e2ee import generate_bundle
    from innernet2.relay_v090 import BulkClient
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    sender = Ed25519PrivateKey.generate()
    recipient = Ed25519PrivateKey.generate()
    wrong = Ed25519PrivateKey.generate()
    source = tmp_path/'sample.bin'; source.write_bytes(b'SYNTHETIC TEST MESSAGE')
    bundle = generate_bundle(recipient, tmp_path/'secret.key')
    obj = prepare_file(source, sender, bundle, expected_recipient=pub_bytes(recipient))
    client=BulkClient.__new__(BulkClient)
    calls=[]
    def call(command, **fields):
        calls.append(command)
        if command == 'get_manifest': return {'record':obj.record}, b''
        pytest.fail('extra RPC sent after detecting wrong recipient')
    monkeypatch.setattr(client,'call',call)
    with pytest.raises(BulkError, match='different recipient'):
        client.fetch(obj.payload['object_id'],wrong,X25519PrivateKey.generate(),
                     tmp_path/'out',expected_sender=pub_bytes(sender),
                     resume_dir=tmp_path/'missing-checkpoint-folder')
    assert calls == ['get_manifest']


def test_d4_1_failed_placement_does_not_mint_or_persist(mesh, tmp_path, monkeypatch):
    """Invalid local topology must fail before any capability reaches disk."""
    from innernet2.network import INNERnetError
    from innernet2 import network
    client, _, _ = mesh
    source = tmp_path / 'sample.bin'
    source.write_bytes(b'SYNTHETIC' * 1000)
    events = []
    monkeypatch.setattr(network, 'new_v3_capabilities',
                        lambda: pytest.fail('minted secrets before placement preflight'))
    monkeypatch.setattr(client, 'put_fragment',
                        lambda *a, **kw: pytest.fail('remote PUT before placement preflight'))
    def persist(reader, admin):
        events.append('persist')
    # Test fixture does not declare the required n+INDEX_N distinct domains.
    with pytest.raises(INNERnetError, match='distinct declared failure domains'):
        client.upload_file(source, require_diverse_domains=True, persist_capabilities=persist)
    assert events == []


def test_d4_3_reject_nonfinite_float_overflow():
    for raw in (b'{"rid":1,"value":1e400}', b'{"rid":1,"value":-1e400}',
                b'{"rid":1,"value":1e309}'):
        session, a, b = _frame_with_header(raw)
        try:
            with pytest.raises(StreamError, match='invalid JSON'):
                session.read()
        finally:
            a.close(); b.close()


def test_d4_3_accept_finite_json_float():
    session, a, b = _frame_with_header(b'{"rid":1,"value":1.25e2}')
    try:
        header, data = session.read()
        assert header['value'] == 125.0 and data == b''
    finally:
        a.close(); b.close()


def test_n2_migrates_populated_v0_db(tmp_path):
    """Reconcile counters without deleting ciphertext when upgrading an old DB."""
    from innernet2.bulk_v080 import prepare_file
    from innernet2.mailbox_e2ee import generate_bundle
    sender, recipient = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    tmp_path.chmod(0o700)
    bundle = generate_bundle(recipient, tmp_path / 'r.key')
    f = tmp_path / 'f.bin'
    f.write_bytes(b'SYNTHETIC:' + os.urandom(70000))
    obj = prepare_file(f, sender, bundle, expected_recipient=pub_bytes(recipient))
    dbfile = tmp_path / 'objects.sqlite'
    store = ChunkStore(dbfile)
    try:
        store.manifest(obj.record)
        for i in range(obj.payload['chunks']):
            store.put(obj.payload['object_id'], i, obj.chunk(i))
        real = store.usage()['ciphertext_bytes']
        assert real > 0
        store.db.execute('UPDATE sender_usage SET payload_bytes=0, object_count=0')
        store.db.execute('UPDATE quota_metrics SET payload_bytes=0, object_count=0')
        store.db.execute('PRAGMA user_version=0')
    finally:
        store.close()
    store = ChunkStore(dbfile)
    try:
        assert store.db.execute('PRAGMA user_version').fetchone()[0] == 1
        assert store.usage()['ciphertext_bytes'] == real
        assert store.db.execute('SELECT payload_bytes FROM sender_usage').fetchone()[0] == real
        assert store.db.execute('SELECT object_count FROM sender_usage').fetchone()[0] == 1
        assert store.missing(obj.payload['object_id']) == []
    finally:
        store.close()
