"""Independent adversarial regression probes: loopback and synthetic local state."""
import hashlib
import json
import secrets
import socket
import struct
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from innernet2.bulk_v080 import CHUNK_SIZE, ChunkStore, LEGACY_VERSION, DOMAIN, prepare_file
from innernet2.mailbox_e2ee import canonical, generate_bundle, load_recipient_secret
from innernet2.mailbox_store import MailboxStore
from innernet2.native_udp import NativeResponder, pub_bytes, hello_packet, ephemeral_pub
from innernet2.relay_v090 import BulkClient, BulkServer, Peer, serve_background
from innernet2.stream_v080 import MAGIC_C, DOMAIN_C, _rawpub

K=Ed25519PrivateKey.generate


def _read(sock, count):
    data=b''
    while len(data)<count:
        new=sock.recv(count-len(data))
        if not new:
            raise EOFError
        data+=new
    return data


def test_st81_key_confirmation_rejects_oversized_ciphertext_before_body(tmp_path):
    node, peer=K(),K()
    server=BulkServer(('127.0.0.1',0),node,tmp_path/'n.db',{pub_bytes(peer)})
    serve_background(server)
    try:
        with socket.create_connection(('127.0.0.1',server.server_address[1]),timeout=3) as sock:
            challenge=_read(sock,68)
            ephemeral=X25519PrivateKey.generate()
            prefix=MAGIC_C+pub_bytes(peer)+_rawpub(ephemeral)+secrets.token_bytes(32)
            sock.sendall(prefix+peer.sign(DOMAIN_C+challenge+prefix))
            assert _read(sock,196).startswith(b'S81S')
            sock.sendall(struct.pack('>I',400000))
            sock.settimeout(2)
            assert sock.recv(1)==b''
    finally:
        server.shutdown();server.server_close()


def test_udp_one_identity_cannot_fill_everyones_replay_cache():
    abusive, honest, server=K(),K(),K()
    responder=NativeResponder(server,{pub_bytes(abusive),pub_bytes(honest)})
    for i in range(600):
        hello=hello_packet(abusive,pub_bytes(server),secrets.token_bytes(16),
                          ephemeral_pub(X25519PrivateKey.generate()),secrets.token_bytes(16))
        responder.process(hello,('127.0.0.1',45000+i))
    normal=hello_packet(honest,pub_bytes(server),secrets.token_bytes(16),
                       ephemeral_pub(X25519PrivateKey.generate()),secrets.token_bytes(16))
    assert responder.process(normal,('127.0.0.1',60000)) is not None
    assert len(responder._hello_seen)<=513


def test_consumed_mail_does_not_block_recipient_delivery(tmp_path):
    tmp_path.chmod(0o700)
    db=MailboxStore(tmp_path/'m.sqlite',max_rows=10)
    spammer,friend,recipient=[pub_bytes(K()) for _ in range(3)]
    try:
        for i in range(8):
            db.store(spammer,recipient,i.to_bytes(16,'big'),b'junk',now=100)
            assert db.consume(recipient,spammer,i.to_bytes(16,'big'),now=101)
        db.store(friend,recipient,b'F'*16,b'legitimate',now=102)
        assert db.fetch(recipient,now=103)[2]==b'legitimate'
    finally:
        db.close()


def test_old_object_can_replicate_via_trusted_relay_and_resume(tmp_path):
    tmp_path.chmod(0o700)
    sender,recipient,relay_a,relay_b=K(),K(),K(),K()
    bundle=generate_bundle(recipient,tmp_path/'recipient.key')
    secret=load_recipient_secret(tmp_path/'recipient.key')
    content=b'synthetic-legacy-object'*(CHUNK_SIZE//23+1)
    source=tmp_path/'source';source.write_bytes(content)
    obj=prepare_file(source,sender,bundle, expected_recipient=bytes.fromhex((bundle)["payload"]["identity_ed25519"]))
    legacy_payload=dict(obj.payload,version=LEGACY_VERSION)
    record={'payload':legacy_payload,'signature':sender.sign(DOMAIN+canonical(legacy_payload)).hex()}
    ident=legacy_payload['object_id']
    db_a=tmp_path/'A.db'; db_b=tmp_path/'B.db'
    store=ChunkStore(db_a)
    try:
        store.db.execute('INSERT INTO objects VALUES (?,?,?,?,?)',(
            ident,canonical(record).decode(),legacy_payload['sender'],
            legacy_payload['recipient'],legacy_payload['expires_at']))
        store.db.execute('UPDATE quota_metrics SET object_count=object_count+1')
        for i in range(legacy_payload['chunks']):
            store.put(ident,i,obj.chunk(i))
    finally:
        store.close()
    server_b=BulkServer(('127.0.0.1',0),relay_b,db_b,
        {pub_bytes(relay_a),pub_bytes(recipient)},relays={pub_bytes(relay_a)})
    server_a=BulkServer(('127.0.0.1',0),relay_a,db_a,
        {pub_bytes(sender),pub_bytes(recipient)},peers={
            'B':Peer('127.0.0.1',server_b.server_address[1],pub_bytes(relay_b))})
    serve_background(server_b);serve_background(server_a)
    try:
        with BulkClient(Peer('127.0.0.1',server_a.server_address[1],pub_bytes(relay_a)),sender) as c:
            assert c.call('forward',ident=ident,peer_id='B')[0]['replica_complete']
        (tmp_path/'resume').mkdir(mode=0o700)
        with BulkClient(Peer('127.0.0.1',server_b.server_address[1],pub_bytes(relay_b)),recipient) as c:
            c.fetch(ident,recipient,secret,tmp_path/'restored',expected_sender=pub_bytes(sender),
                    resume_dir=(tmp_path/'resume'))
        assert (tmp_path/'restored').read_bytes()==content
    finally:
        server_a.shutdown();server_a.server_close()
        server_b.shutdown();server_b.server_close()


def test_authenticated_st81_identity_cannot_take_all_slots(tmp_path):
    peers=[K() for _ in range(2)]
    node=K()
    server=BulkServer(('127.0.0.1',0),node,tmp_path/'n.db',
                      {pub_bytes(p) for p in peers},max_connections=12)
    serve_background(server)
    connections=[]
    target=Peer('127.0.0.1',server.server_address[1],pub_bytes(node))
    try:
        for _ in range(8):
            connections.append(BulkClient(target,peers[0]))
        # Same peer exceeds its allocation but another allowed peer can still connect.
        from innernet2.bulk_v080 import BulkError
        with pytest.raises((OSError,ValueError,EOFError,BulkError)):
            with BulkClient(target,peers[0]) as c:
                c.call('ping')
        with BulkClient(target,peers[1]) as c:
            assert c.call('ping')[0]['pong']
    finally:
        for conn in connections:conn.close()
        server.shutdown();server.server_close()


def test_unknown_mailbox_cursor_returns_authenticated_error(tmp_path):
    from innernet2.mailbox_wire import request, handle_request, parse_response
    db=MailboxStore(tmp_path/'m.sqlite')
    try:
        recipient=pub_bytes(K())
        reqid=b'R'*16
        code,body=parse_response(handle_request(db,recipient,
            request('F',b'x'*48,request_id=reqid)),reqid)
        assert code=='E' and body==b'F'
    finally:
        db.close()
