"""v1.0 candidate application envelope, fail-closed, and true ST80/OB80 integration."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import os
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from innernet2.universal_v1 import pack, unpack, inspect, assemble_stream, UniversalError
from innernet2.universal_transport_v1 import publish, receive
from innernet2.mailbox_e2ee import generate_bundle, load_recipient_secret
from innernet2.native_udp import pub_bytes
from innernet2.relay_v090 import BulkServer, Peer, BulkClient, serve_background
from innernet2.routing_v090 import sign_plan
from innernet2.bulk_v080 import BulkError


def create(path, payload):
    path.write_bytes(payload)
    return path


def test_message_roundtrip(tmp_path):
    raw = 'Hello from a bounded UTF-8 message! 🌍'.encode()
    pack(create(tmp_path/'text',raw),tmp_path/'message.uv10',kind='message',content_type='text/plain',name='message.txt',now=100)
    assert inspect(tmp_path/'message.uv10')['size'] == len(raw)
    assert (tmp_path/'message.uv10').stat().st_mode & 0o077 == 0
    assert unpack(tmp_path/'message.uv10',tmp_path/'out')['sha256'] == hashlib.sha256(raw).hexdigest()
    assert (tmp_path/'out').read_bytes() == raw


def test_file_roundtrip_bounded(tmp_path):
    raw = os.urandom(1024*1024+87)
    pack(create(tmp_path/'file',raw),tmp_path/'file.uv10',kind='file',content_type='application/octet-stream',name='blob.bin')
    unpack(tmp_path/'file.uv10',tmp_path/'out')
    assert (tmp_path/'out').read_bytes() == raw


def test_event_json_required(tmp_path):
    path = create(tmp_path/'event',b'{"type":"ready","count":1}')
    pack(path,tmp_path/'event.uv10',kind='event',content_type='application/json',name='evt')
    assert unpack(tmp_path/'event.uv10',tmp_path/'out')['kind']=='event'
    with pytest.raises(UniversalError, match='JSON'):
        pack(create(tmp_path/'bad',b'{not json}'),tmp_path/'bad.uv10',kind='event',content_type='application/json')


def test_reject_traversal_overwrite_symlink(tmp_path):
    raw = create(tmp_path/'raw',b'hello')
    with pytest.raises(UniversalError,match='unsafe'):
        pack(raw,tmp_path/'x',kind='file',content_type='application/octet-stream',name='../secret')
    pack(raw,tmp_path/'x',kind='file',content_type='application/octet-stream')
    with pytest.raises(UniversalError,match='existing'):
        pack(raw,tmp_path/'x',kind='file',content_type='application/octet-stream')
    (tmp_path/'linked').symlink_to(raw)
    with pytest.raises(UniversalError,match='symlink'):
        pack(tmp_path/'linked',tmp_path/'y',kind='file',content_type='application/octet-stream')
    create(tmp_path/'out',b'CANARY')
    with pytest.raises(UniversalError,match='existing'):
        unpack(tmp_path/'x',tmp_path/'out')
    assert (tmp_path/'out').read_bytes()==b'CANARY'


def test_reject_payload_mutation_and_extra_bytes(tmp_path):
    pack(create(tmp_path/'raw',b'HELLO'),tmp_path/'x',kind='file',content_type='text/plain')
    with (tmp_path/'x').open('r+b') as f:
        f.seek(-1,os.SEEK_END); f.write(b'X')
    with pytest.raises(UniversalError,match='digest mismatch'):
        unpack(tmp_path/'x',tmp_path/'out')
    assert not (tmp_path/'out').exists()
    with (tmp_path/'x').open('ab') as f:f.write(b'junk')
    with pytest.raises(UniversalError,match='trailing'):
        inspect(tmp_path/'x')


def test_reject_invalid_header(tmp_path):
    path=tmp_path/'bad'
    path.write_bytes(b'UV10'+(5000).to_bytes(4,'big'))
    with pytest.raises(UniversalError,match='header length'):
        inspect(path)


def test_stream_three_segments_out_of_order(tmp_path):
    ident='a'*32
    parts=[]
    for i,msg in enumerate((b'hello',b' world',b'!')):
        raw=create(tmp_path/f'raw{i}',msg)
        stage=tmp_path/f'seg{i}.uv10'
        pack(raw,stage,kind='stream-segment',content_type='application/octet-stream',
             stream_id=ident,sequence=i,final=i==2)
        parts.append(stage)
    state=assemble_stream([parts[2],parts[0],parts[1]],tmp_path/'joined')
    assert state['segments']==3
    assert (tmp_path/'joined').read_bytes()==b'hello world!'


def test_stream_reject_missing_final_duplicate_and_gap(tmp_path):
    ident='b'*32
    parts=[]
    for i in (0,2):
        path=tmp_path/f'{i}.uv10'
        pack(create(tmp_path/f'{i}.data',b'x'),path,kind='stream-segment',
             content_type='text/plain',stream_id=ident,sequence=i,final=i==2)
        parts.append(path)
    with pytest.raises(UniversalError,match='gap'):
        assemble_stream(parts,tmp_path/'out')
    with pytest.raises(UniversalError,match='duplicate'):
        assemble_stream([parts[0],parts[0]],tmp_path/'out')
    assert not (tmp_path/'out').exists()


def test_reject_unbounded_attributes_and_bad_content_type(tmp_path):
    src=create(tmp_path/'text',b'data')
    with pytest.raises(UniversalError):
        pack(src,tmp_path/'x',kind='file',content_type='not-a-mime')
    with pytest.raises(UniversalError,match='attributes'):
        pack(src,tmp_path/'x',kind='file',content_type='application/json',attributes={'x':'a'*161})


def test_authenticated_publish_receive_with_fallback_and_sender_pin(tmp_path):
    sender=Ed25519PrivateKey.generate(); recipient=Ed25519PrivateKey.generate()
    operator=Ed25519PrivateKey.generate(); node_a=Ed25519PrivateKey.generate();node_b=Ed25519PrivateKey.generate()
    bundle=generate_bundle(recipient,tmp_path/'recv.secret')
    secret=load_recipient_secret(tmp_path/'recv.secret')
    source=create(tmp_path/'source',b'Universal message from an authenticated sender')
    stage=tmp_path/'stage.uv10'
    pack(source,stage,kind='message',content_type='text/plain',name='hello.txt')
    s_b=BulkServer(('127.0.0.1',0),node_b,tmp_path/'B.sqlite',
                   {pub_bytes(node_a),pub_bytes(recipient)},relays={pub_bytes(node_a)})
    p_b=Peer('127.0.0.1',s_b.server_address[1],pub_bytes(node_b))
    s_a=BulkServer(('127.0.0.1',0),node_a,tmp_path/'A.sqlite',
                   {pub_bytes(sender),pub_bytes(recipient)},peers={'replica-b':p_b})
    p_a=Peer('127.0.0.1',s_a.server_address[1],pub_bytes(node_a))
    serve_background(s_a);serve_background(s_b)
    try:
        sent=publish(stage,sender,bundle,p_a,checkpoint=tmp_path/'sender.ckpt', expected_recipient=bytes.fromhex((bundle)["payload"]["identity_ed25519"]))
        assert sent['status']=='COMMITTED_TO_RELAY'
        with BulkClient(p_a,sender) as c:
            assert c.call('forward',ident=sent['object_id'],peer_id='replica-b')[0]['replica_complete']
        now=int(time.time())
        signed=sign_plan({'version':'R90-ROUTE-1','issued_at':now,'expires_at':now+3600,
            'nodes':[{'id':'a','host':p_a.host,'port':p_a.port,'public_ed25519':p_a.pinned_key.hex(),'failure_domain':'test-a'},
                     {'id':'b','host':p_b.host,'port':p_b.port,'public_ed25519':p_b.pinned_key.hex(),'failure_domain':'test-b'}],
            'routes':[{'recipient':pub_bytes(recipient).hex(),'ordered_nodes':['a','b']}]},operator)
        s_a.shutdown();s_a.server_close()
        with pytest.raises(BulkError,match='all 2'):
            receive(signed,pub_bytes(operator),sent['object_id'],recipient,secret,
                    pub_bytes(Ed25519PrivateKey.generate()),tmp_path/'bad-output')
        assert not (tmp_path/'bad-output').exists()
        result=receive(signed,pub_bytes(operator),sent['object_id'],recipient,secret,
                       pub_bytes(sender),tmp_path/'received')
        assert result['status']=='VERIFIED_APPLICATION_DELIVERY'
        assert result['failed_prior_nodes']==1
        assert (tmp_path/'received').read_bytes()==source.read_bytes()
        with pytest.raises(UniversalError,match='existing'):
            receive(signed,pub_bytes(operator),sent['object_id'],recipient,secret,
                    pub_bytes(sender),tmp_path/'received')
    finally:
        s_a.server_close();s_b.shutdown();s_b.server_close()
