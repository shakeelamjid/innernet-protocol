"""Independent adversarial checks added after the RC2 external static review.

These tests run solely on loopback/temp files. No public listeners or VPS changes.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import sqlite3
import struct
import subprocess
import time
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from innernet2.crypto import new_root,derive,encrypt_metadata,interleave,deinterleave
from innernet2.native_udp import NativeResponder,pub_bytes,ephemeral_pub,hello_packet
from innernet2.relay_v090 import BulkClient,BulkServer,Peer,serve_background
from innernet2.bulk_v080 import BulkError,prepare_file
from innernet2.mailbox_e2ee import generate_bundle,load_recipient_secret
from innernet2.mailbox_store import MailboxStore, MailboxError
from innernet2.mailbox_wire import request,handle_request,parse_response
from innernet2.universal_v1 import pack,inspect,UniversalError

K=Ed25519PrivateKey.generate


def test_sender_pin_required_before_recipient_network_fetch(tmp_path):
    sender,recipient,node=K(),K(),K()
    bundle=generate_bundle(recipient,tmp_path/'r.key')
    secret=load_recipient_secret(tmp_path/'r.key')
    src=tmp_path/'in';src.write_bytes(b'SYNTHETIC:verified')
    obj=prepare_file(src,sender,bundle, expected_recipient=bytes.fromhex((bundle)["payload"]["identity_ed25519"]))
    srv=BulkServer(('127.0.0.1',0),node,tmp_path/'d.db',{pub_bytes(sender),pub_bytes(recipient)})
    serve_background(srv); peer=Peer('127.0.0.1',srv.server_address[1],pub_bytes(node))
    try:
        with BulkClient(peer,sender) as c:c.upload(obj)
        with BulkClient(peer,recipient) as c:
            with pytest.raises(BulkError,match='explicitly pinned'):
                c.fetch(obj.payload['object_id'],recipient,secret,tmp_path/'bad')
            with pytest.raises(BulkError,match='unexpected original sender'):
                c.fetch(obj.payload['object_id'],recipient,secret,tmp_path/'bad',expected_sender=pub_bytes(node))
            assert c.fetch(obj.payload['object_id'],recipient,secret,tmp_path/'good',expected_sender=pub_bytes(sender))['status']=='PASS'
        assert (tmp_path/'good').read_bytes()==src.read_bytes()
        assert not (tmp_path/'bad').exists()
    finally:srv.shutdown();srv.server_close()


def test_idle_unauthenticated_connections_do_not_consume_active_slots(tmp_path):
    node,client=K(),K()
    srv=BulkServer(('127.0.0.1',0),node,tmp_path/'d.db',{pub_bytes(client)},max_connections=2)
    serve_background(srv);port=srv.server_address[1]
    idle=[socket.create_connection(('127.0.0.1',port)) for _ in range(2)]
    try:
        time.sleep(.15)
        assert srv._slots._value==2  # pre-auth must not consume authenticated slots
        assert len(srv._pre_auth_ips)<=1
    finally:
        for sock in idle:sock.close()
        srv.shutdown();srv.server_close()


def test_v2_metadata_interleave_accommodates_documented_four_mib():
    root=new_root();key=derive(root,'metadata/interleave/0')
    body=b'x'*(3*1024*1024)
    mixed=interleave(body,key,64)
    assert deinterleave(mixed,key,64,len(body))==body


def test_udp_hello_cannot_create_session_again_after_expiry():
    client,server=K(),K()
    responder=NativeResponder(server,{pub_bytes(client)},lifetime=1)
    hello=hello_packet(client,pub_bytes(server),secrets.token_bytes(16),ephemeral_pub(X25519PrivateKey.generate()),secrets.token_bytes(16))
    addr=('127.0.0.1',40000)
    first=responder.process(hello,addr)
    assert first is not None
    for state in responder.sessions.values():state.created-=20
    responder._prune()
    assert responder.process(hello,('127.0.0.1',40001)) is None


def test_mailbox_sender_quota_and_cursor_skips_poison(tmp_path):
    tmp_path.chmod(0o700)
    db=MailboxStore(tmp_path/'in.db',max_rows=10)
    sender,recipient=pub_bytes(K()),pub_bytes(K())
    try:
        # RC5 adds an independent sender-recipient quota: distribute an
        # identity's eight entries across recipients while retaining cursor
        # coverage for two messages delivered to the same recipient.
        for i in range(8):
            target = recipient if i < 2 else pub_bytes(K())
            db.store(sender,target,i.to_bytes(16,'big'),b'SYNTHETIC:x',now=100+i)
        with pytest.raises(MailboxError,match='sender mailbox quota'):
            db.store(sender,pub_bytes(K()),(9).to_bytes(16,'big'),b'SYNTHETIC:quota',now=109)
        row=db.fetch(recipient,now=110)
        assert row[1]==(0).to_bytes(16,'big')
        next_row=db.fetch(recipient,now=110,after=(row[0],row[1]))
        assert next_row[1]==(1).to_bytes(16,'big')
    finally:db.close()


def test_go_rejects_noncanonical_python_frame(tmp_path):
    if shutil.which('go') is None:pytest.skip('Go is not installed')
    src=tmp_path/'x';src.write_bytes(b'SYNTHETIC:interop')
    valid=tmp_path/'ok.uv10'
    pack(src,valid,kind='message',content_type='text/plain',name='ok.txt',now=1700000000)
    data=valid.read_bytes();n=struct.unpack('>I',data[4:8])[0]
    h=json.loads(data[8:8+n]);raw=json.dumps(h,indent=1).encode()
    invalid=tmp_path/'bad.uv10';invalid.write_bytes(b'UV10'+struct.pack('>I',len(raw))+raw+data[8+n:])
    with pytest.raises(UniversalError,match='noncanonical'):inspect(invalid)
    root=Path(__file__).resolve().parents[1]/'interop/go'
    assert subprocess.run(['go','run','./uv10verify',str(valid)],cwd=root,capture_output=True,timeout=60).returncode==0
    assert subprocess.run(['go','run','./uv10verify',str(invalid)],cwd=root,capture_output=True,timeout=60).returncode!=0
