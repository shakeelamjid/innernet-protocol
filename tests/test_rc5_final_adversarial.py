"""Adversarial regressions for final RC5 hardening. All synthetic/loopback."""
import hashlib, json, os, secrets, struct, subprocess, shutil
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from innernet2.bulk_v080 import ChunkStore, BulkError, prepare_file
from innernet2.native_udp import pub_bytes
from innernet2.mailbox_e2ee import E2EEError, generate_bundle, seal_message
from innernet2.object_transfer import queue_object
from innernet2.mailbox_store import MailboxStore, MailboxError, OutboxStore
from innernet2.transit_v100 import fetch_any
from innernet2.relay_v090 import Peer
from innernet2.universal_v1 import inspect, UniversalError
from innernet2.crypto import parse_read_capability
from innernet2.network import INNERnetError

K=Ed25519PrivateKey.generate
ROOT=Path(__file__).resolve().parents[1]


def test_ob80_rejects_substituted_recipient_bundle(tmp_path):
    tmp_path.chmod(0o700)
    sender,victim,attacker=K(),K(),K()
    bundle=generate_bundle(attacker,tmp_path/'a.key')
    f=tmp_path/'sample'; f.write_bytes(b'SYNTHETIC:private')
    with pytest.raises((BulkError,E2EEError)):
        prepare_file(f,sender,bundle,expected_recipient=pub_bytes(victim))


def test_ie60_rejects_substituted_recipient_bundle(tmp_path):
    tmp_path.chmod(0o700)
    sender,victim,attacker=K(),K(),K()
    bundle=generate_bundle(attacker,tmp_path/'a.key')
    with pytest.raises(E2EEError):
        seal_message(sender,bundle,b'0'*16,b'SYNTHETIC:private', expected_recipient=pub_bytes(victim))


def test_r90_fails_over_on_malformed_reply(monkeypatch,tmp_path):
    from innernet2 import transit_v100
    seen=[]
    class Fake:
        def __init__(self, peer, identity, timeout=3):self.peer=peer
        def __enter__(self):return self
        def __exit__(self,*args):return False
        def fetch(self,*args,**kw):
            seen.append(self.peer.port)
            if self.peer.port==1:raise KeyError('record')
            return {'status':'PASS','sha256':'0'*64}
    monkeypatch.setattr(transit_v100,'BulkClient',Fake)
    peers=[Peer('127.0.0.1',1,b'1'*32), Peer('127.0.0.1',2,b'2'*32)]
    result=fetch_any(peers,'00'*16,K(),None,tmp_path/'out',expected_sender=b's'*32)
    assert result['failed_prior_nodes']==1 and seen==[1,2]


def test_single_object_checkpoint_uses_full_quota(tmp_path):
    tmp_path.chmod(0o700)
    sender,rcpt=K(),K()
    bundle=generate_bundle(rcpt,tmp_path/'r.key')
    f=tmp_path/'object'; f.write_bytes(b'SYNTHETIC:'+os.urandom(20*65536))
    obj=prepare_file(f,sender,bundle,expected_recipient=pub_bytes(rcpt))
    size=sum(len(obj.chunk(i)) for i in range(obj.payload['chunks']))
    db=ChunkStore(tmp_path/'checkpoint.sqlite',max_storage_bytes=size,max_objects=1)
    try:
        db.manifest(obj.record)
        for i in range(obj.payload['chunks']):db.put(obj.payload['object_id'],i,obj.chunk(i))
        assert db.missing(obj.payload['object_id'])==[]
    finally:db.close()


def test_one_sender_cannot_block_an_entire_inbox(tmp_path):
    tmp_path.chmod(0o700)
    db=MailboxStore(tmp_path/'m.sqlite',max_rows=12)
    spammer,friend,rcpt=[pub_bytes(K()) for _ in range(3)]
    try:
        for i in range(12):
            try:db.store(spammer,rcpt,i.to_bytes(16,'big'),b'x',now=100)
            except MailboxError:break
        assert db.store(friend,rcpt,b'F'*16,b'legit',now=101)[0]=='STORED'
    finally:db.close()


def test_v3_admin_required_before_repair_writes(mesh,monkeypatch):
    client,folder,_=mesh
    f=folder/'v3-target';f.write_bytes(os.urandom(10000))
    stats=client.upload_file(f,chunk_bytes=4096,capability_version=3)
    writes=[]
    monkeypatch.setattr(client,'put_fragment',lambda *a,**k:writes.append(1))
    with pytest.raises((ValueError,INNERnetError)):
        client.repair_file(stats['capability'])
    assert writes==[]


def test_uv10_rejects_lone_surrogate(tmp_path):
    h={'attributes':{},'content_type':'text/plain','created_at':0,'final':None,'kind':'file',
       'name':'a\ud800','sequence':None,'sha256':hashlib.sha256(b'').hexdigest(),
       'size':0,'stream_id':None,'version':'UV10-1'}
    raw=json.dumps(h,sort_keys=True,separators=(',',':')).encode()
    f=tmp_path/'bad.uv10';f.write_bytes(b'UV10'+struct.pack('>I',len(raw))+raw)
    with pytest.raises(UniversalError): inspect(f)


def test_v3_is_default_for_new_mesh_uploads(mesh):
    client,folder,_=mesh
    f=folder/'default';f.write_bytes(os.urandom(8000))
    result=client.upload_file(f,chunk_bytes=4096)
    _,_,v3=parse_read_capability(result['capability'])
    assert v3 and result['admin_capability'].startswith('inna_')


def test_go_ci_build_is_safe(tmp_path):
    if not shutil.which('go'):pytest.skip('Go not installed')
    result=subprocess.run(['go','build','-o',str(tmp_path/'uv10verify'),'./uv10verify'],cwd=ROOT/'interop/go',capture_output=True,text=True,timeout=120)
    assert result.returncode==0,result.stderr


def test_mailbox_reject_requires_recipient_authentication_and_persists(tmp_path):
    from innernet2.mailbox_wire import request, handle_request, parse_response
    tmp_path.chmod(0o700)
    sender,receiver,outsider=[pub_bytes(K()) for _ in range(3)]
    mid=secrets.token_bytes(16)
    path=tmp_path/'m.db'
    db=MailboxStore(path)
    try:
        db.store(sender,receiver,mid,b'SYNTHETIC:unreadable')
        reject=request('R',sender+mid)
        code, body=parse_response(handle_request(db,outsider,reject),reject[5:21])
        assert code=='E' and db.fetch(receiver) is not None
        code, body=parse_response(handle_request(db,receiver,reject),reject[5:21])
        assert code=='R' and body==mid
        assert db.fetch(receiver) is None
        assert db.status(sender,mid)=='REJECTED'
        assert db.store(sender,receiver,mid,b'SYNTHETIC:unreadable')[0]=='DUPLICATE'
    finally:db.close()
    reopened=MailboxStore(path)
    try:assert reopened.status(sender,mid)=='REJECTED'
    finally:reopened.close()


def test_preauth_oldest_evicted_when_budget_full(tmp_path):
    import socket
    from innernet2.relay_v090 import BulkServer
    node,cli=K(),K()
    srv=BulkServer(('127.0.0.1',0),node,tmp_path/'node.db',{pub_bytes(cli)},max_connections=2)
    sockets=[]
    try:
        for i in range(64):
            a,b=socket.socketpair(); sockets.append((a,b))
            assert srv.verify_request(a,(f'192.0.2.{i+1}',i+1000))
        assert len(srv._pre_auth_sockets)==64
        new,b=socket.socketpair();sockets.append((new,b))
        assert srv.verify_request(new,('198.51.100.2',9000))
        assert len(srv._pre_auth_sockets)==64
        assert sockets[0][0] not in srv._pre_auth_sockets
        assert new in srv._pre_auth_sockets
    finally:
        for a,b in sockets:
            srv.release_pre_auth(a)
            a.close();b.close()
        srv.server_close()


def test_sender_counters_consistent_across_restart_and_expiry(tmp_path):
    tmp_path.chmod(0o700)
    s,r=K(),K(); bundle=generate_bundle(r,tmp_path/'r.key')
    data=tmp_path/'f';data.write_bytes(b'SYNTHETIC:'+os.urandom(70000))
    obj=prepare_file(data,s,bundle,expected_recipient=pub_bytes(r),ttl=60)
    path=tmp_path/'store.db';db=ChunkStore(path,max_objects=10,max_storage_bytes=1000000)
    try:
        db.manifest(obj.record)
        for i in range(obj.payload['chunks']):db.put(obj.payload['object_id'],i,obj.chunk(i))
        used=db.usage()['ciphertext_bytes']
        assert used==sum(len(obj.chunk(i)) for i in range(obj.payload['chunks']))
        assert db.db.execute('SELECT payload_bytes FROM sender_usage').fetchone()[0]==used
    finally:db.close()
    db=ChunkStore(path,max_objects=10,max_storage_bytes=1000000)
    try:
        assert db.db.execute('SELECT payload_bytes FROM sender_usage').fetchone()[0]==used
        assert db.prune_expired(now=obj.payload['expires_at']+1)['ciphertext_bytes_reclaimed']==used
        assert db.db.execute('SELECT payload_bytes FROM sender_usage').fetchone()[0]==0
    finally:db.close()


def test_required_recipient_pin_is_not_optional(tmp_path):
    tmp_path.chmod(0o700)
    sender,recipient=K(),K()
    bundle=generate_bundle(recipient,tmp_path/'r.key')
    src=tmp_path/'f';src.write_bytes(b'SYNTHETIC:test')
    with pytest.raises(TypeError):prepare_file(src,sender,bundle)
    with pytest.raises(TypeError):seal_message(sender,bundle,b'0'*16,b'SYNTHETIC:test')
    with pytest.raises(TypeError):queue_object(sender,bundle,None,b'SYNTHETIC:test')
