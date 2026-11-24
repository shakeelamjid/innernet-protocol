"""v0.11 streaming writer, quotas, cleanup, bounded-concurrency regressions."""
import os
import hashlib
import tracemalloc
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from innernet2.bulk_v080 import (
    BulkError, CHUNK_SIZE, ChunkStore, RecipientWriter, prepare_file,
)
from innernet2.mailbox_e2ee import generate_bundle, load_recipient_secret
from innernet2.native_udp import pub_bytes
from innernet2.relay_v090 import BulkClient, BulkServer, Peer, serve_background
from innernet2.node_cli_v100 import main as cli_main


@pytest.fixture
def prepared(tmp_path):
    tmp_path.chmod(0o700)
    sender=Ed25519PrivateKey.generate()
    recipient=Ed25519PrivateKey.generate()
    bundle=generate_bundle(recipient,tmp_path/'recipient.key')
    secret=load_recipient_secret(tmp_path/'recipient.key')
    src=tmp_path/'source.bin'
    src.write_bytes(b'SYNTHETIC:'+os.urandom(5*CHUNK_SIZE))
    return prepare_file(src,sender,bundle, expected_recipient=bytes.fromhex((bundle)["payload"]["identity_ed25519"])),sender,recipient,secret


def test_writer_streams_without_memory_spool(prepared,tmp_path):
    obj,sender,recipient,secret=prepared
    with RecipientWriter(obj.record,recipient,secret,tmp_path/'out.bin') as writer:
        for idx in range(obj.payload['chunks']):
            writer.write_chunk(obj.chunk(idx))
        assert writer.finish()['status']=='PASS'
    assert (tmp_path/'out.bin').read_bytes()==obj.source.read_bytes()
    assert not list(tmp_path.glob('out.bin.partial-*'))


def test_writer_wrong_chunk_never_publishes(prepared,tmp_path):
    obj,sender,recipient,secret=prepared
    with pytest.raises(BulkError,match='fingerprint'):
        with RecipientWriter(obj.record,recipient,secret,tmp_path/'out.bin') as writer:
            writer.write_chunk(obj.chunk(0))
            bad=bytearray(obj.chunk(1));bad[-1]^=1
            writer.write_chunk(bytes(bad))
    assert not (tmp_path/'out.bin').exists()
    assert not list(tmp_path.glob('out.bin.partial-*'))


def test_writer_does_not_overwrite_racing_output(prepared,tmp_path):
    obj,sender,recipient,secret=prepared
    with pytest.raises(BulkError,match='overwrite'):
        with RecipientWriter(obj.record,recipient,secret,tmp_path/'out.bin') as writer:
            for i in range(obj.payload['chunks']):writer.write_chunk(obj.chunk(i))
            (tmp_path/'out.bin').write_bytes(b'OTHER PROCESS DATA')
            writer.finish()
    assert (tmp_path/'out.bin').read_bytes()==b'OTHER PROCESS DATA'
    assert not list(tmp_path.glob('out.bin.partial-*'))


def test_writer_missing_chunks_rejected(prepared,tmp_path):
    obj,sender,recipient,secret=prepared
    with pytest.raises(BulkError,match='checksum'):
        with RecipientWriter(obj.record,recipient,secret,tmp_path/'out.bin') as writer:
            writer.write_chunk(obj.chunk(0))
            writer.finish()
    assert not (tmp_path/'out.bin').exists()


def test_ciphertext_quota_dedup_and_accounting(prepared,tmp_path):
    obj,*_=prepared
    store=ChunkStore(tmp_path/'a.db',max_storage_bytes=CHUNK_SIZE+16,max_objects=1)
    ident=obj.payload['object_id']
    try:
        assert store.manifest(obj.record)
        assert store.put(ident,0,obj.chunk(0))=='STORED'
        assert store.put(ident,0,obj.chunk(0))=='DUPLICATE'
        assert store.usage()['ciphertext_bytes']==CHUNK_SIZE+16
        with pytest.raises(BulkError,match='storage quota'):
            store.put(ident,1,obj.chunk(1))
        assert store.statistics(ident)['stored']==1
        with pytest.raises(BulkError,match='object quota'):
            # create a distinct signed object using the same recipient bundle
            sender=Ed25519PrivateKey.generate()
            recipient=Ed25519PrivateKey.generate()
            bundle=generate_bundle(recipient,tmp_path/'recipient2.key')
            record=prepare_file(obj.source,sender,bundle, expected_recipient=bytes.fromhex((bundle)["payload"]["identity_ed25519"])).record
            store.manifest(record)
    finally:store.close()


def test_maintenance_prunes_expired_objects_and_keeps_live(prepared,tmp_path):
    obj,*_=prepared
    store=ChunkStore(tmp_path/'store.db',max_storage_bytes=CHUNK_SIZE+16,max_objects=2)
    try:
        ident=obj.payload['object_id']
        store.manifest(obj.record)
        store.put(ident,0,obj.chunk(0))
        before=store.usage()
        assert before['objects']==1 and before['ciphertext_bytes']==CHUNK_SIZE+16
        assert store.prune_expired(now=obj.payload['expires_at']-1)['expired_objects_deleted']==0
        result=store.prune_expired(now=obj.payload['expires_at'])
        assert result['expired_objects_deleted']==1
        assert result['chunks_deleted']==1
        assert result['ciphertext_bytes_reclaimed']==CHUNK_SIZE+16
        assert result['objects']==0 and result['ciphertext_bytes']==0
        with pytest.raises(BulkError,match='missing'):
            store.get_manifest(ident)
    finally:store.close()


def test_quota_usage_persists_and_migrates_old_db(prepared,tmp_path):
    obj,*_=prepared
    db=tmp_path/'storage.db'
    with_store=ChunkStore(db)
    ident=obj.payload['object_id']
    try:
        with_store.manifest(obj.record)
        with_store.put(ident,0,obj.chunk(0))
    finally:with_store.close()
    restored=ChunkStore(db,max_storage_bytes=CHUNK_SIZE+16,max_objects=1)
    try:
        assert restored.usage()['objects']==1
        assert restored.usage()['ciphertext_bytes']==CHUNK_SIZE+16
        with pytest.raises(BulkError,match='quota'):
            restored.put(ident,1,obj.chunk(1))
    finally:restored.close()


def test_reject_invalid_window_and_connection_caps(prepared,tmp_path):
    obj,sender,recipient,secret=prepared
    key=Ed25519PrivateKey.generate()
    with pytest.raises(BulkError,match='connection cap'):
        BulkServer(('127.0.0.1',0),key,tmp_path/'x.db',{pub_bytes(sender)},max_connections=0)
    server=BulkServer(('127.0.0.1',0),key,tmp_path/'x.db',
                      {pub_bytes(sender),pub_bytes(recipient)},max_connections=2)
    serve_background(server)
    peer=Peer('127.0.0.1',server.server_address[1],pub_bytes(key))
    try:
        with BulkClient(peer,sender) as client:
            client.upload(obj,window=8)
        with BulkClient(peer,recipient) as client:
            with pytest.raises(BulkError,match='window'):
                client.fetch(obj.payload['object_id'],recipient,secret,tmp_path/'out',window=0,expected_sender=pub_bytes(sender))
    finally:server.shutdown();server.server_close()


def test_server_rejects_second_handler_when_full(prepared,tmp_path):
    obj,sender,recipient,secret=prepared
    key=Ed25519PrivateKey.generate()
    server=BulkServer(('127.0.0.1',0),key,tmp_path/'a.db',
                      {pub_bytes(sender)},max_connections=1)
    serve_background(server)
    peer=Peer('127.0.0.1',server.server_address[1],pub_bytes(key))
    try:
        with BulkClient(peer,sender) as client:
            assert client.call('ping')[0]['pong']
            with pytest.raises((OSError,ValueError)):
                with BulkClient(peer,sender,timeout=1) as second:
                    second.call('ping')
            assert client.call('ping')[0]['pong']
    finally:server.shutdown();server.server_close()


def test_node_cli_maintenance_report(prepared,tmp_path,capsys):
    obj,*_=prepared
    db=tmp_path/'node.db'
    st=ChunkStore(db)
    try:
        st.manifest(obj.record)
        st.put(obj.payload['object_id'],0,obj.chunk(0))
    finally:st.close()
    cli_main(['maintenance','--db',str(db)])
    assert 'ciphertext_bytes' in capsys.readouterr().out
    cli_main(['maintenance','--db',str(db),'--prune-expired'])
    assert 'expired_objects_deleted' in capsys.readouterr().out


def test_receiver_does_not_hold_full_payload_in_memory(tmp_path):
    """16 MiB decrypted through real TCP, assert bounded Python allocation peak."""
    tmp_path.chmod(0o700)
    sender=Ed25519PrivateKey.generate()
    recipient=Ed25519PrivateKey.generate()
    bundle=generate_bundle(recipient,tmp_path/'rec.key')
    secret=load_recipient_secret(tmp_path/'rec.key')
    src=tmp_path/'source'
    with src.open('wb') as out:
        out.write(b'SYNTHETIC:')
        for _ in range(16):out.write(os.urandom(1024*1024))
    obj=prepare_file(src,sender,bundle, expected_recipient=bytes.fromhex((bundle)["payload"]["identity_ed25519"]))
    key=Ed25519PrivateKey.generate()
    srv=BulkServer(('127.0.0.1',0),key,tmp_path/'server.db',
                   {pub_bytes(sender),pub_bytes(recipient)})
    serve_background(srv)
    peer=Peer('127.0.0.1',srv.server_address[1],pub_bytes(key))
    try:
        with BulkClient(peer,sender) as cli:
            cli.upload(obj,window=16)
        tracemalloc.start()
        try:
            with BulkClient(peer,recipient) as cli:
                result=cli.fetch(obj.payload['object_id'],recipient,secret,tmp_path/'result',window=16,expected_sender=pub_bytes(sender))
            _,peak=tracemalloc.get_traced_memory()
        finally:tracemalloc.stop()
        assert result['status']=='PASS'
        assert result['fetch_requests']==65  # 257 chunks -> ceil(257/4)
        assert peak<10*1024*1024, f'excessive peak Python memory: {peak}'
        assert hashlib.sha256((tmp_path/'result').read_bytes()).digest()==hashlib.sha256(src.read_bytes()).digest()
    finally:srv.shutdown();srv.server_close()


def test_recipient_can_resume_from_private_ciphertext_checkpoint(prepared,tmp_path):
    obj,sender,recipient,secret=prepared
    node=Ed25519PrivateKey.generate()
    srv=BulkServer(('127.0.0.1',0),node,tmp_path/'node.db',
                   {pub_bytes(sender),pub_bytes(recipient)})
    serve_background(srv)
    peer=Peer('127.0.0.1',srv.server_address[1],pub_bytes(node))
    checkpoint_dir=tmp_path/'checkpoint';checkpoint_dir.mkdir(mode=0o700)
    target=tmp_path/'received.bin'
    try:
        with BulkClient(peer,sender) as cli:
            assert cli.upload(obj,window=4)['complete']
        with BulkClient(peer,recipient) as client:
            original=client.iter_batch
            delivered=[False]
            def interrupted(batch):
                if batch[0][0].get('cmd')=='get_range':
                    if delivered[0]:
                        raise TimeoutError('injected disconnect after first authenticated range')
                    delivered[0]=True
                yield from original(batch)
            client.iter_batch=interrupted
            with pytest.raises(TimeoutError,match='injected disconnect'):
                client.fetch(obj.payload['object_id'],recipient,secret,target,
                             window=1,resume_dir=checkpoint_dir,expected_sender=pub_bytes(sender))
        assert not target.exists()
        db=checkpoint_dir/('innernet-recv-'+obj.payload['object_id']+'.sqlite')
        assert db.is_file() and db.stat().st_mode & 0o077==0
        store=ChunkStore(db)
        try: assert store.statistics(obj.payload['object_id'])['stored']==4
        finally:store.close()
        with BulkClient(peer,recipient) as cli:
            result=cli.fetch(obj.payload['object_id'],recipient,secret,target,
                             window=2,resume_dir=checkpoint_dir,expected_sender=pub_bytes(sender))
        assert result['status']=='PASS'
        assert result['recipient_cached_chunks']==4
        assert result['recipient_downloaded_chunks']==obj.payload['chunks']-4
        assert not db.exists()
        assert target.read_bytes()==obj.source.read_bytes()
    finally:srv.shutdown();srv.server_close()


def test_resume_directory_requires_owner_only_mode(prepared,tmp_path):
    obj,sender,recipient,secret=prepared
    node=Ed25519PrivateKey.generate()
    srv=BulkServer(('127.0.0.1',0),node,tmp_path/'db',
                   {pub_bytes(sender),pub_bytes(recipient)})
    serve_background(srv)
    peer=Peer('127.0.0.1',srv.server_address[1],pub_bytes(node))
    insecure=tmp_path/'insecure';insecure.mkdir(mode=0o755)
    try:
        with BulkClient(peer,sender) as client:client.upload(obj,window=4)
        with BulkClient(peer,recipient) as client:
            with pytest.raises(BulkError,match='owner-only'):
                client.fetch(obj.payload['object_id'],recipient,secret,tmp_path/'out',resume_dir=insecure,expected_sender=pub_bytes(sender))
    finally:srv.shutdown();srv.server_close()


def test_recipient_checkpoint_can_fallback_after_primary_outage(prepared,tmp_path):
    from innernet2.transit_v100 import fetch_any
    obj,sender,recipient,secret=prepared
    key_a=Ed25519PrivateKey.generate();key_b=Ed25519PrivateKey.generate()
    a=BulkServer(('127.0.0.1',0),key_a,tmp_path/'a.db',
                 {pub_bytes(sender),pub_bytes(recipient)})
    b=BulkServer(('127.0.0.1',0),key_b,tmp_path/'b.db',
                 {pub_bytes(sender),pub_bytes(recipient)})
    serve_background(a);serve_background(b)
    pa=Peer('127.0.0.1',a.server_address[1],pub_bytes(key_a))
    pb=Peer('127.0.0.1',b.server_address[1],pub_bytes(key_b))
    private=tmp_path/'resume';private.mkdir(mode=0o700)
    try:
        with BulkClient(pa,sender) as client: client.upload(obj,window=8)
        with BulkClient(pb,sender) as client: client.upload(obj,window=8)
        with BulkClient(pa,recipient) as client:
            original=client.iter_batch
            delivered=[False]
            def interrupted(cmds):
                if cmds[0][0].get('cmd')=='get_range':
                    if delivered[0]:
                        raise TimeoutError('simulated connection failure')
                    delivered[0]=True
                yield from original(cmds)
            client.iter_batch=interrupted
            with pytest.raises(TimeoutError):
                client.fetch(obj.payload['object_id'],recipient,secret,
                             tmp_path/'received',window=1,resume_dir=private,expected_sender=pub_bytes(sender))
        a.shutdown();a.server_close()
        result=fetch_any([pa,pb],obj.payload['object_id'],recipient,secret,
                         tmp_path/'received',window=8,resume_dir=private,expected_sender=pub_bytes(sender))
        assert result['failed_prior_nodes']==1
        assert result['recipient_cached_chunks']==4
        assert result['sha256']==hashlib.sha256(obj.source.read_bytes()).hexdigest()
        assert not list(private.iterdir())
    finally:
        b.shutdown();b.server_close()
        try:a.server_close()
        except OSError:pass
