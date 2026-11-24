"""New experimental bulk/relay/security/resumption regression checks."""
import json
import os
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from innernet2.bulk_v080 import (
    prepare_file,verify_manifest,ChunkStore,BulkError,load_prepared,
    decrypt_package,CHUNK_SIZE)
from innernet2.mailbox_e2ee import generate_bundle,load_recipient_secret
from innernet2.native_udp import pub_bytes
from innernet2.relay_v090 import BulkClient,BulkServer,Peer,serve_background
from innernet2.transit_v100 import run_demo,fetch_any

@pytest.fixture
def prepared(tmp_path):
    tmp_path.chmod(0o700)
    sender=Ed25519PrivateKey.generate()
    recipient=Ed25519PrivateKey.generate()
    bundle=generate_bundle(recipient,tmp_path/'recipient.key')
    source=tmp_path/'input.dat'
    source.write_bytes(b'SYNTHETIC:' + os.urandom(CHUNK_SIZE*3))
    obj=prepare_file(source,sender,bundle, expected_recipient=bytes.fromhex((bundle)["payload"]["identity_ed25519"]))
    return obj,sender,recipient,bundle,load_recipient_secret(tmp_path/'recipient.key')


def test_chunk_size_bounded(prepared):
    obj,*_=prepared
    assert len(obj.chunk(0))==CHUNK_SIZE+16
    assert len(obj.chunk(3))==len(b'SYNTHETIC:')+16


def test_signed_manifest_tamper_rejected(prepared):
    obj,*_=prepared
    bad=json.loads(json.dumps(obj.record));bad['payload']['size']-=1
    with pytest.raises(BulkError): verify_manifest(bad)


def test_unsigned_digest_hidden(prepared):
    import hashlib
    obj,*_=prepared
    assert hashlib.sha256(obj.source.read_bytes()).hexdigest() not in json.dumps(obj.record)


def test_store_ciphertext_only_and_dedup(prepared,tmp_path):
    obj,*_=prepared
    store=ChunkStore(tmp_path/'state.db')
    ident=obj.payload['object_id']
    try:
        assert store.manifest(obj.record)
        assert not store.manifest(obj.record)
        assert store.put(ident,0,obj.chunk(0))=='STORED'
        assert store.put(ident,0,obj.chunk(0))=='DUPLICATE'
        assert store.get(ident,0)!=obj.source.read_bytes()[:CHUNK_SIZE]
        assert len(store.missing(ident))==obj.payload['chunks']-1
    finally:store.close()


def test_tampered_ciphertext_is_rejected_by_storage(prepared,tmp_path):
    obj,*_=prepared
    store=ChunkStore(tmp_path/'state.db')
    try:
        store.manifest(obj.record)
        blob=bytearray(obj.chunk(0));blob[0]^=1
        with pytest.raises(BulkError,match='fingerprint'):store.put(obj.payload['object_id'],0,bytes(blob))
    finally:store.close()


def test_decrypt_and_corruption(prepared,tmp_path):
    obj,sender,recipient,bundle,secret=prepared
    chunks=[obj.chunk(i) for i in range(obj.payload['chunks'])]
    result=decrypt_package(obj.record,recipient,secret,chunks,tmp_path/'out.bin')
    assert result['status']=='PASS'
    assert (tmp_path/'out.bin').read_bytes()==obj.source.read_bytes()
    chunks[0]=bytes([chunks[0][0]^1])+chunks[0][1:]
    with pytest.raises(BulkError):decrypt_package(obj.record,recipient,secret,chunks,tmp_path/'bad.bin')
    assert not (tmp_path/'bad.bin').exists()


def test_sender_resume_and_mutation_detection(prepared,tmp_path):
    obj,sender,recipient,bundle,secret=prepared
    checkpoint=tmp_path/'checkpoint.json'
    obj.save(checkpoint)
    with pytest.raises(BulkError,match='overwrite'):obj.save(checkpoint)
    resumed=load_prepared(checkpoint,sender,bundle)
    assert resumed.chunk(0)==obj.chunk(0)
    obj.source.write_bytes(obj.source.read_bytes().replace(b'SYNTHETIC:',b'SYNTHETIC;'))
    with pytest.raises(BulkError,match='mutated'):resumed.chunk(0)


def test_new_integrated_relay_flow():
    outcome=run_demo(1,window=8)
    assert outcome['status']=='PASS'
    assert outcome['v090_failed_primary_fallback']==1
    assert outcome['v090_forwarding']['replica_complete']


def test_unauthorized_client_denied(prepared,tmp_path):
    obj,sender,recipient,bundle,secret=prepared
    server_key=Ed25519PrivateKey.generate()
    server=BulkServer(('127.0.0.1',0),server_key,tmp_path/'server.db',{pub_bytes(sender)})
    peer=Peer('127.0.0.1',server.server_address[1],pub_bytes(server_key))
    serve_background(server)
    try:
        with pytest.raises((OSError,ValueError)):
            with BulkClient(peer,Ed25519PrivateKey.generate(),timeout=1) as link:
                link.call('ping')
    finally:
        server.shutdown();server.server_close()


def test_replay_manifest_as_different_sender_rejected(prepared,tmp_path):
    obj,sender,recipient,bundle,secret=prepared
    server_key=Ed25519PrivateKey.generate()
    stranger=Ed25519PrivateKey.generate()
    server=BulkServer(('127.0.0.1',0),server_key,tmp_path/'server.db',
                       {pub_bytes(sender),pub_bytes(stranger)})
    peer=Peer('127.0.0.1',server.server_address[1],pub_bytes(server_key))
    serve_background(server)
    try:
        with BulkClient(peer,stranger) as link:
            with pytest.raises(BulkError,match='only owner'):
                link.call('manifest',record=obj.record)
    finally:
        server.shutdown();server.server_close()


def test_signed_route_plan_and_tamper(prepared):
    from innernet2.routing_v090 import sign_plan,verify_plan,recipient_peers
    import time
    obj,sender,recipient,bundle,secret=prepared
    signer=Ed25519PrivateKey.generate()
    endpoint_key=Ed25519PrivateKey.generate()
    now=int(time.time())
    payload={'version':'R90-ROUTE-1','issued_at':now,'expires_at':now+500,
             'nodes':[{'id':'a','host':'127.0.0.1','port':12345,
                       'public_ed25519':pub_bytes(endpoint_key).hex(),'failure_domain':'lab'}],
             'routes':[{'recipient':pub_bytes(recipient).hex(),'ordered_nodes':['a']}]}
    plan=sign_plan(payload,signer)
    assert len(recipient_peers(plan,pub_bytes(signer),pub_bytes(recipient)))==1
    with pytest.raises(BulkError,match='not pinned'):
        verify_plan(plan,pub_bytes(Ed25519PrivateKey.generate()))
    modified=json.loads(json.dumps(plan));modified['payload']['nodes'][0]['port']=12346
    with pytest.raises(BulkError,match='signature invalid'):
        verify_plan(modified,pub_bytes(signer))
    with pytest.raises(BulkError,match='expired'):
        verify_plan(plan,pub_bytes(signer),now=now+501)


def test_duplicate_node_failure_in_routes(prepared):
    from innernet2.routing_v090 import sign_plan
    import time
    obj,sender,recipient,bundle,secret=prepared
    signer=Ed25519PrivateKey.generate();pub=pub_bytes(signer).hex();now=int(time.time())
    payload={'version':'R90-ROUTE-1','issued_at':now,'expires_at':now+500,
             'nodes':[{'id':'a','host':'127.0.0.1','port':12345,
                       'public_ed25519':pub,'failure_domain':'lab'}],
             'routes':[{'recipient':pub_bytes(recipient).hex(),'ordered_nodes':['a','a']}]}
    with pytest.raises(BulkError):sign_plan(payload,signer)


def test_public_bind_requires_explicit_operator_opt_in(prepared,tmp_path):
    from innernet2.node_cli_v100 import main
    identity=Ed25519PrivateKey.generate()
    from innernet2.native_udp import generate_identity_file
    key=tmp_path/'server.key'
    generate_identity_file(key)
    with pytest.raises(SystemExit,match='Refusing public bind'):
        main(['serve','--key',str(key),'--db',str(tmp_path/'node.db'),
              '--host','0.0.0.0','--allow-client',pub_bytes(identity).hex()])
