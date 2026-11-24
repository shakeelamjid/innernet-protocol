"""v0.11 TCP read coalescing and public-broker transport tests (all offline)."""
import hashlib
import os
from pathlib import Path
import socketserver
import struct
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from innernet2.bulk_v080 import (prepare_file, CHUNK_SIZE, ChunkStore, BulkError)
from innernet2.mailbox_e2ee import generate_bundle, load_recipient_secret
from innernet2.native_udp import pub_bytes
from innernet2.relay_v090 import BulkServer, BulkClient, Peer, serve_background
from innernet2.public_mqtt_v110 import (
    _frame, _varint, _read_packet, _parse_publish, _utf8,
    PublicRelayError, relay_probe, _connect_mqtt
)

@pytest.fixture
def setup_obj(tmp_path):
    tmp_path.chmod(0o700)
    sender=Ed25519PrivateKey.generate()
    recipient=Ed25519PrivateKey.generate()
    bundle=generate_bundle(recipient,tmp_path/'recipient.key')
    secret=load_recipient_secret(tmp_path/'recipient.key')
    src=tmp_path/'source.dat'
    src.write_bytes(b'SYNTHETIC:'+os.urandom(CHUNK_SIZE*10))
    obj=prepare_file(src,sender,bundle, expected_recipient=bytes.fromhex((bundle)["payload"]["identity_ed25519"]))
    return obj,sender,recipient,secret


def test_range_store_bounds_and_missing(setup_obj,tmp_path):
    obj,*_=setup_obj
    store=ChunkStore(tmp_path/'chunks.db');ident=obj.payload['object_id']
    try:
        store.manifest(obj.record)
        store.put(ident,0,obj.chunk(0))
        with pytest.raises(BulkError,match='missing'):store.get_range(ident,0,2)
        assert store.get_range(ident,0,1)==obj.chunk(0)
        for start,count in [(0,5),(-1,1),(0,0),(0,True),(True,1),(100,1)]:
            with pytest.raises(BulkError):store.get_range(ident,start,count)
        for i in range(1,4):store.put(ident,i,obj.chunk(i))
        assert store.get_range(ident,0,4)==b''.join(obj.chunk(i) for i in range(4))
    finally:store.close()


def test_fast_fetch_coalesces_authentic_frames(setup_obj,tmp_path):
    obj,sender,recipient,secret=setup_obj
    key=Ed25519PrivateKey.generate()
    server=BulkServer(('127.0.0.1',0),key,tmp_path/'server.db',
                      {pub_bytes(sender),pub_bytes(recipient)})
    serve_background(server)
    peer=Peer('127.0.0.1',server.server_address[1],pub_bytes(key))
    try:
        with BulkClient(peer,sender) as client:
            assert client.upload(obj,window=8)['complete']
        with BulkClient(peer,recipient) as client:
            result=client.fetch(obj.payload['object_id'],recipient,secret,tmp_path/'retrieved.dat',window=4,expected_sender=pub_bytes(sender))
        assert result['status']=='PASS'
        assert result['fetch_mode']=='get-range-v1'
        assert result['fetch_requests']==3  # 11 chunks, grouped 4+4+3
        assert hashlib.sha256((tmp_path/'retrieved.dat').read_bytes()).digest()==hashlib.sha256(obj.source.read_bytes()).digest()
    finally:server.shutdown();server.server_close()


def test_legacy_peer_negotiation_falls_back(setup_obj,tmp_path):
    obj,sender,recipient,secret=setup_obj
    key=Ed25519PrivateKey.generate()
    server=BulkServer(('127.0.0.1',0),key,tmp_path/'db',
                      {pub_bytes(sender),pub_bytes(recipient)})
    serve_background(server)
    peer=Peer('127.0.0.1',server.server_address[1],pub_bytes(key))
    class PretendOldServer(BulkClient):
        def call(self, command, **fields):
            if command=='ping':
                return [{'pong':True}]
            return super().call(command,**fields)
    try:
        with BulkClient(peer,sender) as client:client.upload(obj,window=8)
        with PretendOldServer(peer,recipient) as client:
            result=client.fetch(obj.payload['object_id'],recipient,secret,tmp_path/'legacy.dat',window=4,expected_sender=pub_bytes(sender))
        assert result['fetch_mode']=='legacy-get'
        assert result['fetch_requests']==obj.payload['chunks']
        assert (tmp_path/'legacy.dat').read_bytes()==obj.source.read_bytes()
    finally:server.shutdown();server.server_close()


def test_unauthorized_range_rejected(setup_obj,tmp_path):
    obj,sender,recipient,secret=setup_obj
    stranger=Ed25519PrivateKey.generate()
    key=Ed25519PrivateKey.generate()
    server=BulkServer(('127.0.0.1',0),key,tmp_path/'db',
                      {pub_bytes(sender),pub_bytes(recipient),pub_bytes(stranger)})
    serve_background(server)
    peer=Peer('127.0.0.1',server.server_address[1],pub_bytes(key))
    try:
        with BulkClient(peer,sender) as client:client.upload(obj,window=4,stop_after=1)
        with BulkClient(peer,stranger) as attacker:
            with pytest.raises(BulkError,match='not authorized'):
                attacker.call('get_range',ident=obj.payload['object_id'],start=0,count=1)
        with BulkClient(peer,recipient) as client:
            with pytest.raises(BulkError,match='range'):
                client.call('get_range',ident=obj.payload['object_id'],start=0,count=5)
    finally:server.shutdown();server.server_close()


def test_mqtt_frame_limits_and_validation():
    assert _varint(127)==b'\x7f'
    assert _varint(128)==b'\x80\x01'
    assert _varint(4096)==b'\x80\x20'
    with pytest.raises(PublicRelayError):_varint(16384)
    with pytest.raises(PublicRelayError):_frame(0x30,b'x'*4097)
    with pytest.raises(PublicRelayError):_parse_publish(0x32,b'\x00\x01aZ')
    with pytest.raises(PublicRelayError):_parse_publish(0x30,b'\xff\xffa')
    with pytest.raises(PublicRelayError):_utf8('x'*161)


def test_mqtt_plaintext_requires_loopback():
    with pytest.raises(PublicRelayError,match='plaintext MQTT'):
        _connect_mqtt('8.8.8.8',1883,timeout=1,tls=False)
    with pytest.raises(PublicRelayError,match='plaintext'):
        _connect_mqtt('test.mosquitto.org',1883,timeout=1,tls=False)


class _MockBroker(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True
    def __init__(self,addr):
        self.subscriber=None
        self.topic=None
        self.lock=threading.Lock()
        super().__init__(addr,_Handler)

class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        s=self.request
        try:
            kind,raw=_read_packet(s)
            if kind!=0x10: return
            s.sendall(_frame(0x20,b'\x00\x00'))
            while True:
                kind,raw=_read_packet(s)
                if kind==0x82:
                    pid=raw[:2]
                    size=struct.unpack('>H',raw[2:4])[0]
                    topic=raw[4:4+size].decode()
                    with self.server.lock:
                        self.server.subscriber=s
                        self.server.topic=topic
                    s.sendall(_frame(0x90,pid+b'\x00'))
                elif kind==0x30:
                    topic,payload=_parse_publish(kind,raw)
                    with self.server.lock:
                        sub=self.server.subscriber
                        selected=self.server.topic
                    if sub and topic==selected:
                        sub.sendall(_frame(0x30,_utf8(topic)+payload))
                elif kind==0xe0:
                    return
                else: return
        except (PublicRelayError,OSError):
            return


def test_public_mqtt_probe_through_independent_client_sockets():
    broker=_MockBroker(('127.0.0.1',0))
    thread=threading.Thread(target=broker.serve_forever,daemon=True);thread.start()
    try:
        report=relay_probe('127.0.0.1',broker.server_address[1],timeout=2,tls=False)
        assert report['status']=='PASS'
        assert report['profile']=='PM11/IE60'
        assert report['sender_connections']==report['recipient_connections']==1
        assert report['encrypted_envelope_bytes']<960
        assert len(report['sha256_of_synthetic_plaintext'])==64
        assert 'not INNERnet server' in report['limits']
    finally:
        broker.shutdown();broker.server_close();thread.join(timeout=2)
