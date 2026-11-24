"""ST81 regression tests: server challenge, first AEAD key proof, total deadline."""
import secrets
import socket
import time
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from innernet2.native_udp import pub_bytes
from innernet2.stream_v080 import connect, MAGIC_C, DOMAIN_C, _rawpub
from innernet2.relay_v090 import BulkServer, BulkClient, Peer, serve_background


def _start(tmp_path, slots=2):
    server, client = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    srv=BulkServer(('127.0.0.1',0),server,tmp_path/'db.sqlite',{pub_bytes(client)},max_connections=slots)
    thread=serve_background(srv)
    return srv,thread,server,client


def test_st81_authenticated_ping(tmp_path):
    srv,thread,server,client=_start(tmp_path)
    try:
        with BulkClient(Peer('127.0.0.1',srv.server_address[1],pub_bytes(server)),client) as link:
            assert link.call('ping')[0]['pong'] is True
    finally:
        srv.shutdown();srv.server_close();thread.join(timeout=2)


def test_captured_hello_replay_does_not_take_authenticated_slot(tmp_path):
    srv,thread,server,client=_start(tmp_path,slots=1)
    port=srv.server_address[1]
    sockets=[]
    try:
        first=socket.create_connection(('127.0.0.1',port),timeout=2)
        sockets.append(first)
        challenge=first.recv(68)
        assert len(challenge)==68
        eph=X25519PrivateKey.generate()
        prefix=MAGIC_C+pub_bytes(client)+_rawpub(eph)+secrets.token_bytes(32)
        hello=prefix+client.sign(DOMAIN_C+challenge+prefix)
        first.sendall(hello)
        response=first.recv(196)
        assert response.startswith(b'S81S')
        # No encrypted key proof: first connection has not occupied the active slot.
        assert srv._slots._value == 1
        first.close();sockets.remove(first)
        # Replay against a new fresh challenge is invalid, regardless of the signed identity.
        replay=socket.create_connection(('127.0.0.1',port),timeout=2)
        sockets.append(replay)
        assert replay.recv(68).startswith(b'S81H')
        replay.sendall(hello)
        replay.settimeout(2)
        assert replay.recv(4)==b''
        replay.close();sockets.remove(replay)
        with BulkClient(Peer('127.0.0.1',port,pub_bytes(server)),client) as link:
            assert link.call('ping')[0]['pong']
    finally:
        for s in sockets: s.close()
        srv.shutdown();srv.server_close();thread.join(timeout=2)


def test_slow_sender_cannot_extend_handshake_past_total_deadline(tmp_path):
    srv,thread,server,client=_start(tmp_path)
    s=socket.create_connection(('127.0.0.1',srv.server_address[1]),timeout=3)
    try:
        challenge=s.recv(68)
        assert challenge.startswith(b'S81H')
        s.sendall(b'S')
        time.sleep(2.4)
        s.settimeout(1)
        assert s.recv(1)==b''
    finally:
        s.close();srv.shutdown();srv.server_close();thread.join(timeout=2)
