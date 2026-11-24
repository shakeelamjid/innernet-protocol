"""v0.5.0 experimental mailbox integration; localhost/socket and SQLite only."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import threading
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from innernet2.mailbox_store import MailboxStore, OutboxStore, MailboxError, MAX_BODY
from innernet2.mailbox_wire import (WireError, handle_request, parse_response,
                                   request, store_request)
from innernet2.mailbox_directory import (DirectoryError, sign_directory,
                                         verify_directory, find_route)
from innernet2.mailbox_client import (rpc, store_message, fetch_message,
                                      consume_message, query_status, demo)
from innernet2.native_udp import (NativeResponder, NativeTransitError,
                                  pub_bytes, serve)


def make_keys(n: int = 3):
    return [Ed25519PrivateKey.generate() for _ in range(n)]


@pytest.fixture
def keys():
    return make_keys()


@pytest.fixture
def store(tmp_path):
    tmp_path.chmod(0o700)
    db = MailboxStore(tmp_path / 'mail.sqlite')
    yield db
    db.close()


class Server:
    def __init__(self, identity, allowed, db):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0))
        self.addr = self.sock.getsockname()
        self.responder = NativeResponder(identity, {pub_bytes(k) for k in allowed},
                                         mailbox_store=db)
        self.halt = threading.Event()
        self.thread = threading.Thread(target=serve, args=(self.sock, self.responder),
                                       kwargs={'stop': self.halt}, daemon=True)
        self.thread.start()

    def close(self):
        self.halt.set()
        self.thread.join(2)
        self.sock.close()
        assert not self.thread.is_alive()


def test_store_duplicate_conflict_and_ttl(store, keys):
    sender, receiver, _ = keys
    mid = secrets.token_bytes(16)
    a, b = pub_bytes(sender), pub_bytes(receiver)
    assert store.store(a, b, mid, b'payload', now=100)[0] == 'STORED'
    assert store.store(a, b, mid, b'payload', now=101)[0] == 'DUPLICATE'
    for recipient, payload in [(a, b'payload'), (b, b'changed')]:
        with pytest.raises(MailboxError):
            store.store(a, recipient, mid, payload, now=102)
    assert store.fetch(a, now=102) is None
    assert store.fetch(b, now=102) == (a, mid, b'payload')
    assert store.status(a, mid, now=102) == 'STORED'
    assert store.status(a, mid, now=4000) == 'EXPIRED'
    assert store.fetch(b, now=4000) is None
    assert store.consume(b, a, mid, now=4000) is False
    assert store.prune(now=100000) == 1
    assert store.status(a, mid) == 'UNKNOWN'


def test_strict_permissions_and_limits(tmp_path, keys):
    # A public directory is deliberately refused for plaintext DB files.
    world = tmp_path / 'public'
    world.mkdir(mode=0o755)
    world.chmod(0o755)
    with pytest.raises(MailboxError):
        MailboxStore(world / 'inbox.sqlite')
    safe = tmp_path / 'private'
    safe.mkdir(mode=0o700)
    mail = MailboxStore(safe / 'm.sqlite', max_rows=1)
    try:
        a, b = pub_bytes(keys[0]), pub_bytes(keys[1])
        mail.store(a, b, secrets.token_bytes(16), b'A')
        with pytest.raises(MailboxError):
            mail.store(a, b, secrets.token_bytes(16), b'B')
        with pytest.raises(MailboxError):
            mail.store(a, b, secrets.token_bytes(16), b'Y' * (MAX_BODY + 1))
    finally:
        mail.close()


def test_consumption_identity_and_status_survive_reopen(tmp_path, keys):
    tmp_path.chmod(0o700)
    path = tmp_path / 'persistent.sqlite'
    a, b, c = [pub_bytes(k) for k in keys]
    mid = secrets.token_bytes(16)
    db = MailboxStore(path)
    db.store(a, b, mid, b'expected', ttl=3600)
    assert not db.consume(c, a, mid)
    assert db.fetch(c) is None
    assert db.consume(b, a, mid)
    assert db.consume(b, a, mid)  # idempotent
    db.close()
    reopened = MailboxStore(path)
    assert reopened.status(a, mid) == 'CONSUMED'
    assert reopened.fetch(b) is None
    assert reopened.store(a, b, mid, b'expected')[0] == 'DUPLICATE'
    reopened.close()


def test_wire_validation_and_status(store, keys):
    a, b = pub_bytes(keys[0]), pub_bytes(keys[1])
    mid = secrets.token_bytes(16)
    packet = store_request(b, mid, b'SYNTHETIC:x')
    code, body = parse_response(handle_request(store, a, packet), packet[5:21])
    assert code == 'D' and body[:16] == mid and body[16:48] == hashlib.sha256(b'SYNTHETIC:x').digest()
    code, _ = parse_response(handle_request(store, a, packet), packet[5:21])
    assert code == 'D'
    status_q = request('Q', mid)
    assert parse_response(handle_request(store, a, status_q), status_q[5:21]) == ('Q', b'S')
    fetch_q = request('F')
    code, body = parse_response(handle_request(store, b, fetch_q), fetch_q[5:21])
    assert code == 'M' and body == a + mid + b'SYNTHETIC:x'
    assert parse_response(handle_request(store, keys[2].public_key().public_bytes_raw(), fetch_q), fetch_q[5:21])[0] == 'N'
    ack_q = request('A', a + mid)
    assert parse_response(handle_request(store, b, ack_q), ack_q[5:21]) == ('A', mid)
    assert parse_response(handle_request(store, a, status_q), status_q[5:21]) == ('Q', b'C')
    with pytest.raises(WireError):
        parse_response(b'junk', packet[5:21])
    with pytest.raises(WireError):
        request('K')
    with pytest.raises(WireError):
        handle_request(store, a, request('F', b'forbidden'))


def test_udp_end_to_end_and_v040_legacy_path(store, keys):
    sender, recipient, server = keys
    srv = Server(server, [sender, recipient], store)
    try:
        mid = secrets.token_bytes(16)
        receipt = store_message(*srv.addr, sender, pub_bytes(server), pub_bytes(recipient),
                                mid, b'SYNTHETIC:hi', timeout=.15)
        assert receipt['status'] == 'STORED'
        second = store_message(*srv.addr, sender, pub_bytes(server), pub_bytes(recipient),
                               mid, b'SYNTHETIC:hi', timeout=.15)
        assert second['status'] == 'ALREADY_STORED'
        delivered = fetch_message(*srv.addr, recipient, pub_bytes(server), timeout=.15)
        assert delivered['payload'] == b'SYNTHETIC:hi'
        assert delivered['sender'] == pub_bytes(sender).hex()
        assert fetch_message(*srv.addr, sender, pub_bytes(server), timeout=.15)['status'] == 'EMPTY'
        consume_message(*srv.addr, recipient, pub_bytes(server), pub_bytes(sender), mid, timeout=.15)
        assert query_status(*srv.addr, sender, pub_bytes(server), mid, timeout=.15)['status'] == 'CONSUMED'
        from innernet2.native_udp import native_probe
        legacy = native_probe(*srv.addr, sender, pub_bytes(server),
                              samples=3, payload_bytes=32, timeout=.15)
        assert legacy['status'] == 'PASS' and legacy['authenticated_receipts'] == 3
    finally:
        srv.close()


def test_unpinned_client_timeout(store, keys):
    sender, recipient, server = keys
    srv = Server(server, [recipient], store)
    try:
        with pytest.raises(NativeTransitError):
            rpc(*srv.addr, sender, pub_bytes(server), request('P'),
                timeout=.06, attempts=1, fresh_sessions=1)
        assert srv.responder.rejected_datagrams >= 1
    finally:
        srv.close()


def test_offline_sender_outbox_recovery_and_restart(tmp_path, keys):
    tmp_path.chmod(0o700)
    sender, recipient, server = keys
    mail_path, out_path = tmp_path / 'mail.sqlite', tmp_path / 'out.sqlite'
    outbox = OutboxStore(out_path)
    mid = outbox.enqueue(pub_bytes(recipient), b'SYNTHETIC:offline')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as unused:
        unused.bind(('127.0.0.1', 0))
        dead_port = unused.getsockname()[1]
    with pytest.raises(NativeTransitError):
        store_message('127.0.0.1', dead_port, sender, pub_bytes(server),
                      pub_bytes(recipient), mid, b'SYNTHETIC:offline', timeout=.05)
    assert outbox.queued()[0][0] == mid
    db = MailboxStore(mail_path)
    srv = Server(server, [sender, recipient], db)
    try:
        result = store_message(*srv.addr, sender, pub_bytes(server), pub_bytes(recipient),
                               mid, b'SYNTHETIC:offline', timeout=.15)
        assert result['status'] == 'STORED'
        # Simulate ACK loss: do not change local outbox yet.
    finally:
        srv.close()
        db.close()
    db = MailboxStore(mail_path)
    srv = Server(server, [sender, recipient], db)
    try:
        result = store_message(*srv.addr, sender, pub_bytes(server), pub_bytes(recipient),
                               mid, b'SYNTHETIC:offline', timeout=.15)
        assert result['status'] == 'ALREADY_STORED'
        outbox.mark_stored(mid)
        assert outbox.queued() == []
        assert fetch_message(*srv.addr, recipient, pub_bytes(server), timeout=.15)['message_id'] == mid.hex()
    finally:
        srv.close()
        db.close()
        outbox.close()


def signed_payload(keys, ports):
    sender, r1, r2, s1, s2 = keys
    now = int(time.time())
    return {'version': 'IN50-STATIC-1', 'created_at': now - 1, 'expires_at': now + 3600,
            'nodes': [
                {'id': 'one', 'host': '127.0.0.1', 'port': ports[0],
                 'public_ed25519': pub_bytes(s1).hex(), 'failure_domain': 'PROCESS-A'},
                {'id': 'two', 'host': '127.0.0.1', 'port': ports[1],
                 'public_ed25519': pub_bytes(s2).hex(), 'failure_domain': 'PROCESS-B'}],
            'routes': [
                {'recipient_ed25519': pub_bytes(r1).hex(), 'node_id': 'one'},
                {'recipient_ed25519': pub_bytes(r2).hex(), 'node_id': 'two'}]}


def test_two_node_route_and_signature_tampering(tmp_path):
    tmp_path.chmod(0o700)
    sender, r1, r2, s1, s2 = make_keys(5)
    store1, store2 = MailboxStore(tmp_path/'one.sqlite'), MailboxStore(tmp_path/'two.sqlite')
    node1, node2 = Server(s1, [sender, r1], store1), Server(s2, [sender, r2], store2)
    try:
        payload = signed_payload([sender, r1, r2, s1, s2], (node1.addr[1], node2.addr[1]))
        record = sign_directory(payload, sender)
        verified = verify_directory(record, pub_bytes(sender))
        for idx, recip in enumerate((r1, r2)):
            node = find_route(verified, pub_bytes(recip))
            mid = secrets.token_bytes(16)
            result = store_message(node['host'], node['port'], sender,
                                   bytes.fromhex(node['public_ed25519']), pub_bytes(recip),
                                   mid, b'SYNTHETIC:node'+bytes([idx]), timeout=.15)
            assert result['status'] == 'STORED'
        assert store1.db.execute('SELECT COUNT(*) FROM messages').fetchone()[0] == 1
        assert store2.db.execute('SELECT COUNT(*) FROM messages').fetchone()[0] == 1
        record['payload']['nodes'][0]['host'] = 'evil.example'
        with pytest.raises(DirectoryError):
            verify_directory(record, pub_bytes(sender))
        with pytest.raises(DirectoryError):
            verify_directory(sign_directory(payload, sender), pub_bytes(r1))
    finally:
        node1.close(); node2.close(); store1.close(); store2.close()


def test_expired_signed_directory(keys):
    sender, r1, server = keys
    now = int(time.time())
    payload = {'version': 'IN50-STATIC-1', 'created_at': now-300,
               'expires_at': now-100,
               'nodes': [{'id': 'n', 'host': '127.0.0.1', 'port': 9000,
                          'public_ed25519': pub_bytes(server).hex(),
                          'failure_domain': 'test'}],
               'routes': [{'recipient_ed25519': pub_bytes(r1).hex(), 'node_id': 'n'}]}
    with pytest.raises(DirectoryError):
        sign_directory(payload, sender)


def test_cli_demo_and_store_replay_stress(tmp_path, keys):
    assert demo(messages=8)['status'] == 'PASS'
    tmp_path.chmod(0o700)
    db = MailboxStore(tmp_path/'stress.sqlite', max_rows=1500)
    try:
        a,b = pub_bytes(keys[0]), pub_bytes(keys[1])
        # RC5 per-pair quota deliberately prevents concentrating 1,100
        # pending rows in one recipient's inbox; test idempotency while
        # distributing across five independently identified recipients.
        recipients = [b] + [pub_bytes(Ed25519PrivateKey.generate()) for _ in range(4)]
        for i in range(1100):
            assert db.store(a,recipients[i%5],i.to_bytes(16,'big'),b'SYNTHETIC:payload')[0] == 'STORED'
        for i in range(1100):
            assert db.store(a,recipients[i%5],i.to_bytes(16,'big'),b'SYNTHETIC:payload')[0] == 'DUPLICATE'
        assert db.db.execute('SELECT COUNT(*) FROM messages').fetchone()[0] == 1100
    finally:
        db.close()
    p = subprocess.run([sys.executable, '-m', 'innernet2.mailbox', 'demo', '--messages', '3'],
                       capture_output=True, text=True, timeout=15)
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout)['status'] == 'PASS'
