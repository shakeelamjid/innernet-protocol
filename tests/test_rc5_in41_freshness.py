import secrets
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from innernet2.native_udp import (NativeResponder, PersistentHelloJournal,
    hello_packet, hello_packet_v041, pub_bytes, ephemeral_pub)


def packet(client, server, *, timestamp=None, legacy=False):
    maker = hello_packet if legacy else hello_packet_v041
    kwargs = {} if legacy else {'timestamp': timestamp}
    return maker(client, pub_bytes(server), secrets.token_bytes(16),
                 ephemeral_pub(X25519PrivateKey.generate()),
                 secrets.token_bytes(16), **kwargs)


def test_in41_replay_is_rejected_after_restart_and_downgrade_is_rejected(tmp_path):
    client, server = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    private = tmp_path / 'private'
    private.mkdir(mode=0o700)
    path = private / 'replays.db'
    hello = packet(client, server)
    old = packet(client, server, legacy=True)
    first_journal = PersistentHelloJournal(path)
    responder = NativeResponder(server, {pub_bytes(client)}, fresh_journal=first_journal)
    addr = ('127.0.0.1', 40001)
    assert responder.process(hello, addr).startswith(b'IN41S')
    assert responder.process(old, addr) is None
    first_journal.close()
    second_journal = PersistentHelloJournal(path)
    fresh_responder = NativeResponder(server, {pub_bytes(client)}, fresh_journal=second_journal)
    assert fresh_responder.process(hello, addr) is None
    assert fresh_responder.process(packet(client, server), addr).startswith(b'IN41S')
    second_journal.close()


def test_in41_freshness_window_and_cross_identity_replay(tmp_path):
    a, b, server = (Ed25519PrivateKey.generate() for _ in range(3))
    d = tmp_path / 'private'
    d.mkdir(mode=0o700)
    journal = PersistentHelloJournal(d / 'replay.db')
    responder = NativeResponder(server, {pub_bytes(a), pub_bytes(b)}, fresh_journal=journal)
    now = int(time.time())
    assert responder.process(packet(a, server, timestamp=now - 200), ('127.0.0.1', 1234)) is None
    assert responder.process(packet(a, server, timestamp=now + 200), ('127.0.0.1', 1234)) is None
    assert responder.process(packet(b, server), ('127.0.0.1', 1235)).startswith(b'IN41S')
    journal.close()


def test_in41_network_probe_with_pinned_keys_and_journal(tmp_path):
    import socket
    import threading
    from innernet2.native_udp import native_probe, serve
    c, s = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    d = tmp_path / 'private-net'
    d.mkdir(mode=0o700)
    journal = PersistentHelloJournal(d / 'journal.db')
    responder = NativeResponder(s, {pub_bytes(c)}, fresh_journal=journal)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 0))
    stop = threading.Event()
    worker = threading.Thread(target=serve, args=(sock, responder), kwargs={'stop': stop}, daemon=True)
    worker.start()
    try:
        report = native_probe('127.0.0.1', sock.getsockname()[1], c, pub_bytes(s),
                              samples=3, timeout=1.0, wire_version=41)
        assert report['status'] == 'PASS'
        assert report['authenticated_receipts'] == 3
        assert report['wire_version'].startswith('IN41')
    finally:
        stop.set()
        worker.join(timeout=2)
        sock.close()
        journal.close()
