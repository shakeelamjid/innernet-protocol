"""v0.4.0 native UDP tests. All use loopback; do not imply Internet reachability."""
from __future__ import annotations

import hashlib
import os
import secrets
import socket
import threading
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from innernet2.live import LiveSession
from innernet2.native_udp import (
    NativeResponder, NativeTransitError, SERVER_DOMAIN, HANDSHAKE_DOMAIN,
    HELLO_LEN, REPLY_LEN, MAX_SESSIONS,
    generate_identity_file, load_identity, pub_bytes, ephemeral_pub,
    hello_packet, local_qualification, native_probe, parse_public_hex, serve,
    _secret,
)


def peers():
    client = Ed25519PrivateKey.generate()
    server = Ed25519PrivateKey.generate()
    return client, server, NativeResponder(server, {pub_bytes(client)})


def handshaked(client, server, responder, addr=('127.0.0.1', 44100)):
    eph = X25519PrivateKey.generate()
    sid = secrets.token_bytes(16)
    hello = hello_packet(client, pub_bytes(server), sid, ephemeral_pub(eph), secrets.token_bytes(16))
    reply = responder.process(hello, addr)
    assert reply is not None and len(reply) == REPLY_LEN
    secret = _secret(eph, reply[21:53], hello + reply)
    return hello, reply, LiveSession(secret, sid, 'initiator'), addr


def test_identity_file_permissions_symlink_and_overwrite(tmp_path):
    path = tmp_path / 'sub' / 'identity.key'
    public_hex = generate_identity_file(path)
    assert path.stat().st_mode & 0o777 == 0o600
    assert pub_bytes(load_identity(path)).hex() == public_hex
    assert parse_public_hex(public_hex) == bytes.fromhex(public_hex)
    with pytest.raises(NativeTransitError):
        generate_identity_file(path)
    path.chmod(0o644)
    with pytest.raises(NativeTransitError, match='permissions'):
        load_identity(path)
    link = tmp_path / 'ref.key'
    link.symlink_to(path)
    with pytest.raises(NativeTransitError):
        load_identity(link)
    with pytest.raises(NativeTransitError):
        generate_identity_file(link)


@pytest.mark.parametrize('key', ['xyz', 'z'*64, '', 'ff'*33])
def test_bad_public_keys_fail_closed(key):
    with pytest.raises(ValueError):
        parse_public_hex(key)


def test_hello_authenticates_both_identities_and_ephemeral_keys():
    client, server, responder = peers()
    sid = secrets.token_bytes(16)
    ephemeral = X25519PrivateKey.generate()
    packet = hello_packet(client, pub_bytes(server), sid, ephemeral_pub(ephemeral), secrets.token_bytes(16))
    assert len(packet) == HELLO_LEN
    assert responder.process(packet, ('127.0.0.1', 30001)) is not None
    corrupted = bytearray(packet)
    corrupted[26] ^= 1
    assert responder.process(bytes(corrupted), ('127.0.0.1', 30001)) is None
    other = Ed25519PrivateKey.generate()
    assert responder.process(hello_packet(other, pub_bytes(server), secrets.token_bytes(16),
                                          ephemeral_pub(ephemeral), secrets.token_bytes(16)),
                             ('127.0.0.1', 30001)) is None
    assert responder.process(hello_packet(client, pub_bytes(other), secrets.token_bytes(16),
                                          ephemeral_pub(ephemeral), secrets.token_bytes(16)),
                             ('127.0.0.1', 30001)) is None
    assert responder.process(b'IN40C' + b'garbage', ('127.0.0.1', 30001)) is None


def test_byte_exact_handshake_retry_and_session_collision():
    client, server, responder = peers()
    hello, reply, session, addr = handshaked(client, server, responder)
    assert responder.process(hello, addr) == reply
    assert responder.process(hello, ('127.0.0.1', addr[1] + 1)) is None
    modified = bytearray(hello)
    modified[-1] ^= 0x01
    assert responder.process(bytes(modified), addr) is None
    assert len(responder.sessions) == 1


def test_authenticated_receipts_replay_and_sender_address_binding():
    client, server, responder = peers()
    hello, reply, session, addr = handshaked(client, server, responder)
    message = b'pure synthetic data'
    packet = session.encrypt_packet(message)
    assert responder.process(packet, ('127.0.0.1', 9)) is None
    receipt = responder.process(packet, addr)
    assert receipt is not None
    path, plaintext = session.decrypt_packet(receipt)
    assert path == 0 and plaintext == b'\x01' + hashlib.sha256(message).digest()
    assert responder.process(packet, addr) == receipt
    assert responder.accepted_messages == 1
    assert responder.duplicate_datagrams == 1
    forged = bytearray(packet)
    forged[-1] ^= 1
    assert responder.process(bytes(forged), addr) is None
    assert responder.accepted_messages == 1
    assert responder.process(session.encrypt_packet(b'second'), addr) is not None
    assert responder.accepted_messages == 2
    assert responder.process(packet, addr) == receipt


def test_server_state_expiration_and_limit(monkeypatch):
    client, server, responder = peers()
    hello, reply, session, addr = handshaked(client, server, responder)
    responder.sessions[next(iter(responder.sessions))].created -= 400
    assert responder.process(session.encrypt_packet(b'expired'), addr) is None
    assert len(responder.sessions) == 0
    for _ in range(MAX_SESSIONS):
        handshaked(client, server, responder)
    assert len(responder.sessions) == MAX_SESSIONS
    sid = secrets.token_bytes(16)
    eph = X25519PrivateKey.generate()
    hello = hello_packet(client, pub_bytes(server), sid, ephemeral_pub(eph), secrets.token_bytes(16))
    # RC4 deliberately evicts the oldest unconfirmed session under pressure;
    # this prevents a table of replayed, unconfirmed hellos from locking out clients.
    original_ids = set(responder.sessions)
    reply = responder.process(hello, addr)
    assert reply is not None
    assert len(responder.sessions) == MAX_SESSIONS
    assert sid in responder.sessions
    assert len(original_ids - set(responder.sessions)) == 1


def test_invalid_packets_are_silent_and_capped():
    client, server, responder = peers()
    addr = ('127.0.0.1', 8000)
    for raw in (b'', b'junk', b'IN40C' + b'\0'*8000, b'INL2', b'IN40S' + b'\0'*144):
        assert responder.process(raw, addr) is None
    assert responder.rejected_datagrams >= 5
    assert len(responder.sessions) == 0


def test_one_socket_local_qualify_live_code_path():
    report = local_qualification(samples=30, payload_bytes=256)
    assert report['status'] == 'PASS'
    assert report['authenticated_receipts'] == 30
    assert report['server_accepted_unique_messages'] == 30
    assert report['unacknowledged_messages'] == 0
    assert report['rtt_p50_ms'] <= report['rtt_p95_ms']
    assert '127.0.0.1' in report['scope']
    assert report['peer_authentication'].startswith('mutually')


def test_wrong_pinned_server_fails_without_acceptance():
    client, server, responder = peers()
    stop = threading.Event()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('127.0.0.1', 0))
        t = threading.Thread(target=serve, args=(sock, responder), kwargs={'stop': stop}, daemon=True)
        t.start()
        try:
            with pytest.raises(NativeTransitError, match='handshake timed out'):
                native_probe('127.0.0.1', sock.getsockname()[1], client,
                             pub_bytes(Ed25519PrivateKey.generate()), samples=1,
                             timeout=0.1, attempts=1)
        finally:
            stop.set()
            t.join(timeout=2)
    assert responder.accepted_messages == 0


def test_no_allowed_client_fails_without_reply():
    client, server, responder = peers()
    other = Ed25519PrivateKey.generate()
    stop = threading.Event()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('127.0.0.1', 0))
        t = threading.Thread(target=serve, args=(sock, responder), kwargs={'stop': stop}, daemon=True)
        t.start()
        try:
            with pytest.raises(NativeTransitError, match='handshake timed out'):
                native_probe('127.0.0.1', sock.getsockname()[1], other,
                             pub_bytes(server), samples=1, timeout=0.1, attempts=1)
        finally:
            stop.set()
            t.join(timeout=2)
    assert responder.accepted_messages == 0


def test_retransmission_of_exact_packet_receives_same_authenticated_receipt():
    client, server, responder = peers()
    hello, reply, session, addr = handshaked(client, server, responder)
    packet = session.encrypt_packet(b'retry same packet')
    dropped_receipt = responder.process(packet, addr)
    delivered_receipt = responder.process(packet, addr)
    assert dropped_receipt == delivered_receipt
    assert session.decrypt_packet(delivered_receipt)[1] == b'\x01' + hashlib.sha256(b'retry same packet').digest()
    assert responder.accepted_messages == 1
    assert responder.duplicate_datagrams == 1


def test_receipt_cache_is_bounded():
    client, server, responder = peers()
    hello, reply, session, addr = handshaked(client, server, responder)
    for i in range(280):
        assert responder.process(session.encrypt_packet(i.to_bytes(2, 'big')), addr)
    state = list(responder.sessions.values())[0]
    assert len(state.acknowledgments) == 256
    assert responder.accepted_messages == 280


def test_no_key_material_in_report_json():
    report = local_qualification(samples=2, payload_bytes=10)
    assert 'private_key' not in str(report)
    assert 'session_secret' not in str(report)
    assert 'WIRE' not in report['transport']


def test_unauthenticated_live_payload_is_never_accepted():
    client, server, responder = peers()
    hello, reply, session, addr = handshaked(client, server, responder)
    wrong = LiveSession(os.urandom(32), session.session_id, 'initiator')
    assert responder.process(wrong.encrypt_packet(b'message'), addr) is None
    assert responder.accepted_messages == 0


def test_unsupported_payload_size_is_rejected():
    client, server, responder = peers()
    hello, reply, session, addr = handshaked(client, server, responder)
    with pytest.raises(ValueError):
        session.encrypt_packet(secrets.token_bytes(1153))


def test_socket_timeout_parameter_validation():
    client, server, responder = peers()
    with pytest.raises(ValueError):
        native_probe('127.0.0.1', 29410, client, pub_bytes(server), samples=0)
    with pytest.raises(ValueError):
        native_probe('127.0.0.1', 29410, client, pub_bytes(server), attempts=7)
    with pytest.raises(ValueError):
        NativeResponder(server, set())


def test_actual_udp_probe_recovers_one_dropped_authenticated_receipt():
    """The client reuses a single encrypted datagram, server deduplicates."""
    client, server, responder = peers()
    stop = threading.Event()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('127.0.0.1', 0))
        sock.settimeout(.2)
        port = sock.getsockname()[1]
        dropped = [False]

        def worker():
            while not stop.is_set():
                try:
                    packet, addr = sock.recvfrom(2048)
                except socket.timeout:
                    continue
                reply = responder.process(packet, addr)
                if reply is None:
                    continue
                if packet.startswith(b'INL2') and not dropped[0]:
                    dropped[0] = True
                    continue
                sock.sendto(reply, addr)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        try:
            result = native_probe('127.0.0.1', port, client, pub_bytes(server),
                                  samples=3, timeout=.1, attempts=3)
            assert result['status'] == 'PASS'
            assert result['datagram_retransmissions'] >= 1
            assert result['authenticated_receipts'] == 3
            assert responder.accepted_messages == 3
            assert responder.duplicate_datagrams >= 1
        finally:
            stop.set()
            thread.join(timeout=2)


def test_forged_signed_server_reply_is_rejected():
    client, server, responder = peers()
    stop = threading.Event()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('127.0.0.1', 0))
        sock.settimeout(.2)
        port = sock.getsockname()[1]

        def worker():
            while not stop.is_set():
                try:
                    packet, addr = sock.recvfrom(2048)
                except socket.timeout:
                    continue
                reply = responder.process(packet, addr)
                if reply:
                    if packet.startswith(b'IN40C'):
                        forged = bytearray(reply)
                        forged[-1] ^= 1
                        reply = bytes(forged)
                    sock.sendto(reply, addr)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        try:
            with pytest.raises(NativeTransitError, match='signature invalid'):
                native_probe('127.0.0.1', port, client, pub_bytes(server),
                             samples=1, timeout=.2, attempts=1)
        finally:
            stop.set()
            thread.join(timeout=2)


def test_epoch_derived_keys_accept_next_epoch_and_reject_replay():
    """Existing INL2 codec uses a new directional key at epoch 65536."""
    client, server, responder = peers()
    _, _, sender, address = handshaked(client, server, responder)
    sender.send_seq = 65535
    first = sender.encrypt_packet(b'before rekey')
    second = sender.encrypt_packet(b'after rekey')
    receipt_a = responder.process(first, address)
    receipt_b = responder.process(second, address)
    assert receipt_a and receipt_b
    assert sender.decrypt_packet(receipt_a)[1][1:] == hashlib.sha256(b'before rekey').digest()
    assert sender.decrypt_packet(receipt_b)[1][1:] == hashlib.sha256(b'after rekey').digest()
    assert responder.process(first, address) == receipt_a
