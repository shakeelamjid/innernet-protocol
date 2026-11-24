import os
import secrets

import pytest
from cryptography.exceptions import InvalidTag

from innernet2.live import LiveSession, MAX_PAYLOAD, ReplayError, REKEY_INTERVAL


@pytest.mark.parametrize("mixing", [True, False])
@pytest.mark.parametrize("length", [0, 1, 48, MAX_PAYLOAD])
def test_two_way_live_packets(mixing, length):
    secret, session_id = secrets.token_bytes(32), secrets.token_bytes(16)
    a = LiveSession(secret, session_id, "initiator", mixing=mixing)
    b = LiveSession(secret, session_id, "responder", mixing=mixing)
    content = os.urandom(length)
    assert b.decrypt_packet(a.encrypt_packet(content, path_id=2)) == (2, content)
    assert a.decrypt_packet(b.encrypt_packet(content, path_id=7)) == (7, content)


def test_live_out_of_order_and_replay():
    secret, session_id = secrets.token_bytes(32), secrets.token_bytes(16)
    sender = LiveSession(secret, session_id, "initiator")
    receiver = LiveSession(secret, session_id, "responder")
    first = sender.encrypt_packet(b"first")
    second = sender.encrypt_packet(b"second")
    assert receiver.decrypt_packet(second) == (0, b"second")
    assert receiver.decrypt_packet(first) == (0, b"first")
    with pytest.raises(ReplayError):
        receiver.decrypt_packet(first)


def test_tampering_cannot_advance_replay_window():
    secret, session_id = secrets.token_bytes(32), secrets.token_bytes(16)
    sender = LiveSession(secret, session_id, "initiator")
    receiver = LiveSession(secret, session_id, "responder")
    honest = sender.encrypt_packet(b"authenticated data")
    tampered = bytearray(honest)
    tampered[-1] ^= 1
    with pytest.raises((InvalidTag, ValueError)):
        receiver.decrypt_packet(bytes(tampered))
    assert receiver.decrypt_packet(honest) == (0, b"authenticated data")


def test_rekey_at_epoch_boundary():
    secret, session_id = secrets.token_bytes(32), secrets.token_bytes(16)
    sender = LiveSession(secret, session_id, "initiator")
    receiver = LiveSession(secret, session_id, "responder")
    sender.send_seq = REKEY_INTERVAL - 1
    a, b = sender.encrypt_packet(b"old epoch"), sender.encrypt_packet(b"new epoch")
    assert receiver.decrypt_packet(a) == (0, b"old epoch")
    assert receiver.decrypt_packet(b) == (0, b"new epoch")


def test_other_session_cannot_decrypt():
    secret, session_id = secrets.token_bytes(32), secrets.token_bytes(16)
    packet = LiveSession(secret, session_id, "initiator").encrypt_packet(b"secret")
    with pytest.raises(ValueError):
        LiveSession(secret, secrets.token_bytes(16), "responder").decrypt_packet(packet)
    with pytest.raises((InvalidTag, ValueError)):
        LiveSession(secrets.token_bytes(32), session_id, "responder").decrypt_packet(packet)


def test_live_payload_limits():
    sender = LiveSession(secrets.token_bytes(32), secrets.token_bytes(16), "initiator")
    with pytest.raises(ValueError):
        sender.encrypt_packet(b"X" * (MAX_PAYLOAD + 1))
