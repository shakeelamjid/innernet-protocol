"""v0.4.2 synthetic-only encrypted application and bounded soak tests.

All tests use real IPv4 loopback sockets or in-memory protocol state, never VPS.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from innernet2.live import LiveSession
from innernet2.native_udp import (NativeResponder, ephemeral_pub, hello_packet,
                                  pub_bytes, _secret, MAX_APPLICATION_RECORDS,
                                  MAX_SESSIONS)
from innernet2.native_udp_application import (APP_MAGIC, MAX_APP_PAYLOAD,
                                              application_qualification,
                                              encode_frame, parse_frame,
                                              synthetic_frames)
from innernet2.native_udp_soak import soak_qualification

ROOT = Path(__file__).resolve().parents[1]


def session_for(client, server, responder, port=44100):
    eph = X25519PrivateKey.generate()
    sid = secrets.token_bytes(16)
    hello = hello_packet(client, pub_bytes(server), sid, ephemeral_pub(eph), secrets.token_bytes(16))
    addr = ("127.0.0.1", port)
    reply = responder.process(hello, addr)
    assert reply is not None
    secret = _secret(eph, reply[21:53], hello + reply)
    return LiveSession(secret, sid, "initiator"), addr


def test_application_frame_round_trip_and_bounds():
    msgid = secrets.token_bytes(16)
    payload = b"SYNTHETIC-ONLY"
    assert parse_frame(encode_frame(msgid, payload)) == (msgid, payload)
    assert encode_frame(msgid, payload).startswith(APP_MAGIC)
    with pytest.raises(ValueError):
        encode_frame(b"bad", payload)
    with pytest.raises(ValueError):
        encode_frame(msgid, b"")
    with pytest.raises(ValueError):
        encode_frame(msgid, b"x" * (MAX_APP_PAYLOAD + 1))
    with pytest.raises(ValueError):
        parse_frame(b"BAD!" + msgid + payload)
    with pytest.raises(ValueError):
        parse_frame(APP_MAGIC + msgid)
    with pytest.raises(ValueError):
        parse_frame(APP_MAGIC + msgid + b"x" * (MAX_APP_PAYLOAD + 1))


def test_application_generator_has_unique_synthetic_ids():
    generated = synthetic_frames(20, 17)
    assert len({frame[4:20] for frame in generated}) == 20
    assert all(len(frame) == 20 + 17 for frame in generated)
    for kwargs in ({"count": 0}, {"count": 201}, {"count": 1, "payload_bytes": 0}):
        with pytest.raises(ValueError):
            synthetic_frames(**kwargs)


def test_server_refuses_application_path_by_default():
    client, server = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    responder = NativeResponder(server, {pub_bytes(client)})
    session, addr = session_for(client, server, responder)
    assert responder.process(session.encrypt_packet(encode_frame(secrets.token_bytes(16), b"test"), path_id=1), addr) is None
    assert responder.application_accepted == 0
    assert len(responder.application_inbox) == 0
    assert responder.accepted_messages == 0


def test_application_accepts_into_ram_and_authenticated_receipt_is_digest():
    client, server = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    responder = NativeResponder(server, {pub_bytes(client)}, accept_synthetic_application=True)
    session, addr = session_for(client, server, responder)
    msgid, payload = secrets.token_bytes(16), b"test-only!"
    frame = encode_frame(msgid, payload)
    datagram = session.encrypt_packet(frame, path_id=1)
    receipt = responder.process(datagram, addr)
    assert receipt is not None
    assert session.decrypt_packet(receipt) == (0, b"\x01" + hashlib.sha256(frame).digest())
    assert responder.application_inbox[-1] == (msgid, payload)
    assert responder.application_accepted == 1
    assert responder.process(datagram, addr) == receipt
    assert responder.duplicate_datagrams == 1
    assert responder.application_accepted == 1


def test_retransmitted_id_on_new_session_is_not_redelivered():
    client, server = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    responder = NativeResponder(server, {pub_bytes(client)}, accept_synthetic_application=True)
    msgid = secrets.token_bytes(16)
    frame = encode_frame(msgid, b"same-test-value")
    for port in (44100, 44101):
        session, addr = session_for(client, server, responder, port)
        assert responder.process(session.encrypt_packet(frame, path_id=1), addr)
    assert responder.application_accepted == 1
    assert responder.application_duplicate_ids == 1
    assert len(responder.application_inbox) == 1
    assert responder.accepted_messages == 2  # two distinct encrypted datagrams, one app ID


def test_reused_application_id_with_different_payload_is_rejected():
    client, server = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    responder = NativeResponder(server, {pub_bytes(client)}, accept_synthetic_application=True)
    session, addr = session_for(client, server, responder)
    message_id = secrets.token_bytes(16)
    assert responder.process(session.encrypt_packet(encode_frame(message_id, b"first"), path_id=1), addr)
    assert responder.process(session.encrypt_packet(encode_frame(message_id, b"changed"), path_id=1), addr) is None
    assert responder.application_accepted == 1
    assert responder.accepted_messages == 1
    assert responder.rejected_datagrams >= 1


def test_application_ids_are_scoped_by_client_identity():
    clients = [Ed25519PrivateKey.generate() for _ in range(2)]
    server = Ed25519PrivateKey.generate()
    responder = NativeResponder(server, {pub_bytes(c) for c in clients}, accept_synthetic_application=True)
    same_id = secrets.token_bytes(16)
    for idx, client in enumerate(clients):
        session, addr = session_for(client, server, responder, 44300 + idx)
        assert responder.process(session.encrypt_packet(encode_frame(same_id, b"payload"), path_id=1), addr)
    assert responder.application_accepted == 2
    assert responder.application_duplicate_ids == 0


def test_application_queue_is_bounded_and_nonpersistent():
    client, server = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    responder = NativeResponder(server, {pub_bytes(client)}, accept_synthetic_application=True)
    session, addr = session_for(client, server, responder)
    for i in range(MAX_APPLICATION_RECORDS + 1):
        frame = encode_frame(i.to_bytes(16, "big"), b"synthetic")
        assert responder.process(session.encrypt_packet(frame, path_id=1), addr)
    assert len(responder.application_inbox) == MAX_APPLICATION_RECORDS
    assert responder.application_accepted == MAX_APPLICATION_RECORDS + 1
    fresh = NativeResponder(server, {pub_bytes(client)}, accept_synthetic_application=True)
    assert len(fresh.application_inbox) == 0


def test_application_qualification_reports_in_memory_not_delivery():
    result = application_qualification(messages=12, payload_bytes=128)
    assert result["status"] == "PASS"
    assert result["volatile_message_digests_match"] is True
    assert result["authenticated_receipts"] == 12
    assert result["volatile_application_accepted"] == 12
    assert "no persistence" in result["scope"]


def test_application_cli():
    p = subprocess.run([sys.executable, "-m", "innernet2.native_udp_application", "--messages", "4", "--bytes", "32"],
                       cwd=ROOT, capture_output=True, text=True, timeout=15)
    assert p.returncode == 0, p.stderr
    result = json.loads(p.stdout)
    assert result["status"] == "PASS" and result["requested_messages"] == 4


def test_soak_qualification_reset_between_sessions():
    result = soak_qualification(cycles=4, clients=3, messages_per_client=5,
                                restart_at_cycle=3)
    assert result["status"] == "PASS"
    assert result["authenticated_receipts"] == 60
    assert result["authenticated_handshakes"] == 12
    assert result["in_memory_server_state_resets"] == 1
    assert len(result["cycles_report"]) == 4
    assert result["cycles_report"][2]["server_state_reset_before_cycle"] is True


def test_soak_limits_prevent_exhausting_session_limit():
    for params in ({"clients": 9}, {"cycles": 0}, {"restart_at_cycle": 1},
                   {"cycles": 20, "clients": 8, "restart_at_cycle": 0},
                   {"cycles": 20, "clients": 8, "restart_at_cycle": 3}):
        with pytest.raises(ValueError, match="limits"):
            soak_qualification(**params)


def test_soak_cli():
    p = subprocess.run([sys.executable, "-m", "innernet2.native_udp_soak", "--cycles", "3",
                        "--clients", "2", "--messages", "4", "--restart-at-cycle", "2"],
                       cwd=ROOT, capture_output=True, text=True, timeout=15)
    assert p.returncode == 0, p.stderr
    result = json.loads(p.stdout)
    assert result["status"] == "PASS" and result["authenticated_receipts"] == 24
