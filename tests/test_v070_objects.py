"""IO70 object transfer semantics, actual UDP, resume, durable recipient checkpoint."""
import hashlib
import os
from pathlib import Path
import secrets
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from innernet2.mailbox_e2ee import generate_bundle, seal_message, open_message, load_recipient_secret
from innernet2.mailbox_store import OutboxStore
from innernet2.object_transfer import (MAX_OBJECT_BYTES, MAX_CHUNKS, CHUNK_SIZE,
    ObjectTransferError, ObjectInbox, chunk_message_id, decode_chunk, queue_object, _chunks)
from innernet2.object_demo import run_demo, synthetic_bytes
from innernet2.native_udp import pub_bytes


@pytest.fixture
def keys(tmp_path):
    tmp_path.chmod(0o700)
    sender, receiver = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    bundle = generate_bundle(receiver, tmp_path / "recipient.key")
    return sender, receiver, bundle, load_recipient_secret(tmp_path / "recipient.key")


def test_frame_capacity_and_maximum_object():
    assert CHUNK_SIZE > 600
    blob = synthetic_bytes(MAX_OBJECT_BYTES)
    raw = list(_chunks(blob, b"k" * 16))
    assert len(raw) == MAX_CHUNKS
    assert sum(len(decode_chunk(p)["data"]) for _, p in raw) == len(blob)
    assert all(decode_chunk(p)["digest"] == hashlib.sha256(blob).digest() for _, p in raw)
    assert raw[0][0] == 0 and raw[-1][0] == MAX_CHUNKS-1


def test_chunk_ids_are_stable_and_domain_separated():
    t = secrets.token_bytes(16)
    assert chunk_message_id(t, 0) == chunk_message_id(t, 0)
    assert chunk_message_id(t, 0) != chunk_message_id(t, 1)
    assert chunk_message_id(t, 1) != chunk_message_id(b"x"*16, 1)
    with pytest.raises(ObjectTransferError):
        chunk_message_id(t, MAX_CHUNKS)


def test_reject_malformed_frames():
    blob = synthetic_bytes(3000)
    frame = next(_chunks(blob, b"t"*16))[1]
    for damaged in (frame[:-1], frame + b"a" * 1000, b"SYNTHETIC:WRONG" + frame):
        with pytest.raises(ObjectTransferError):
            decode_chunk(damaged)
    # advertised total size/number of chunks must be coherent
    broken = bytearray(frame)
    broken[len(b"SYNTHETIC:IO70\x01")+16:len(b"SYNTHETIC:IO70\x01")+20] = (0xFFFFFFFF).to_bytes(4, "big")
    with pytest.raises(ObjectTransferError):
        decode_chunk(bytes(broken))


def test_queue_is_ciphertext_only_and_decrypts(keys, tmp_path):
    sender, receiver, bundle, secret = keys
    out = OutboxStore(tmp_path / "out.sqlite")
    data = synthetic_bytes(CHUNK_SIZE * 2 + 5)
    result = queue_object(sender, bundle, out, data, expected_recipient=bytes.fromhex((bundle)["payload"]["identity_ed25519"]))
    assert result["chunks"] == 3
    packets = out.queued(limit=100)
    assert len(packets) == 3
    for index, (mid, recipient, ciphertext, ttl) in enumerate(packets):
        assert recipient == pub_bytes(receiver)
        assert ciphertext.startswith(b"IE60")
        assert b"SYNTHETIC:IO70" not in ciphertext
        clear = open_message(receiver, secret, ciphertext, expected_sender=pub_bytes(sender),
                             expected_message_id=mid)
        decoded = decode_chunk(clear)
        assert decoded["index"] == index
        assert mid == chunk_message_id(bytes.fromhex(result["transfer_id"]), index)
    out.close()


def test_inbox_restart_idempotence_out_of_order(keys, tmp_path):
    sender, receiver, bundle, secret = keys
    data = synthetic_bytes(CHUNK_SIZE * 3 + 37)
    chunks = list(_chunks(data, b"t"*16))
    inbox = ObjectInbox(tmp_path / "receiver.sqlite")
    s, r = pub_bytes(sender), pub_bytes(receiver)
    for idx in [2, 0, 0]:
        mid = chunk_message_id(b"t"*16, idx)
        result = inbox.ingest(s, r, mid, chunks[idx][1])
        if idx == 0 and result["duplicate"]:
            assert result["duplicate"]
    assert inbox.progress(s, r, b"t"*16)["received"] == 2
    with pytest.raises(ObjectTransferError):
        inbox.assemble(s, r, b"t"*16)
    inbox.close()
    inbox = ObjectInbox(tmp_path / "receiver.sqlite")
    for idx in [1, 3]:
        inbox.ingest(s, r, chunk_message_id(b"t"*16, idx), chunks[idx][1])
    assert inbox.assemble(s, r, b"t"*16) == data
    inbox.close()


def test_inbox_reject_wrong_id_and_mixed_object(keys, tmp_path):
    sender, receiver, _, _ = keys
    data = synthetic_bytes(CHUNK_SIZE+100)
    first, second = [frame for _, frame in _chunks(data, b"t"*16)]
    inbox = ObjectInbox(tmp_path / "box.sqlite")
    s, r = pub_bytes(sender), pub_bytes(receiver)
    with pytest.raises(ObjectTransferError):
        inbox.ingest(s, r, os.urandom(16), first)
    inbox.ingest(s, r, chunk_message_id(b"t"*16, 0), first)
    changed = bytearray(second)
    changed[len(b"SYNTHETIC:IO70\x01")+16+4+4+4] ^= 1
    with pytest.raises(ObjectTransferError):
        inbox.ingest(s, r, chunk_message_id(b"t"*16, 1), bytes(changed))
    assert inbox.progress(s,r,b"t"*16)["received"] == 1
    inbox.close()


def test_assemble_checks_full_object_digest(keys, tmp_path):
    sender, receiver, _, _ = keys
    data = synthetic_bytes(2000)
    s, r = pub_bytes(sender), pub_bytes(receiver)
    inbox = ObjectInbox(tmp_path / "bad.sqlite")
    for i, frame in _chunks(data, b"o"*16):
        tampered = bytearray(frame)
        tampered[len(b"SYNTHETIC:IO70\x01")+16+4+4+4] ^= 1
        inbox.ingest(s, r, chunk_message_id(b"o"*16, i), bytes(tampered))
    with pytest.raises(ObjectTransferError, match="integrity"):
        inbox.assemble(s, r, b"o"*16)
    inbox.close()


def test_reject_nonsynthetic_oversize_bad_ttl(keys, tmp_path):
    sender, _, bundle, _ = keys
    out = OutboxStore(tmp_path / "queue.sqlite")
    with pytest.raises(ObjectTransferError):
        queue_object(sender, bundle, out, b"secret data", expected_recipient=bytes.fromhex((bundle)["payload"]["identity_ed25519"]))
    with pytest.raises(ObjectTransferError):
        queue_object(sender, bundle, out, b"SYNTHETIC:" + b"x"*MAX_OBJECT_BYTES, expected_recipient=bytes.fromhex((bundle)["payload"]["identity_ed25519"]))
    with pytest.raises(ObjectTransferError):
        queue_object(sender, bundle, out, b"SYNTHETIC:ok", ttl=1, expected_recipient=bytes.fromhex((bundle)["payload"]["identity_ed25519"]))
    out.close()


def test_two_node_outage_and_resume_demo():
    report = run_demo(kib=16)
    assert report["status"] == "PASS"
    assert report["authenticated_chunk_commits"] == report["object_a_chunks"] + report["object_b_chunks"]
    assert report["node_b_served_during_a_outage"]
    assert report["recipient_inbox_resumed_after_restart"]
    assert report["duplicate_server_store_detected"]


def test_cli_object_demo():
    p = subprocess.run([sys.executable, "-m", "innernet2.mailbox", "object-demo", "--kib", "4"],
                       capture_output=True, text=True, timeout=20)
    assert p.returncode == 0, p.stderr
    assert '"status": "PASS"' in p.stdout
    from innernet2.version import RELEASE_VERSION
    assert __import__("json").loads(p.stdout)["release_version"] == RELEASE_VERSION
