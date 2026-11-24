"""WAN TTL regression: delayed batched commits must not outlive signed IE60 envelopes."""
import time
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from innernet2.mailbox_e2ee import generate_bundle, inspect_envelope
from innernet2.mailbox_store import MailboxStore, MailboxError, OutboxStore, MIN_TTL
from innernet2.native_udp import pub_bytes
from innernet2.object_transfer import (CHUNK_SIZE, queue_object, _fresh_commit_ttl,
                                       ObjectTransferError)
from innernet2.object_demo import synthetic_bytes


def test_per_packet_ttl_renews_through_slow_wan_batch(tmp_path: Path):
    tmp_path.chmod(0o700)
    sender, receiver = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    bundle = generate_bundle(receiver, tmp_path / 'recipient.key')
    outbox = OutboxStore(tmp_path / 'outbox.sqlite')
    mailbox = MailboxStore(tmp_path / 'mailbox.sqlite', require_e2ee=True)
    try:
        q = queue_object(sender, bundle, outbox, synthetic_bytes(CHUNK_SIZE * 24), ttl=1500, expected_recipient=bytes.fromhex((bundle)["payload"]["identity_ed25519"]))
        assert q['chunks'] == 24
        pending = outbox.queued(limit=100)  # TTLs computed at batch selection (the old bug).
        sender_id = pub_bytes(sender)
        base_time = inspect_envelope(pending[0][2])['created_at']
        # Each five packet acknowledgements represents a second of WAN latency.
        # The cached TTL is rejected by strict server after a few seconds.
        stale_ttl = pending[-1][3]
        last_mid, last_dest, last_env, _ = pending[-1]
        with pytest.raises(MailboxError, match='authenticated IE60 ciphertext'):
            mailbox.store(sender_id, last_dest, last_mid, last_env, stale_ttl, now=base_time + 8)
        # Fixed behavior: recalculate just before each transmission.
        for i,(mid,recipient,envelope,batch_ttl) in enumerate(pending):
            server_time = base_time + i//5
            ttl = _fresh_commit_ttl(envelope, sender_id, recipient, mid, batch_ttl, now=server_time)
            state, _ = mailbox.store(sender_id, recipient, mid, envelope, ttl, now=server_time)
            assert state == 'STORED'
        assert mailbox.db.execute('select count(*) from messages').fetchone()[0] == 24
    finally:
        mailbox.close()
        outbox.close()


def test_fresh_ttl_refuses_nearly_expired_envelope(tmp_path: Path):
    tmp_path.chmod(0o700)
    sender, receiver = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    bundle = generate_bundle(receiver, tmp_path/'recipient.key')
    outbox = OutboxStore(tmp_path/'outbox.sqlite')
    try:
        queue_object(sender,bundle,outbox,synthetic_bytes(100),ttl=600, expected_recipient=bytes.fromhex((bundle)["payload"]["identity_ed25519"]))
        mid,recipient,env,ttl=outbox.queued()[0]
        signed=inspect_envelope(env)
        with pytest.raises(ObjectTransferError,match='insufficient remaining'):
            _fresh_commit_ttl(env,pub_bytes(sender),recipient,mid,ttl,
                              now=signed['expires_at']-MIN_TTL-5)
    finally:
        outbox.close()
