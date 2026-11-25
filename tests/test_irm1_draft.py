"""Tests for the IRM-1 draft reference code (REG-1, PAY-1 tickets, STO-1 proofs)."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from innernet2 import irm_registry as reg
from innernet2 import irm_storage as sto
from innernet2.bulk_v080 import BulkError
from innernet2.native_udp import pub_bytes
from innernet2.routing_v090 import SequenceStore

NOW = 1_764_000_000
FEE = "0x" + "fe" * 20
SPLIT = "0x" + "5a" * 20


def provider_entry(key, **over):
    entry = {
        "id": pub_bytes(key).hex(), "name": "test-provider", "region": "eu-central",
        "endpoints": [{"host": "node1.example.test", "port": 9443}],
        "services": ["STO-1", "RLY-1"],
        "payto": {"eip155:84532": SPLIT},
        "prices": {"STO-1": {"asset": "USDC", "unit": "GiB-day", "amount": "0.0010"},
                   "RLY-1": {"asset": "USDC", "unit": "GiB", "amount": "0.0050"}},
    }
    entry.update(over)
    return entry


def registry_payload(providers, seq=1, **over):
    p = {"version": "REG-1", "sequence": seq, "issued_at": NOW, "expires_at": NOW + 3600,
         "fee_bps": 100, "fee_payto": {"eip155:84532": FEE}, "providers": providers}
    p.update(over)
    return p


# ---------------- REG-1 ----------------

def test_registry_roundtrip_and_rollback(tmp_path):
    rk, pk = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    store = SequenceStore(tmp_path / "s" / "seq.json")
    d1 = reg.sign_registry(registry_payload([provider_entry(pk, listed_at=NOW)], seq=5), rk, now=NOW)
    payload = reg.verify_registry(d1, [pub_bytes(rk)], now=NOW + 10, sequence_store=store)
    assert payload["fee_bps"] == 100
    d2 = reg.sign_registry(registry_payload([], seq=6), rk, now=NOW)
    reg.verify_registry(d2, [pub_bytes(rk)], now=NOW + 10, sequence_store=store)
    with pytest.raises(BulkError):  # replay of the older list
        reg.verify_registry(d1, [pub_bytes(rk)], now=NOW + 10, sequence_store=store)


def test_registry_rejects_unpinned_tampered_expired():
    rk, other, pk = (Ed25519PrivateKey.generate() for _ in range(3))
    doc = reg.sign_registry(registry_payload([provider_entry(pk)]), rk, now=NOW)
    with pytest.raises(BulkError):
        reg.verify_registry(doc, [pub_bytes(other)], now=NOW)
    tampered = json.loads(json.dumps(doc))
    tampered["payload"]["fee_bps"] = 0
    with pytest.raises(BulkError):
        reg.verify_registry(tampered, [pub_bytes(rk)], now=NOW)
    with pytest.raises(BulkError):
        reg.verify_registry(doc, [pub_bytes(rk)], now=NOW + 3601)


@pytest.mark.parametrize("bad", [
    {"fee_bps": 10_001},
    {"fee_payto": {"eip155:84532": "0x123"}},
    {"fee_payto": {"solana:x": FEE}},
    {"expires_at": NOW + 90_000},           # window longer than 24 h
    {"extra": 1},
])
def test_registry_payload_validation(bad):
    rk, pk = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    with pytest.raises(BulkError):
        reg.sign_registry(registry_payload([provider_entry(pk)], **bad), rk, now=NOW)


def test_provider_needs_fee_wallet_on_its_network_and_unique_id():
    rk, pk = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    entry = provider_entry(pk, payto={"eip155:8453": SPLIT})
    with pytest.raises(BulkError):
        reg.sign_registry(registry_payload([entry]), rk, now=NOW)
    e = provider_entry(pk)
    with pytest.raises(BulkError):
        reg.sign_registry(registry_payload([e, dict(e)]), rk, now=NOW)


def test_provider_must_price_exactly_its_services():
    rk, pk = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    entry = provider_entry(pk, services=["STO-1"])
    with pytest.raises(BulkError):
        reg.sign_registry(registry_payload([entry]), rk, now=NOW)


def test_rotation_requires_backup_and_moves_forward(tmp_path):
    active, backup, new, attacker = (Ed25519PrivateKey.generate() for _ in range(4))
    store = SequenceStore(tmp_path / "r" / "seq.json")
    rec = reg.sign_rotation(pub_bytes(new), 1, backup_key=backup, old_key=active, now=NOW)
    assert reg.verify_rotation(rec, active_key=pub_bytes(active), backup_key=pub_bytes(backup),
                               sequence_store=store) == pub_bytes(new)
    with pytest.raises(BulkError):  # replay
        reg.verify_rotation(rec, active_key=pub_bytes(active), backup_key=pub_bytes(backup), sequence_store=store)
    forged = reg.sign_rotation(pub_bytes(attacker), 9, backup_key=attacker, now=NOW)
    with pytest.raises(BulkError):
        reg.verify_rotation(forged, active_key=pub_bytes(active), backup_key=pub_bytes(backup))
    emergency = reg.sign_rotation(pub_bytes(new), 2, backup_key=backup, now=NOW)
    assert reg.verify_rotation(emergency, active_key=pub_bytes(active), backup_key=pub_bytes(backup),
                               sequence_store=store) == pub_bytes(new)


def test_descriptor_self_signed():
    pk, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    rec = reg.sign_descriptor(provider_entry(pk), pk)
    assert reg.verify_descriptor(rec)["id"] == pub_bytes(pk).hex()
    with pytest.raises(BulkError):
        reg.sign_descriptor(provider_entry(other), pk)       # id is someone else's key
    rec["payload"]["provider"]["region"] = "us-east"
    with pytest.raises(BulkError):
        reg.verify_descriptor(rec)
    with pytest.raises(BulkError):                           # registry-only fields not allowed
        reg.sign_descriptor(provider_entry(pk, listed_at=NOW), pk)


def test_price_and_payto_checks():
    rk, pk = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    payload = reg.verify_registry(reg.sign_registry(registry_payload([provider_entry(pk)]), rk, now=NOW),
                                  [pub_bytes(rk)], now=NOW)
    entry = reg.find_provider(payload, pub_bytes(pk))
    assert str(reg.check_quoted_price(entry, "STO-1", asset="USDC", amount="0.0009", unit="GiB-day")) == "0.0009"
    reg.check_quoted_price(entry, "STO-1", asset="USDC", amount="0.0010", unit="GiB-day")
    for amount, unit, asset in [("0.0011", "GiB-day", "USDC"), ("0.0010", "GiB", "USDC"), ("0.0010", "GiB-day", "USDT")]:
        with pytest.raises(BulkError):
            reg.check_quoted_price(entry, "STO-1", asset=asset, amount=amount, unit=unit)
    with pytest.raises(BulkError):
        reg.check_quoted_price(entry, "CMP-1", asset="USDC", amount="0", unit="GiB")
    reg.check_payto(payload, entry, "eip155:84532", SPLIT.upper().replace("0X", "0x"))
    with pytest.raises(BulkError):
        reg.check_payto(payload, entry, "eip155:84532", FEE)
    with pytest.raises(BulkError):
        reg.find_provider(payload, pub_bytes(rk))


def test_service_ticket():
    pk, client, other = (Ed25519PrivateKey.generate() for _ in range(3))
    fields = {"client": pub_bytes(client).hex(), "service": "STO-1", "lease": "ab" * 16,
              "units": "10.0", "unit": "GiB-day", "payment_tx": "0x" + "11" * 32, "expires_at": NOW + 600}
    t = reg.sign_ticket(fields, pk)
    assert reg.verify_ticket(t, pub_bytes(pk), now=NOW)["units"] == "10.0"
    with pytest.raises(BulkError):
        reg.verify_ticket(t, pub_bytes(other), now=NOW)
    with pytest.raises(BulkError):
        reg.verify_ticket(t, pub_bytes(pk), now=NOW + 601)
    t["payload"]["units"] = "100.0"
    with pytest.raises(BulkError):
        reg.verify_ticket(t, pub_bytes(pk), now=NOW)


# ---------------- STO-1 ----------------

@pytest.mark.parametrize("size", [1, 1023, 1024, 1025, 2048, 3 * 1024 + 7, 65_536, 65_552])
def test_every_block_proves(size):
    chunk = os.urandom(size)
    root, count = sto.chunk_root(chunk)
    assert count == -(-size // 1024)
    for i in range(count):
        block, path = sto.prove(chunk, i)
        assert sto.verify(root, count, i, block, path)


def test_tampering_is_caught():
    chunk = os.urandom(65_552)
    root, count = sto.chunk_root(chunk)
    block, path = sto.prove(chunk, 7)
    assert not sto.verify(root, count, 7, bytes([block[0] ^ 1]) + block[1:], path)   # flipped bit
    assert not sto.verify(root, count, 8, block, path)                                # wrong index
    assert not sto.verify(root, count, 7, block, path[:-1])                           # short path
    assert not sto.verify(root, count, 7, block, path + [b"\0" * 32])                 # long path
    assert not sto.verify(root, count + 1, 7, block, path)                            # wrong size
    assert not sto.verify(root, count, 7, block[:512], path)                          # truncated block
    other = os.urandom(65_552)
    b2, p2 = sto.prove(other, 7)
    assert not sto.verify(root, count, 7, b2, p2)                                     # different data


def test_challenge_flow():
    chunks = [os.urandom(65_552) for _ in range(4)] + [os.urandom(300)]
    roots = sto.lease_roots(chunks)
    for _ in range(50):
        ch = sto.make_challenge(roots)
        assert sto.check_answer(roots, ch, sto.answer_challenge(chunks, ch))
    ch = {"chunk": 2, "block": 5}
    lost = list(chunks)
    lost[2] = os.urandom(65_552)                       # provider lost/replaced the chunk
    assert not sto.check_answer(roots, ch, sto.answer_challenge(lost, ch))
    assert not sto.check_answer(roots, ch, {"chunk": 2, "block": 6, "data": "", "path": []})
    assert not sto.check_answer(roots, ch, {"garbage": True})


# ---------------- golden vectors ----------------

def test_irm1_vectors_do_not_change_unintentionally():
    from tools.create_irm1_vectors import create
    baseline = Path(__file__).resolve().parents[1] / "docs" / "TEST_VECTORS_IRM1_DRAFT.json"
    assert create() == json.loads(baseline.read_text(encoding="utf-8"))


# ---------------- independent Go implementation ----------------

def _go_verify(path):
    import shutil
    import subprocess
    if shutil.which("go") is None:
        pytest.skip("Go toolchain not installed")
    root = Path(__file__).resolve().parents[1] / "interop" / "go"
    return subprocess.run(["go", "run", "./irm1verify", str(path)], cwd=root, capture_output=True, text=True, timeout=180)


def test_go_verifier_accepts_vectors():
    vectors = Path(__file__).resolve().parents[1] / "docs" / "TEST_VECTORS_IRM1_DRAFT.json"
    result = _go_verify(vectors)
    assert result.returncode == 0, result.stderr
    assert "IRM1_VERIFY_PASS" in result.stdout


@pytest.mark.parametrize("mutate", [
    lambda v: v["registry_document"]["payload"].__setitem__("fee_bps", 0),
    lambda v: v["service_ticket"]["payload"].__setitem__("units", "99.0"),
    lambda v: v["storage_proof"]["path"].__setitem__(0, "00" * 32),
    lambda v: v["descriptor"]["payload"]["provider"].__setitem__("region", "us-east"),
])
def test_go_verifier_rejects_tampering(tmp_path, mutate):
    vectors = Path(__file__).resolve().parents[1] / "docs" / "TEST_VECTORS_IRM1_DRAFT.json"
    data = json.loads(vectors.read_text(encoding="utf-8"))
    mutate(data)
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(data), encoding="utf-8")
    result = _go_verify(bad)
    assert result.returncode != 0
    assert "IRM1_VERIFY_FAIL" in result.stderr
