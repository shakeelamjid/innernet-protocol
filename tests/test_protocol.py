from __future__ import annotations

import base64
import json
import os
import secrets

import httpx
import pytest
from cryptography.exceptions import InvalidTag

from innernet2.crypto import (canonical, decrypt_chunk, decrypt_metadata, derive, digest,
                              encode_root, encrypt_chunk, encrypt_metadata, interleave,
                              deinterleave, new_root, parse_root, root_lookup, sign_directory, verify_directory)
from innernet2.network import INNERnetError, MeshClient, INDEX_CELL, INDEX_K, INDEX_N
from innernet2.node import MAX_FRAGMENT, private_write


def test_key_capability_is_compact_and_rejects_bad_tokens():
    root = new_root()
    token = encode_root(root)
    assert len(root) == 32 and len(token) == 48
    assert parse_root(token) == root
    for bad in (token + "=", token.upper(), "inn1_" + token[5:], "a" * 48, "inn2_" + "1" * 43):
        with pytest.raises(ValueError):
            parse_root(bad)


def test_object_keys_separated_across_purposes():
    root = new_root()
    assert derive(root, "data/aead") != derive(root, "metadata/aead/0")
    assert derive(root, "metadata/aead/0") != derive(root, "metadata/aead/1")
    assert root_lookup(root) != root.hex()


def test_cryptographic_integrity_and_nonces():
    root, object_id = new_root(), secrets.token_bytes(16)
    e0 = encrypt_chunk(root, object_id, 0, b"abc")
    e1 = encrypt_chunk(root, object_id, 1, b"abc")
    assert e0 != e1
    assert decrypt_chunk(root, object_id, 0, e0, 3) == b"abc"
    for args in [(root, object_id, 0, e0[:-1] + bytes([e0[-1] ^ 1]), 3),
                 (root, object_id, 1, e0, 3), (new_root(), object_id, 0, e0, 3)]:
        with pytest.raises(InvalidTag):
            decrypt_chunk(*args)


def test_new_generation_changes_metadata_key():
    root = new_root()
    e0 = encrypt_metadata(root, {"a": 2}, sequence=0)
    e1 = encrypt_metadata(root, {"a": 2}, sequence=1)
    assert e0 != e1
    assert decrypt_metadata(root, e1, sequence=1) == {"a": 2}
    with pytest.raises(InvalidTag):
        decrypt_metadata(root, e1, sequence=0)


def test_mix_is_reversible_with_padding():
    for data in [b"", b"x", os.urandom(12965)]:
        root = new_root()
        key = derive(root, "data/interleave/0")
        mixed = interleave(data, key, 64)
        assert deinterleave(mixed, key, 64, len(data)) == data


def test_signed_directory_rejects_forgery():
    root = new_root()
    lookup = root_lookup(root)
    record = sign_directory(root, {"protocol_version": 2, "sequence": 0, "cipher_length": 99})
    assert verify_directory(lookup, record)
    record["cipher_length"] = 100
    assert not verify_directory(lookup, record)
    assert not verify_directory(root_lookup(new_root()), record)


def inspected_manifest(client, capability):
    root = parse_root(capability)
    entry = client.resolve(root)
    cipher_len = entry["cipher_length"]
    mix_len = ((cipher_len + INDEX_CELL - 1) // INDEX_CELL) * INDEX_CELL
    mixed = client._recover(entry["fragments"], INDEX_K, INDEX_N, mix_len)
    ciphertext = deinterleave(mixed, derive(root, f"metadata/interleave/{entry['sequence']}"), INDEX_CELL, cipher_len)
    return entry, decrypt_metadata(root, ciphertext, entry["sequence"])


@pytest.mark.parametrize("length", [0, 1, 2048, 65722, 140000])
def test_file_roundtrip(mesh, length):
    client, tmp_path, _ = mesh
    source = tmp_path / "data.bin"
    raw = os.urandom(length)
    source.write_bytes(raw)
    stored = client.upload_file(source, k=4, n=6, chunk_bytes=32768, capability_version=2)
    assert len(stored["capability"]) == 48
    assert stored["bytes"] == len(raw)
    target = tmp_path / "recovered.bin"
    report = client.restore_file(stored["capability"], target)
    assert report["bytes"] == len(raw)
    assert target.read_bytes() == raw


def test_missing_two_data_shards_recovers(mesh):
    client, tmp_path, _ = mesh
    file = tmp_path / "input.bin"
    file.write_bytes(os.urandom(85000))
    stored = client.upload_file(file, chunk_bytes=32768, capability_version=2)
    _, manifest = inspected_manifest(client, stored["capability"])
    failed = [loc["node"] for loc in manifest["chunks"][0]["fragments"][:2]]
    for node_id in failed:
        for f in (tmp_path / node_id / "fragments").iterdir():
            f.unlink()
    dest = tmp_path / "restored.bin"
    client.restore_file(stored["capability"], dest)
    assert dest.read_bytes() == file.read_bytes()


def test_missing_one_metadata_shard_recovers(mesh):
    client, tmp_path, _ = mesh
    source = tmp_path / "hi.txt"
    source.write_bytes(b"hello metadata" * 170)
    stored = client.upload_file(source, chunk_bytes=4096, capability_version=2)
    entry = client.resolve(parse_root(stored["capability"]))
    failed_node = entry["fragments"][0]["node"]
    for f in (tmp_path / failed_node / "fragments").iterdir():
        f.unlink()
    dest = tmp_path / "return.txt"
    client.restore_file(stored["capability"], dest)
    assert dest.read_bytes() == source.read_bytes()


def test_tampered_fragments_are_rejected(mesh):
    client, tmp_path, _ = mesh
    source = tmp_path / "frag.txt"
    source.write_bytes(os.urandom(54000))
    stored = client.upload_file(source, chunk_bytes=32768, capability_version=2)
    _, manifest = inspected_manifest(client, stored["capability"])
    for locator in manifest["chunks"][0]["fragments"][:2]:
        node_id = locator["node"]
        f = tmp_path / node_id / "fragments" / locator["sha256"]
        f.write_bytes(b"attacker-controlled bytes")
    restored = tmp_path / "out.bin"
    client.restore_file(stored["capability"], restored)
    assert restored.read_bytes() == source.read_bytes()


def test_insufficient_shards_fails_without_destination(mesh):
    client, tmp_path, _ = mesh
    source = tmp_path / "irrecoverable"
    source.write_bytes(os.urandom(10240))
    stored = client.upload_file(source, chunk_bytes=8192, capability_version=2)
    _, manifest = inspected_manifest(client, stored["capability"])
    failed = [loc["node"] for loc in manifest["chunks"][0]["fragments"][:3]]
    for node_id in failed:
        for f in (tmp_path / node_id / "fragments").iterdir():
            f.unlink()
    dest = tmp_path / "should-not-exist"
    with pytest.raises(INNERnetError):
        client.restore_file(stored["capability"], dest)
    assert not dest.exists()


def test_storage_writes_authorized_and_public_reads(mesh):
    client, _, apps = mesh
    api = apps["127.0.0.1:9600"]
    raw = b"a test fragment"
    hash_value = digest(raw)
    assert api.put(f"/v2/fragments/{hash_value}", content=raw).status_code == 401
    assert api.get(f"/v2/fragments/{hash_value}").status_code == 404
    result = client.put_fragment("node-01", raw)
    response = api.get(f"/v2/fragments/{hash_value}")
    assert response.status_code == 200 and response.content == raw
    assert "X-Innernet-Write-Token" not in response.headers
    assert result["sha256"] == hash_value


def test_refuse_fake_checksum_and_oversized_upload(mesh):
    client, _, apps = mesh
    api = apps["127.0.0.1:9600"]
    h = {"X-Innernet-Write-Token": client.writers["node-01"]}
    bad = api.put(f"/v2/fragments/{'0' * 64}", content=b"wrong", headers=h)
    assert bad.status_code == 422
    huge = api.put(f"/v2/fragments/{digest(b'X' * (MAX_FRAGMENT + 1))}", content=b"X" * (MAX_FRAGMENT + 1), headers=h)
    assert huge.status_code == 413


def test_signed_directory_requires_admin_and_monotonic_sequence(mesh):
    client, _, apps = mesh
    api = apps["127.0.0.1:9600"]
    root = new_root()
    lookup = root_lookup(root)
    r0 = sign_directory(root, {"protocol_version": 2, "sequence": 0, "index_cell": 64})
    r1 = sign_directory(root, {"protocol_version": 2, "sequence": 1, "index_cell": 64})
    url = f"/v2/records/{lookup}"
    h = {"X-Innernet-Write-Token": client.writers["node-01"]}
    assert api.put(url, json=r0).status_code == 401
    assert api.put(url, json=r0, headers=h).status_code == 200
    assert api.get(url).json() == r0
    assert api.put(url, json=r0, headers=h).status_code == 200  # idempotent
    assert api.put(url, json=r1, headers=h).status_code == 200
    assert api.put(url, json=r0, headers=h).status_code == 409
    forged = dict(r1, sequence=2)
    assert api.put(url, json=forged, headers=h).status_code == 422


def test_unauthorized_writing_not_possible_with_public_registry(mesh):
    client, tmp_path, _ = mesh
    public = {"nodes": list(client.nodes.values())}
    unprivileged = MeshClient(public, http=client.http)
    with pytest.raises(INNERnetError):
        unprivileged.put_fragment("node-01", b"spam")


def test_no_secret_in_discovery_records(mesh):
    client, tmp_path, _ = mesh
    source = tmp_path / "extremely-private-name.txt"
    source.write_bytes(b"this is private content " * 123)
    saved = client.upload_file(source, chunk_bytes=8192, capability_version=2)
    root = parse_root(saved["capability"])
    lookup = root_lookup(root)
    contents = (tmp_path / "node-01" / "records" / lookup).read_bytes()
    assert source.name.encode() not in contents
    assert source.read_bytes() not in contents
    assert root.hex().encode() not in contents
    assert saved["capability"].encode() not in contents


def test_file_private_save_permissions(tmp_path):
    path = tmp_path / "read-capability.secret"
    private_write(path, b"secret")
    assert (path.stat().st_mode & 0o777) == 0o600
    with pytest.raises(FileExistsError):
        private_write(path, b"replace")


def test_read_only_client_can_recover_with_no_write_tokens(mesh):
    client, tmp_path, _ = mesh
    source = tmp_path / "from-private-owner.bin"
    source.write_bytes(os.urandom(18000))
    cap = client.upload_file(source, chunk_bytes=8192, capability_version=2)["capability"]
    reader = MeshClient({"nodes": list(client.nodes.values())}, http=client.http)
    target = tmp_path / "buyer-copy.bin"
    result = reader.restore_file(cap, target)
    assert target.read_bytes() == source.read_bytes()
    assert result["bytes"] == source.stat().st_size


def test_wrong_capability_cannot_read_another_object(mesh):
    client, tmp_path, _ = mesh
    source = tmp_path / "protected.bin"
    source.write_bytes(b"not public" * 100)
    real = client.upload_file(source, chunk_bytes=8192, capability_version=2)["capability"]
    assert parse_root(real) != parse_root(encode_root(new_root()))
    with pytest.raises(INNERnetError):
        client.restore_file(encode_root(new_root()), tmp_path / "not-recovered.bin")


def test_v2_vectors_do_not_change_unintentionally():
    from tools.create_test_vectors import create
    from pathlib import Path
    baseline = Path(__file__).resolve().parents[1] / "docs" / "TEST_VECTORS_v0.2.json"
    assert create() == json.loads(baseline.read_text(encoding="utf-8"))
