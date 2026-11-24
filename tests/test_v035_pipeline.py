"""v0.3.5: bounded cross-chunk pipelining, K-of-N recovery and safe timing."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from innernet2.crypto import deinterleave, decrypt_metadata, derive, parse_root
from innernet2.network import (DATA_CELL, INDEX_CELL, INDEX_K, INDEX_N,
                               PIPELINE_CHUNKS, INNERnetError, MeshClient)
from innernet2.profiler import OperationProfiler


def _manifest(client: MeshClient, cap: str) -> dict:
    root = parse_root(cap)
    record = client.resolve(root)
    cipher_len = record["cipher_length"]
    mixed = client._recover(record["fragments"], INDEX_K, INDEX_N,
                            ((cipher_len + INDEX_CELL - 1) // INDEX_CELL) * INDEX_CELL)
    cipher = deinterleave(mixed, derive(root, "metadata/interleave/0"), INDEX_CELL, cipher_len)
    return decrypt_metadata(root, cipher, 0)


def test_multi_chunk_puts_and_gets_use_bounded_concurrent_waves(mesh, tmp_path):
    client, _, _ = mesh
    payload = os.urandom(2 * PIPELINE_CHUNKS * 32768)
    file = tmp_path / "test.bin"
    file.write_bytes(payload)
    calls = []
    original = client._parallel_map

    def counted(operation, values):
        calls.append(len(values))
        return original(operation, values)

    client._parallel_map = counted
    cap = client.upload_file(file, k=4, n=6, chunk_bytes=32768, capability_version=2)["capability"]
    assert calls.count(PIPELINE_CHUNKS * 6) == 2  # two bounded PUT waves, not one wave per chunk

    reader = MeshClient({"nodes": list(client.nodes.values())}, http=client.http, max_workers=6)
    read_calls = []
    read_map = reader._parallel_map

    def read_count(operation, values):
        read_calls.append(len(values))
        return read_map(operation, values)

    reader._parallel_map = read_count
    out = tmp_path / "restored.bin"
    assert reader.restore_file(cap, out)["bytes"] == len(payload)
    assert out.read_bytes() == payload
    assert read_calls.count(PIPELINE_CHUNKS * 4) == 2  # two bounded GET waves, not one wave per chunk


def test_batch_recovery_with_missing_shards_in_different_chunks(mesh, tmp_path):
    client, folder, _ = mesh
    original = os.urandom(6 * 32768 + 192)
    source = tmp_path / "test.bin"
    source.write_bytes(original)
    cap = client.upload_file(source, chunk_bytes=32768, capability_version=2)["capability"]
    manifest = _manifest(client, cap)
    for chunk in manifest["chunks"][:4]:
        locator = chunk["fragments"][0]
        (folder / locator["node"] / "fragments" / locator["sha256"]).unlink()
    # Different data chunks require parity simultaneously. No plaintext
    # reaches disk until every recovered chunk is authenticated by AEAD.
    restored = tmp_path / "restored.bin"
    reader = MeshClient({"nodes": list(client.nodes.values())}, http=client.http)
    assert reader.restore_file(cap, restored)["bytes"] == len(original)
    assert restored.read_bytes() == original


def test_corrupted_primary_fragment_uses_parity_but_not_tampered_data(mesh, tmp_path):
    client, folder, _ = mesh
    source = tmp_path / "test.bin"
    content = os.urandom(5 * 32768)
    source.write_bytes(content)
    cap = client.upload_file(source, chunk_bytes=32768, capability_version=2)["capability"]
    locator = _manifest(client, cap)["chunks"][1]["fragments"][1]
    (folder / locator["node"] / "fragments" / locator["sha256"]).write_bytes(b"bad")
    reader = MeshClient({"nodes": list(client.nodes.values())}, http=client.http)
    result = tmp_path / "restored.bin"
    assert reader.restore_file(cap, result)["bytes"] == len(content)
    assert result.read_bytes() == content


def test_unrecoverable_shards_fail_closed_and_remove_partial_plaintext(mesh, tmp_path):
    client, folder, _ = mesh
    source = tmp_path / "test.bin"
    source.write_bytes(os.urandom(5 * 32768))
    cap = client.upload_file(source, chunk_bytes=32768, capability_version=2)["capability"]
    for locator in _manifest(client, cap)["chunks"][0]["fragments"][:3]:
        (folder / locator["node"] / "fragments" / locator["sha256"]).unlink()
    reader = MeshClient({"nodes": list(client.nodes.values())}, http=client.http)
    out = tmp_path / "failure-should-not-exist.bin"
    with pytest.raises(INNERnetError, match="not enough valid fragments"):
        reader.restore_file(cap, out)
    assert not out.exists()
    assert not list(tmp_path.glob(".innernet-restore-*.tmp"))
    assert not list(tmp_path.glob(".innernet-restore-*"))


def test_profile_reports_cpu_and_network_without_secrets(mesh, tmp_path):
    client, _, _ = mesh
    original = os.urandom(200_000)
    source = tmp_path / "source.bin"
    source.write_bytes(original)
    writers = {"tokens": client.writers}
    pub = MeshClient({"nodes": list(client.nodes.values())}, writers,
                     http=client.http, max_workers=6, profile=True)
    cap = pub.upload_file(source, chunk_bytes=32768, capability_version=2)["capability"]
    upload = pub.timing_report()
    assert upload["enabled"]
    assert upload["stages"]["network.fragment_put"]["calls"] > 0
    assert upload["stages"]["codec.encode"]["calls"] > 0
    assert upload["stages"]["crypto.chunk_encrypt"]["calls"] > 0
    reader = MeshClient({"nodes": list(client.nodes.values())}, http=client.http,
                        max_workers=6, profile=True)
    out = tmp_path / "restored.bin"
    reader.restore_file(cap, out)
    read = reader.timing_report()
    assert read["stages"]["crypto.chunk_decrypt"]["calls"] > 0
    assert read["stages"]["network.fragment_get"]["calls"] > 0
    assert read["stages"]["disk.restore_sync"]["calls"] == 1
    assert read["stages"]["crypto.metadata_decrypt"]["calls"] == 1
    assert out.read_bytes() == original
    entire_report = json.dumps({"read": read, "upload": upload})
    assert cap not in entire_report and str(source) not in entire_report
    for token in client.writers.values():
        assert token not in entire_report


def test_profiling_disabled_and_rejects_invalid_flag(mesh):
    client, _, _ = mesh
    assert client.timing_report() == {"enabled": False, "stages": {}}
    for value in (1, "yes", None):
        with pytest.raises(ValueError):
            OperationProfiler(enabled=value)


def test_chunk_size_configuration_rejects_invalid_early(tmp_path):
    from innernet2.remote_lab import run_trial
    for invalid in (0, 65535, 1048577, 1.5, True):
        with pytest.raises(ValueError, match="chunk_bytes"):
            run_trial(tmp_path, chunk_bytes=invalid)
