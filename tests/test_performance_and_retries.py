"""v0.3.3: concurrency and transient I/O failure regression tests."""
from __future__ import annotations

import hashlib
import threading
import time
from pathlib import Path

import httpx
import pytest

from innernet2.network import MeshClient, INNERnetError
from innernet2.remote_lab import (MAX_TRIAL_BYTES, RemoteLabError, _private_capability,
                                  bench_sizes, upload_local_file)


def test_worker_count_is_bounded(mesh):
    client, _, _ = mesh
    for value in (0, 10, -1, 2.5, True):
        with pytest.raises(ValueError):
            MeshClient({"nodes": list(client.nodes.values())}, max_workers=value)
    for value in (0, 5, 2.5):
        with pytest.raises(ValueError):
            MeshClient({"nodes": list(client.nodes.values())}, retry_attempts=value)


def test_concurrent_operation_preserves_shard_indices(mesh):
    client, _, _ = mesh
    lock = threading.Lock()
    active, peak = 0, 0

    def work(value):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.012)
        with lock:
            active -= 1
        return value ** 2

    assert client._parallel_map(work, list(range(9))) == [x * x for x in range(9)]
    assert peak >= 2
    client.max_workers = 1
    peak = 0
    assert client._parallel_map(work, list(range(9))) == [x * x for x in range(9)]
    assert peak == 1


@pytest.mark.parametrize('transient_code', [408, 429, 500, 502, 503, 504])
def test_transient_download_retries_and_checks_sha256(mesh, transient_code):
    original, _, _ = mesh
    content = b'safe synthetic fragment'
    digest = hashlib.sha256(content).hexdigest()
    attempts = 0

    def responder(_request):
        nonlocal attempts
        attempts += 1
        if attempts <= 2:
            return httpx.Response(transient_code, content=b'temporarily unavailable')
        return httpx.Response(200, content=content)

    with httpx.Client(transport=httpx.MockTransport(responder)) as transport:
        reader = MeshClient({"nodes": list(original.nodes.values())}, http=transport, retry_attempts=3)
        assert reader.get_fragment({"node":"node-01", "sha256":digest, "bytes":len(content)}) == content
    assert attempts == 3


@pytest.mark.parametrize('status', [400, 401, 403, 404, 422])
def test_permanent_failure_never_retries(mesh, status):
    original, _, _ = mesh
    attempts = 0
    def responder(_request):
        nonlocal attempts
        attempts += 1
        return httpx.Response(status)
    with httpx.Client(transport=httpx.MockTransport(responder)) as transport:
        reader = MeshClient({"nodes": list(original.nodes.values())}, http=transport, retry_attempts=3)
        with pytest.raises(httpx.HTTPStatusError):
            reader.get_fragment({"node":"node-01", "sha256":"0" * 64, "bytes":12})
    assert attempts == 1


def test_tampered_result_never_retries(mesh):
    original, _, _ = mesh
    attempts = 0
    def responder(_request):
        nonlocal attempts
        attempts += 1
        return httpx.Response(200, content=b'corrupted')
    with httpx.Client(transport=httpx.MockTransport(responder)) as transport:
        reader = MeshClient({"nodes": list(original.nodes.values())}, http=transport, retry_attempts=3)
        with pytest.raises(ValueError, match='hash/length'):
            reader.get_fragment({"node":"node-01", "sha256":"0"*64, "bytes":9})
    assert attempts == 1


def test_sequential_and_parallel_client_cross_compatible(mesh, tmp_path):
    original, _, _ = mesh
    registry = {"nodes":list(original.nodes.values())}
    writers = {"tokens": original.writers}
    source = tmp_path / 'synthetic.bin'
    raw = b'INNERnet v0.3.3-test' * 4096
    source.write_bytes(raw)
    sequential = MeshClient(registry, writers, http=original.http, max_workers=1)
    parallel = MeshClient(registry, http=original.http, max_workers=6)
    cap = sequential.upload_file(source, chunk_bytes=32768, capability_version=2)["capability"]
    dest = tmp_path / 'reconstructed.bin'
    assert parallel.restore_file(cap, dest)["bytes"] == len(raw)
    assert dest.read_bytes() == raw


def test_benchmark_size_parser_and_real_file_gate(tmp_path):
    assert bench_sizes('1048576,10485760') == [1048576, 10485760]
    assert bench_sizes(str(MAX_TRIAL_BYTES)) == [MAX_TRIAL_BYTES]
    for value in ('', '1,2,3,4', '1,-2', '0', '100000001', 'NaN'):
        with pytest.raises(ValueError):
            bench_sizes(value)
    file = tmp_path / 'private.txt'
    file.write_bytes(b'not-for-experimental-hosting')
    with pytest.raises(RemoteLabError, match='acknowledge'):
        upload_local_file(tmp_path, file)


def test_read_secret_must_be_private_and_not_symlink(tmp_path):
    secret = tmp_path / 'read.secret'
    secret.write_text('synthetic-key-not-real')
    secret.chmod(0o644)
    with pytest.raises(RemoteLabError, match='unsafe'):
        _private_capability(secret)
    secret.chmod(0o600)
    assert _private_capability(secret) == 'synthetic-key-not-real'
    link = tmp_path / 'alias.secret'
    link.symlink_to(secret)
    with pytest.raises(RemoteLabError, match='unsafe'):
        _private_capability(link)


def test_same_node_fragment_repair_after_return(mesh, tmp_path):
    from innernet2.crypto import parse_root
    from innernet2.network import INDEX_CELL, INDEX_K, INDEX_N
    client, folder, _ = mesh
    source = tmp_path / "synthetic-repair.bin"
    original = b"repair-test" * 9000
    source.write_bytes(original)
    cap = client.upload_file(source, chunk_bytes=32768, capability_version=2)["capability"]
    root_record = client.resolve(parse_root(cap))
    # Delete one metadata shard and one data shard, then return nodes online.
    bad_meta = root_record["fragments"][0]
    (folder / bad_meta["node"] / "fragments" / bad_meta["sha256"]).unlink()
    from innernet2.crypto import deinterleave, decrypt_metadata, derive
    root = parse_root(cap)
    length = root_record["cipher_length"]
    mixed = client._recover(root_record["fragments"], INDEX_K, INDEX_N,
                            ((length+INDEX_CELL-1)//INDEX_CELL)*INDEX_CELL)
    manifest = decrypt_metadata(root, deinterleave(mixed, derive(root, "metadata/interleave/0"),
                                                    INDEX_CELL, length), 0)
    bad_data = manifest["chunks"][0]["fragments"][0]
    (folder / bad_data["node"] / "fragments" / bad_data["sha256"]).unlink()
    result = client.repair_file(cap)
    assert result["repaired_shards"] == 2
    assert result["metadata_repaired"] == 1
    assert result["root_record_replicas"] >= 3
    assert client.get_fragment(bad_meta)
    assert client.get_fragment(bad_data)
    dest = tmp_path / "restored-after-repair.bin"
    client.restore_file(cap, dest)
    assert dest.read_bytes() == original

    public = MeshClient({"nodes":list(client.nodes.values())}, http=client.http)
    with pytest.raises(INNERnetError, match="writer credentials"):
        public.repair_file(cap)
