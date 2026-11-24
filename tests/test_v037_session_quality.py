"""v0.3.7 session cache, bounded fallback, and honest read-only latency stats."""
from __future__ import annotations

import json
import math
import time

import pytest

from innernet2 import remote_lab
from innernet2.crypto import parse_root, root_lookup
from innernet2.network import (FAILURE_COOLDOWN, INNERnetError, MeshClient,
                               MAX_CACHED_RECORDS)


def make_reader(mesh, **kwargs):
    writer, _, _ = mesh
    return MeshClient({"nodes": list(writer.nodes.values())}, http=writer.http,
                      profile=True, **kwargs)


def test_signed_discovery_cache_reuses_network_and_defends_against_mutation(mesh, tmp_path):
    writer, _, _ = mesh
    source = tmp_path / 'item.bin'
    source.write_bytes(b'cached but verified' * 250)
    cap = writer.upload_file(source, capability_version=2)['capability']
    root = parse_root(cap)
    reader = make_reader(mesh)
    original = reader._parallel_directory
    calls = []

    def counted(operation, values):
        calls.append(len(values))
        return original(operation, values)

    reader._parallel_directory = counted
    original_record = reader.resolve(root)
    assert calls == [9]
    original_record['fragments'].clear()  # caller mutation must not damage trusted cache
    cached = reader.resolve(root)
    assert len(cached['fragments']) == 3
    assert calls == [9]
    assert reader.timing_report()['stages']['network.discovery_cache_hit']['calls'] == 1
    # The operator can always force a fresh all-peers check, bypassing the TTL.
    assert reader.resolve(root, fresh=True)['sequence'] == 0
    assert calls == [9, 9]
    assert root_lookup(root) in reader._verified_directory_cache
    assert len(reader._verified_directory_cache) <= MAX_CACHED_RECORDS
    assert cap not in json.dumps(reader.timing_report())


def test_cache_ttl_expires_and_zero_ttl_disables_caching(mesh, tmp_path):
    writer, _, _ = mesh
    src = tmp_path / 'item.bin'
    src.write_bytes(b'hello' * 100)
    root = parse_root(writer.upload_file(src, capability_version=2)['capability'])
    for ttl in (0, 0.001):
        reader = make_reader(mesh, discovery_ttl_seconds=ttl)
        original = reader._parallel_directory
        hits = []

        def counted(op, values):
            hits.append(True)
            return original(op, values)

        reader._parallel_directory = counted
        reader.resolve(root)
        if ttl:
            time.sleep(0.02)
        reader.resolve(root)
        assert len(hits) == 2


@pytest.mark.parametrize('invalid', [True, -1, 61, float('inf'), float('nan'), '15', None])
def test_cache_rejects_invalid_ttl(mesh, invalid):
    with pytest.raises(ValueError, match='discovery_ttl'):
        make_reader(mesh, discovery_ttl_seconds=invalid)


def test_session_fails_closed_if_signed_discovery_sequence_regresses(mesh, tmp_path):
    writer, _, _ = mesh
    src = tmp_path / 'item.bin'
    src.write_bytes(b'A' * 300)
    root = parse_root(writer.upload_file(src, capability_version=2)['capability'])
    reader = make_reader(mesh)
    reader.resolve(root)
    reader._highest_sequences[root_lookup(root)] = 10
    with pytest.raises(INNERnetError, match='sequence regressed'):
        reader.resolve(root, fresh=True)


def test_failed_node_is_temporarily_deprioritized_without_deleting_a_share(mesh):
    reader = make_reader(mesh)
    nodes = list(reader.nodes)[:6]
    locators = [{'node': nid, 'sha256': 'a' * 64, 'bytes': 123} for nid in nodes]
    assert reader._primary_indices(locators, 4) == [0, 1, 2, 3]
    with reader._latency_lock:
        reader._unhealthy_until[nodes[0]] = time.monotonic() + FAILURE_COOLDOWN
        reader._unhealthy_until[nodes[1]] = time.monotonic() + FAILURE_COOLDOWN
    assert reader._primary_indices(locators, 4) == [2, 3, 4, 5]
    # If every node is degraded, still return K distinct candidates.
    with reader._latency_lock:
        for node in nodes:
            reader._unhealthy_until[node] = time.monotonic() + FAILURE_COOLDOWN
    assert len(reader._primary_indices(locators, 4)) == 4
    assert len(set(reader._primary_indices(locators, 4))) == 4


def test_corrupt_fragment_does_not_get_accepted_or_recommended(mesh, tmp_path):
    writer, folder, _ = mesh
    src = tmp_path / 'item.bin'
    src.write_bytes(b'content' * 4000)
    cap = writer.upload_file(src, capability_version=2)['capability']
    reader = make_reader(mesh)
    from innernet2.crypto import decrypt_metadata, deinterleave, derive
    from innernet2.network import INDEX_CELL, INDEX_N, INDEX_K
    root = parse_root(cap)
    record = reader.resolve(root)
    length = ((record['cipher_length'] + INDEX_CELL - 1) // INDEX_CELL) * INDEX_CELL
    mixed = reader._recover(record['fragments'], INDEX_K, INDEX_N, length)
    encrypted = deinterleave(mixed, derive(root, 'metadata/interleave/0'), INDEX_CELL, record['cipher_length'])
    manifest = decrypt_metadata(root, encrypted, 0)
    target = manifest['chunks'][0]['fragments'][0]
    (folder / target['node'] / 'fragments' / target['sha256']).write_bytes(b'corrupted')
    output = tmp_path / 'recovered.bin'
    assert reader.restore_file(cap, output)['bytes'] == src.stat().st_size
    assert output.read_bytes() == src.read_bytes()
    assert reader._unhealthy_until[target['node']] > time.monotonic()


def test_percentile_uses_nearest_rank_and_blocks_misleading_single_sample():
    assert remote_lab.percentile_ms([1, 4, 2, 5, 3]) == 5
    assert remote_lab.percentile_ms([5, 1, 4, 2, 3], .50) == 3
    assert remote_lab.percentile_ms([3]) == 3
    for data, rank in [([], .95), ([1], 0), ([1], 1.5)]:
        with pytest.raises(ValueError):
            remote_lab.percentile_ms(data, rank)


@pytest.mark.parametrize('read_repeats,latency_probes', [(0, 0), (10, 0), (1, -1), (1, 10)])
def test_qualify_rejects_unbounded_probes_without_writes(tmp_path, read_repeats, latency_probes):
    with pytest.raises(ValueError):
        remote_lab.qualify_lab(tmp_path, [1048576], acknowledge=True,
                               read_repeats=read_repeats, latency_probes=latency_probes)
