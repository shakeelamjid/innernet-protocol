"""v0.3.4: signed capacity, registry, direct baseline and safe local cache retention."""
from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from innernet2.baseline import one_node_baseline
from innernet2.local_retention import local_trial_cleanup
from innernet2.observability import capacity_report, topology_report
from innernet2.remote_lab import RemoteLabError, compare_remote, maintenance_once


def test_signed_capacity_report_is_read_only_and_does_not_sum_nodes(mesh):
    client, _, _ = mesh
    report = capacity_report({"nodes": list(client.nodes.values())}, client.http)
    assert report["verified"] == 9 and report["failed"] == 0
    assert len(report["nodes"]) == 9
    assert report["nodes"][0]["advertised_used_bytes"] == 0
    assert report["nodes"][0]["status"] == "ok"
    assert "total_capacity_bytes" not in report
    assert "not" in report["note"].lower()


def test_capacity_reports_real_usage_and_warns(mesh):
    client, _, _ = mesh
    client.put_fragment("node-01", b"some-test-data")
    report = capacity_report({"nodes": list(client.nodes.values())}, client.http, warn_at=0.1)
    assert report["nodes"][0]["advertised_used_bytes"] == len(b"some-test-data")
    with pytest.raises(ValueError):
        capacity_report({"nodes": list(client.nodes.values())}, client.http, warn_at=1.0)


def test_topology_detects_shared_hosts_and_unverified_labels(mesh):
    client, _, _ = mesh
    entries = list(client.nodes.values())
    registry = {"nodes": [{**entry, "failure_domain": f"simulated-group-{'abc'[i//3]}"}
                          for i, entry in enumerate(entries)]}
    result = topology_report(registry)
    assert result["nodes"] == 9
    assert result["distinct_advertised_hostnames"] == 1
    assert result["independent_infrastructure_verified"] is False
    assert result["simulated_domain_labels_detected"] is True
    assert result["one_declared_domain_outage_profile_placeable"] is True
    with pytest.raises(ValueError, match="duplicate"):
        topology_report({"nodes": [entries[0], entries[0]]})


def test_one_node_baseline_checks_receipts_and_end_to_end_hash(mesh, tmp_path):
    client, _, _ = mesh
    source = tmp_path / "synthetic.bin"
    payload = os.urandom(140_000)
    source.write_bytes(payload)
    result = one_node_baseline(client, source, node_id="node-09", chunk_size=32768)
    assert result["status"] == "PASS"
    assert result["bytes"] == len(payload)
    assert result["fragments"] == 5
    assert result["sha256_verified"] is True
    assert "SSH" in result["transport"]
    with pytest.raises(ValueError):
        one_node_baseline(client, source, node_id="unknown")


def test_inspect_file_reveals_missing_and_repair_restores(mesh, tmp_path):
    from innernet2.crypto import parse_root
    from innernet2.network import INDEX_CELL, INDEX_K, INDEX_N, MeshClient
    client, folder, _ = mesh
    f = tmp_path / "in.bin"
    f.write_bytes(os.urandom(58000))
    stats = client.upload_file(f, chunk_bytes=32768, capability_version=2)
    assert stats["physical_fragment_bytes"] > stats["bytes"]
    cap = stats["capability"]
    before = client.inspect_file(cap)
    assert before["shard_status"]["missing"] == 0
    assert before["shard_status"]["verified"] == before["total_shards"]
    root_record = client.resolve(parse_root(cap))
    locator = root_record["fragments"][0]
    (folder / locator["node"] / "fragments" / locator["sha256"]).unlink()
    after = client.inspect_file(cap)
    assert after["metadata_shard_status"]["missing"] == 1
    assert after["shard_status"]["missing"] == 1
    assert client.repair_file(cap)["repaired_shards"] == 1
    assert client.inspect_file(cap)["shard_status"]["missing"] == 0


def test_inspect_shares_corruption_and_refuses_destructive_repair(mesh, tmp_path):
    from innernet2.crypto import parse_root
    from innernet2.network import INNERnetError
    client, folder, _ = mesh
    f = tmp_path / "in.bin"
    f.write_bytes(os.urandom(70000))
    cap = client.upload_file(f, chunk_bytes=32768, capability_version=2)["capability"]
    locator = client.resolve(parse_root(cap))["fragments"][0]
    (folder / locator["node"] / "fragments" / locator["sha256"]).write_bytes(b"corrupt data")
    result = client.inspect_file(cap)
    assert result["metadata_shard_status"]["corrupt"] == 1
    with pytest.raises(INNERnetError, match="cannot safely repair"):
        client.repair_file(cap)


def test_local_trial_cleanup_dry_run_and_preserves_secrets(tmp_path):
    folder = tmp_path / "client"
    trial = folder / "trials" / "abcdef012345"
    trial.mkdir(parents=True)
    original = trial / "synthetic-input.bin"
    restored = trial / "recovered-normal.bin"
    original.write_bytes(b"synthetic" * 10)
    restored.write_bytes(b"synthetic" * 10)
    (trial / "read.secret").write_text("valuable-secret")
    (trial / "report.json").write_text("valuable-report")
    (trial / "unrelated.txt").write_text("never-delete")
    for f in (original, restored):
        os.utime(f, (time.time() - 60 * 86400, time.time() - 60 * 86400))
    preview = local_trial_cleanup(folder, older_than_days=30)
    assert preview["mode"] == "dry-run" and preview["eligible_files"] == 2
    assert original.exists()
    result = local_trial_cleanup(folder, older_than_days=30, execute=True)
    assert result["eligible_files"] == 2 and not original.exists() and not restored.exists()
    assert (trial / "read.secret").read_text() == "valuable-secret"
    assert (trial / "report.json").exists() and (trial / "unrelated.txt").exists()
    with pytest.raises(ValueError):
        local_trial_cleanup(folder, older_than_days=0)


def test_local_trial_cleanup_refuses_symlinks(tmp_path):
    folder = tmp_path / "client"
    trial = folder / "trials" / "000011112222"
    trial.mkdir(parents=True)
    offsite = tmp_path / "offsite"
    offsite.write_bytes(b"must never be touched")
    (trial / "synthetic-input.bin").symlink_to(offsite)
    assert local_trial_cleanup(folder, older_than_days=1, execute=True)["eligible_files"] == 0
    assert offsite.read_bytes() == b"must never be touched"


def test_compare_requires_explicit_ack_and_maintenance_reads_config(tmp_path):
    with pytest.raises(RemoteLabError, match="acknowledge"):
        compare_remote(tmp_path, [10])
    # without prepared local configuration, scheduled maintenance must fail closed
    with pytest.raises(RemoteLabError, match="config"):
        maintenance_once(tmp_path)


def test_https_read_only_sample_validates_signed_pinned_peer(mesh):
    from innernet2.observability import https_sample_baseline
    client, _, _ = mesh
    node = dict(client.nodes["node-01"])
    locator = client.put_fragment("node-01", b"public-research-fragment")
    node["url"] = node["url"].replace("http://", "https://")
    report = https_sample_baseline(node, client.http, sample_sha256=locator["sha256"],
                                   expected_bytes=locator["bytes"], samples=2)
    assert report["status"] == "PASS" and len(report["download_ms"]) == 2
    assert report["sha256_verified_each_time"]
    with pytest.raises(ValueError, match="HTTPS"):
        https_sample_baseline(client.nodes["node-01"], client.http,
                              sample_sha256=locator["sha256"], expected_bytes=locator["bytes"])
    with pytest.raises(ValueError, match="expected"):
        https_sample_baseline(node, client.http,
                              sample_sha256=locator["sha256"], expected_bytes=2)
