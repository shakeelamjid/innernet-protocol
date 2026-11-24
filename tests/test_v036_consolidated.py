"""v0.3.6: combined qualification, security and bounded latency scheduling."""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from innernet2 import remote_lab
from innernet2.network import MeshClient, PIPELINE_CHUNKS


def test_parallel_directory_checks_all_nine_even_with_six_shard_workers(mesh):
    client, _, _ = mesh
    client.max_workers = 6
    lock = threading.Lock()
    current = peak = 0

    def slow(index):
        nonlocal current, peak
        with lock:
            current += 1
            peak = max(peak, current)
        time.sleep(0.04)
        with lock:
            current -= 1
        return index

    assert client._parallel_directory(slow, list(range(9))) == list(range(9))
    assert peak == 9


def test_adaptive_k_of_n_prefers_verified_fast_parity_but_never_less_than_k(mesh):
    client, _, _ = mesh
    node_ids = list(client.nodes)
    locators = [{"node": node, "sha256": "0" * 64, "bytes": 10}
                for node in node_ids[:6]]
    assert client._primary_indices(locators, 4) == [0, 1, 2, 3]
    client._verified_get_latency = {node_ids[0]: 5.0, node_ids[1]: 5.0,
                                    node_ids[2]: 0.2, node_ids[3]: 0.2,
                                    node_ids[4]: 0.05, node_ids[5]: 0.01}
    assert client._primary_indices(locators, 4) == [2, 3, 4, 5]
    assert len(set(client._primary_indices(locators, 4))) == 4


def test_mixed_parity_primary_roundtrip_keeps_hash_and_aead(mesh, tmp_path):
    publisher, _, _ = mesh
    source = tmp_path / "safe.bin"
    source.write_bytes(b"hello research lab" * 5000)
    stored = publisher.upload_file(source, chunk_bytes=32768, capability_version=2)
    reader = MeshClient({"nodes": list(publisher.nodes.values())}, http=publisher.http)
    # Simulate a proven fast parity set before restoring any fragments.
    from innernet2.crypto import parse_root, decrypt_metadata, deinterleave, derive
    from innernet2.network import INDEX_CELL, INDEX_K, INDEX_N
    root = parse_root(stored["capability"])
    entry = reader.resolve(root)
    cipher_len = entry["cipher_length"]
    mixed = reader._recover(entry["fragments"], INDEX_K, INDEX_N,
                            ((cipher_len + INDEX_CELL - 1) // INDEX_CELL) * INDEX_CELL)
    manifest = decrypt_metadata(root, deinterleave(mixed,
                                derive(root, "metadata/interleave/0"), INDEX_CELL, cipher_len), 0)
    locators = manifest["chunks"][0]["fragments"]
    for i, loc in enumerate(locators):
        reader._verified_get_latency[loc["node"]] = 0.001 if i >= 4 else 1.0
    assert 4 in reader._primary_indices(locators, 4)
    dest = tmp_path / "result.bin"
    assert reader.restore_file(stored["capability"], dest)["bytes"] == len(source.read_bytes())
    assert dest.read_bytes() == source.read_bytes()


def test_ssh_multiplexing_only_in_private_directory(tmp_path):
    folder = remote_lab.ensure_private_directory(tmp_path / "private")
    cfg = {"ssh": "root@example.test", "local_base": 29400}
    command = remote_lab.tunnel_args(cfg, folder)
    assert "ControlMaster=yes" in command
    assert f"ControlPath={folder / '.innernet-ssh.sock'}" in command
    assert "ExitOnForwardFailure=yes" in command
    assert command.count("-L") == 9
    unsafe = folder / ".innernet-ssh.sock"
    unsafe.symlink_to(tmp_path / "victim")
    with pytest.raises(remote_lab.RemoteLabError, match="symlink"):
        remote_lab.tunnel_args(cfg, folder)


def test_qualification_requires_storage_acknowledgment(tmp_path):
    with pytest.raises(remote_lab.RemoteLabError, match="acknowledge"):
        remote_lab.qualify_lab(tmp_path, [1048576])


@pytest.mark.parametrize("repeats, sizes", [(0, [100]), (6, [100]), (5, [1, 2, 3])])
def test_qualification_limits_total_writes(tmp_path, repeats, sizes):
    with pytest.raises(ValueError):
        remote_lab.qualify_lab(tmp_path, sizes, repeats=repeats, acknowledge=True)


def test_one_consolidated_qualification_one_audit_and_only_one_outage(tmp_path, monkeypatch):
    calls = {"audit": 0, "trial": [], "baseline": 0, "capacity": 0}
    folder = remote_lab.ensure_private_directory(tmp_path / "private")

    def audit(_folder):
        calls["audit"] += 1
        return {"nodes_audited": 9, "signatures_verified": 9}

    def capacity(_folder):
        calls["capacity"] += 1
        return {"failed": 0, "nodes": [{"node_id": f"node-{i:02d}",
                      "advertised_available_bytes": 256 * 1024**2} for i in range(1, 10)],
                "topology": {"independent_infrastructure_verified": False,
                             "distinct_advertised_hostnames": 1}}

    def trial(_folder, **kwargs):
        calls["trial"].append(kwargs)
        secret = folder / f"trial{len(calls['trial'])}" / "read.secret"
        secret.parent.mkdir()
        (secret.parent / "synthetic-input.bin").write_bytes(b"synthetic")
        return {"private_read_capability_file": str(secret), "upload_ms": 1000,
                "ordinary_read_ms": 1300, "ordinary_recovery": True,
                "three_remote_processes_offline_recovery": kwargs["simulate_group_a_failure"],
                "profiling": {"upload": {"stages": {"network.discovery_publish": {"cumulative_ms": 90}}},
                              "normal_read": {"stages": {"network.discovery_resolve": {"cumulative_ms": 120}}}}}

    def baseline(_folder, _source, **kwargs):
        calls["baseline"] += 1
        return {"upload_ms": 200, "download_ms": 190, "sha256_verified": True}

    monkeypatch.setattr(remote_lab, "audit_local", audit)
    monkeypatch.setattr(remote_lab, "capacity_local", capacity)
    monkeypatch.setattr(remote_lab, "refresh_container_reference", lambda _folder: {"container_refreshed": True})
    monkeypatch.setattr(remote_lab, "run_trial", trial)
    monkeypatch.setattr(remote_lab, "baseline_remote", baseline)
    result = remote_lab.qualify_lab(folder, [1048576, 2097152], repeats=2,
                                    outage=True, acknowledge=True)
    assert result["status"] == "PASS" and result["samples"] == 4
    assert result["container_refreshed"] is True
    assert calls["audit"] == 1 and calls["capacity"] == 1
    assert calls["baseline"] == 4
    assert len([call for call in calls["trial"] if call["simulate_group_a_failure"]]) == 1
    assert all(call["preverified_audit"]["signatures_verified"] == 9 for call in calls["trial"])
    assert result["summary"][0]["p95_ms"] == "insufficient_samples"
    assert "read.secret" not in json.dumps(result)
    assert result["topology"]["independent_infrastructure_verified"] is False


def test_qualification_blocks_excess_cumulative_quota(tmp_path, monkeypatch):
    monkeypatch.setattr(remote_lab, "audit_local", lambda _: {"nodes_audited": 9, "signatures_verified": 9})
    monkeypatch.setattr(remote_lab, "capacity_local", lambda _: {
        "failed": 0, "nodes": [{"node_id": f"node-{i:02d}", "advertised_available_bytes": 20_000_000}
                               for i in range(1, 10)],
        "topology": {"independent_infrastructure_verified": False, "distinct_advertised_hostnames": 1}})
    with pytest.raises(remote_lab.RemoteLabError, match="headroom"):
        remote_lab.qualify_lab(tmp_path, [10_000_000], repeats=2,
                               outage=False, acknowledge=True)


def test_up_fallback_uses_ordinary_ssh_if_control_tunnel_dies(monkeypatch):
    calls = []

    def fake_ssh(target, argv, **kwargs):
        calls.append(kwargs.get("control_path"))
        if kwargs.get("control_path"):
            raise remote_lab.RemoteLabError("control socket no longer available")
        return b"ok"

    monkeypatch.setattr(remote_lab, "ssh_command", fake_ssh)
    cfg = {"ssh": "root@example.test", "container": "lab-abc-20261122T145857",
           "_control_socket": "/tmp/private/.innernet-ssh.sock"}
    remote_lab.fault_set(cfg, "up")
    assert calls == [cfg["_control_socket"], None]
    calls.clear()
    with pytest.raises(remote_lab.RemoteLabError):
        remote_lab.fault_set(cfg, "down")
    assert calls == [cfg["_control_socket"]]


def test_container_refresh_rejects_unexpected_port_bindings(tmp_path, monkeypatch):
    folder = remote_lab.ensure_private_directory(tmp_path / "private")
    config = {"ssh": "root@example.test", "container": "lab-abc-20261122T145857", "local_base": 29400}
    remote_lab.secure_write(folder / "config.json", json.dumps(config).encode())
    fresh = "lab-abc-20261122T175015"

    def fake_ssh(target, argv, **kwargs):
        assert kwargs.get("control_path") == str(folder / ".innernet-ssh.sock")
        if argv[1] == "ps":
            return f"{fresh}\n".encode()
        if argv[1] == "port":
            return b"19401/tcp -> 0.0.0.0:19401\n"
        raise AssertionError(argv)

    monkeypatch.setattr(remote_lab, "ssh_command", fake_ssh)
    with pytest.raises(remote_lab.RemoteLabError, match="unexpected published ports"):
        remote_lab.refresh_container_reference(folder)
    assert remote_lab.read_config(folder)["container"] == config["container"]


def test_container_refresh_updates_exact_running_lab_only(tmp_path, monkeypatch):
    folder = remote_lab.ensure_private_directory(tmp_path / "private")
    config = {"ssh": "root@example.test", "container": "lab-abc-20261122T145857", "local_base": 29400}
    remote_lab.secure_write(folder / "config.json", json.dumps(config).encode())
    fresh = "lab-abc-20261122T175015"

    def fake_ssh(target, argv, **kwargs):
        if argv[1] == "ps":
            return f"{fresh}\n".encode()
        if argv[1] == "port":
            return "\n".join(f"{19400+i}/tcp -> 127.0.0.1:{19400+i}"
                             for i in range(1, 10)).encode()
        raise AssertionError(argv)

    monkeypatch.setattr(remote_lab, "ssh_command", fake_ssh)
    assert remote_lab.refresh_container_reference(folder)["container_refreshed"]
    assert remote_lab.read_config(folder)["container"] == fresh
    assert not remote_lab.refresh_container_reference(folder)["container_refreshed"]
