"""End-to-end v0.3.2 research client across nine real HTTP processes.

No real SSH or external provider involved; fault injection kills three *processes*.
"""
from __future__ import annotations

import contextlib
import io
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from innernet2 import remote_lab
from innernet2.cli import create_demo


def port_range():
    for base in range(27000, 37000, 17):
        sockets = []
        try:
            for i in range(9):
                sock = socket.socket()
                sock.bind(("127.0.0.1", base+i))
                sockets.append(sock)
            return base
        except OSError:
            continue
        finally:
            for sock in sockets:
                sock.close()
    raise RuntimeError("no nine-port test range available")


def test_mac_style_client_transfers_and_recovers_when_three_processes_fail(tmp_path, monkeypatch):
    base_port = port_range()
    mesh = tmp_path / "mesh"
    with contextlib.redirect_stdout(io.StringIO()):
        create_demo(mesh, 9, base_port)
    original_peers = json.loads((mesh / "peers.json").read_text())
    for i, peer in enumerate(original_peers["nodes"]):
        peer["failure_domain"] = f"simulated-group-{'abc'[i//3]}"
    folder = remote_lab.ensure_private_directory(tmp_path / "client")
    remote_lab.secure_write(folder / "peers.json", json.dumps(original_peers).encode())
    remote_lab.secure_write(folder / "writers.json", (mesh / "writers.json").read_bytes())
    remote_lab.secure_write(folder / "config.json", json.dumps({
        "ssh": "root@example.test", "container": "lab-abc-20261122T145857", "local_base": base_port-1
    }).encode())
    procs = {}

    def start_one(i):
        node_id = f"node-{i:02d}"
        procs[node_id] = subprocess.Popen([
            sys.executable, "-m", "innernet2.cli", "serve-node", "--dir",
            str(mesh / node_id), "--port", str(base_port + i - 1)
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def stop_one(i):
        node_id = f"node-{i:02d}"
        p = procs.pop(node_id)
        p.terminate()
        p.wait(timeout=5)

    try:
        for i in range(1, 10):
            start_one(i)
        remote_lab.wait_for_audit(folder, 9, seconds=15)
        assert remote_lab.audit_local(folder)["nodes_audited"] == 9

        def fake_fault_set(_config, state):
            if state == "down":
                for i in range(1, 4):
                    stop_one(i)
            else:
                for i in range(1, 4):
                    start_one(i)

        monkeypatch.setattr(remote_lab, "fault_set", fake_fault_set)
        result = remote_lab.run_trial(folder, simulate_group_a_failure=True, data_size=180_000)
        assert result["result"] == "PASS"
        assert result["ordinary_recovery"] is True
        assert result["three_remote_processes_offline_recovery"] is True
        assert result["nodes_online_after"] == 9
        assert result["read_client_had_upload_tokens"] is False
        cap = Path(result["private_read_capability_file"])
        assert cap.exists() and cap.stat().st_mode & 0o077 == 0
        assert (cap.parent / "recovered-normal.bin").read_bytes() == (cap.parent / "synthetic-input.bin").read_bytes()
        assert (cap.parent / "recovered-with-outage.bin").read_bytes() == (cap.parent / "synthetic-input.bin").read_bytes()

        # Explicitly authorized research-file workflow; still private tunnel only.
        test_input = tmp_path / "safe-synthetic-file.bin"
        test_input.write_bytes(b"not sensitive " * 2500)
        upload = remote_lab.upload_local_file(folder, test_input, acknowledge=True)
        assert upload["status"] == "STORED"
        file_cap = Path(upload["read_capability_file"])
        assert file_cap.exists() and file_cap.stat().st_mode & 0o077 == 0
        output = tmp_path / "file-recovered.bin"
        restored = remote_lab.restore_local_file(folder, file_cap, output)
        assert restored["result"] == "PASS"
        assert output.read_bytes() == test_input.read_bytes()
        assert output.stat().st_mode & 0o077 == 0
        with pytest.raises(remote_lab.RemoteLabError, match="overwrit"):
            remote_lab.restore_local_file(folder, file_cap, output)

        # v0.3.4 signed monitoring and controlled synthetic HTTP baseline, all
        # through the existing private local nine-process lab.
        capacity = remote_lab.capacity_local(folder)
        assert capacity["verified"] == 9 and capacity["failed"] == 0
        assert capacity["topology"]["distinct_advertised_hostnames"] == 1
        assert capacity["topology"]["independent_infrastructure_verified"] is False
        comparison = remote_lab.compare_remote(folder, [8192], workers=4, acknowledge=True)
        assert comparison["status"] == "PASS"
        assert comparison["results"][0]["baseline_sha256_verified"]
        # v0.3.6 one-command remote qualification: audit, capacity,
        # K-of-N outage and one-node baseline all use the SAME synthetic file.
        # The integration lab has no SSH; fault_set above is already mocked.
        monkeypatch.setattr(remote_lab, "refresh_container_reference",
                            lambda _folder: {"container_refreshed": False})
        qualification = remote_lab.qualify_lab(folder, [16384], workers=4,
                                               outage=True, acknowledge=True,
                                               read_repeats=5, latency_probes=5)
        assert qualification["status"] == "PASS"
        assert qualification["nodes_audited"] == 9
        assert qualification["samples"] == 1
        assert qualification["results"][0]["outage_recovery"] is True
        assert qualification["results"][0]["sha256_verified"] is True
        assert qualification["topology"]["independent_infrastructure_verified"] is False
        assert qualification["summary"][0]["read_only_distribution"]["samples"] == 5
        assert isinstance(qualification["summary"][0]["read_only_distribution"]["p95_ms"], int)
        assert qualification["small_message"]["tested"] is True
        assert qualification["small_message"]["payload_bytes"] == 256
        assert qualification["small_message"]["repeated_restores"]["verified_sha256"] is True
        assert qualification["small_message"]["repeated_restores"]["samples"] == 5
        assert qualification["small_message"]["repeated_restores"]["signed_discovery_cache_hits"] >= 4
        assert "read.secret" not in json.dumps(qualification)

        status = remote_lab.inspect_local_file(folder, file_cap)
        assert status["shard_status"]["missing"] == 0
        sweep = remote_lab.maintenance_once(folder, max_objects=1)
        assert sweep["mode"] == "audit" and sweep["objects_scanned"] == 1
    finally:
        for p in procs.values():
            p.terminate()
        for p in procs.values():
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
