"""v0.3.8 immediate-delivery prototype and SSH readiness regression tests."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from innernet2 import remote_lab
from innernet2.version import RELEASE_VERSION
from innernet2.immediate_probe import probe_local_immediate_delivery


@pytest.mark.parametrize("size", [1, 256, 1152])
def test_authenticated_ephemeral_message_receipt_over_loopback(size):
    report = probe_local_immediate_delivery(samples=5, payload_bytes=size)
    assert report["tested"] is True
    assert report["scope"] == "loopback-only"
    assert report["authenticated_receipts"] == 5
    assert report["payload_bytes"] == size
    assert report["durability"] == "none"
    assert 0 <= report["p50_ms"] <= report["max_ms"]
    assert "VPN" in report["caution"]
    assert "session_secret" not in report and "session_id" not in report


@pytest.mark.parametrize("samples,size", [(0, 256), (26, 256), (1, 0), (1, 1153), (True, 256)])
def test_invalid_immediate_probe_arguments_rejected(samples, size):
    with pytest.raises(ValueError):
        probe_local_immediate_delivery(samples=samples, payload_bytes=size)


def test_wait_for_tunnel_ready_waits_for_authenticated_control_socket(tmp_path, monkeypatch):
    folder = remote_lab.ensure_private_directory(tmp_path / "private")
    control = folder / ".innernet-ssh.sock"
    remote_lab.secure_write(folder / "config.json", json.dumps({
        "ssh": "root@example.test", "container": "lab-abc-20261122T175015", "local_base": 29400
    }).encode())
    calls = {"checks": 0, "audit": 0}

    def fake_subprocess_run(args, **_kwargs):
        assert args[0] == "ssh" and args[2] == str(control)
        calls["checks"] += 1
        return SimpleNamespace(returncode=0)

    def fake_sleep(_seconds):
        control.touch()  # socket appears after SSH password was accepted

    def fake_audit(_folder, expected, seconds):
        assert expected == 9 and seconds > 0
        calls["audit"] += 1

    monkeypatch.setattr(remote_lab.subprocess, "run", fake_subprocess_run)
    monkeypatch.setattr(remote_lab.time, "sleep", fake_sleep)
    monkeypatch.setattr(remote_lab, "wait_for_audit", fake_audit)
    remote_lab.wait_for_tunnel_ready(folder, SimpleNamespace(poll=lambda: None), seconds=3)
    assert calls == {"checks": 1, "audit": 1}


def test_tunnel_exit_is_immediately_reported_without_waiting(tmp_path):
    folder = remote_lab.ensure_private_directory(tmp_path / "private")
    remote_lab.secure_write(folder / "config.json", json.dumps({
        "ssh": "root@example.test", "container": "lab-abc-20261122T175015", "local_base": 29400
    }).encode())
    with pytest.raises(remote_lab.RemoteLabError, match="exit 255"):
        remote_lab.wait_for_tunnel_ready(folder, SimpleNamespace(poll=lambda: 255), seconds=4)


def test_tunnel_ready_rejects_symlink_control_socket(tmp_path):
    folder = remote_lab.ensure_private_directory(tmp_path / "private")
    remote_lab.secure_write(folder / "config.json", json.dumps({
        "ssh": "root@example.test", "container": "lab-abc-20261122T175015", "local_base": 29400
    }).encode())
    (folder / ".innernet-ssh.sock").symlink_to(tmp_path / "not-ours")
    with pytest.raises(remote_lab.RemoteLabError, match="symlink"):
        remote_lab.wait_for_tunnel_ready(folder, SimpleNamespace(poll=lambda: None), seconds=4)


def test_qualification_rejects_too_many_immediate_probes(tmp_path):
    with pytest.raises(ValueError, match="immediate_probes"):
        remote_lab.qualify_lab(tmp_path, [1024], acknowledge=True, immediate_probes=26)


def test_qualification_local_probe_does_not_add_remote_writes(tmp_path, monkeypatch):
    folder = remote_lab.ensure_private_directory(tmp_path / "private")
    calls = {"trial": 0, "probe": 0}
    monkeypatch.setattr(remote_lab, "audit_local", lambda _: {"nodes_audited": 9, "signatures_verified": 9})
    monkeypatch.setattr(remote_lab, "capacity_local", lambda _: {
        "failed": 0, "nodes": [{"node_id": f"node-{i:02d}",
                                  "advertised_available_bytes": 256 * 1024**2} for i in range(1, 10)],
        "topology": {"independent_infrastructure_verified": False, "distinct_advertised_hostnames": 1}})

    def mock_trial(_folder, **_kwargs):
        calls["trial"] += 1
        trial = folder / "fake-trial"
        trial.mkdir(exist_ok=True)
        (trial / "synthetic-input.bin").write_bytes(b"dummy")
        return {"private_read_capability_file": str(trial / "read.secret"), "upload_ms": 1,
                "ordinary_read_ms": 1, "ordinary_recovery": True,
                "three_remote_processes_offline_recovery": "not-tested"}

    monkeypatch.setattr(remote_lab, "run_trial", mock_trial)
    monkeypatch.setattr(remote_lab, "baseline_remote", lambda *_args, **_kw: {
        "upload_ms": 1, "download_ms": 1, "sha256_verified": True})

    def mock_probe(**_kw):
        calls["probe"] += 1
        return {"scope": "loopback-only", "tested": True}

    monkeypatch.setattr(remote_lab, "probe_local_immediate_delivery", mock_probe)
    report = remote_lab.qualify_lab(folder, [1024], outage=False, profile=False,
                                    read_repeats=1, immediate_probes=9, acknowledge=True)
    assert report["status"] == "PASS" and report["version"] == RELEASE_VERSION
    assert report["immediate_delivery_local"]["scope"] == "loopback-only"
    assert calls == {"trial": 1, "probe": 1}


def test_local_immediate_probe_cli_runs_without_config_directory(tmp_path):
    proc = subprocess.run([sys.executable, "-m", "innernet2.remote_lab", "--dir", str(tmp_path / "nonexistent"),
                           "immediate-probe", "--samples", "3"],
                          capture_output=True, text=True, timeout=15)
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    assert report["samples"] == 3 and report["authenticated_receipts"] == 3
