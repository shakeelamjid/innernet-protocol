"""v0.3.9 cross-host stream codec, ephemeral handshake and dual-delivery tests.

All tests run locally. Remote Mac-to-Contabo behavior requires the actual
one-command qualification; no CI test pretends to prove internet performance.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import subprocess
import sys
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from innernet2 import remote_lab, remote_transit
from innernet2.version import RELEASE_VERSION


def worker(source=remote_transit.REMOTE_WORKER):
    return subprocess.Popen([sys.executable, "-u", "-c", source],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, bufsize=0)


@pytest.mark.parametrize("length", [1, 256, 1152])
def test_remote_framed_authenticated_delivery_round_trip(length):
    p = worker()
    try:
        msg = secrets.token_bytes(length)
        report = remote_transit.probe_process(p, samples=5, payload_bytes=length,
                                               first_message=msg)
        assert report["authenticated_receipts"] == 5
        assert report["first_message_sha256"] == hashlib.sha256(msg).hexdigest()
        assert report["failed_receipts"] == 0
        assert report["durability"].startswith("none")
        assert report["scope"] == "local-process-test"
        assert "NOT direct UDP" in report["carrier"]
        assert report["packet_loss"].startswith("not measurable")
        assert report["min_ms"] <= report["p50_ms"] <= report["p95_ms"] <= report["max_ms"]
        serialized = json.dumps(report)
        if len(msg) >= 16:
            assert msg.hex() not in serialized
        assert "session_secret" not in serialized
    finally:
        remote_transit._finish_process(p)
    assert p.returncode == 0


def test_bad_authenticated_remote_receipt_is_rejected():
    corrupt_worker = remote_transit.REMOTE_WORKER.replace(
        "hashlib.sha256(message).digest()", "bytes(32)")
    p = worker(corrupt_worker)
    try:
        with pytest.raises(remote_transit.RemoteTransitError, match="did not match"):
            remote_transit.probe_process(p, samples=1)
    finally:
        remote_transit._finish_process(p)


def test_untrusted_handshake_cannot_open_live_session():
    changed = remote_transit.REMOTE_WORKER.replace(
        "INFO = b\"INNERnet/remote-transit/v0.3.9/ssh-ephemeral\"",
        "INFO = b\"malicious remote transcript\"")
    p = worker(changed)
    try:
        with pytest.raises(remote_transit.RemoteTransitError, match="handshake failed"):
            remote_transit.probe_process(p, samples=1)
    finally:
        remote_transit._finish_process(p)


@pytest.mark.parametrize("samples,length", [
    (0,256), (33,256), (True,256), (1,0), (1,1153),
])
def test_reject_invalid_remote_probe_dimensions(samples, length):
    p = worker()
    try:
        with pytest.raises(ValueError):
            remote_transit.probe_process(p, samples=samples, payload_bytes=length)
    finally:
        remote_transit._finish_process(p)


def test_reject_inconsistent_shared_payload_size():
    p = worker()
    try:
        with pytest.raises(ValueError, match="wrong size"):
            remote_transit.probe_process(p, samples=1, first_message=b"short")
    finally:
        remote_transit._finish_process(p)


def test_remote_ssh_command_requires_current_private_control_socket(tmp_path):
    folder = remote_lab.ensure_private_directory(tmp_path / "private")
    config = {"ssh": "root@example.test", "container": "lab-abc-20261122T175015"}
    with pytest.raises(remote_lab.RemoteLabError, match="tunnel missing"):
        remote_transit._remote_ssh_args(config, folder)
    (folder / ".innernet-ssh.sock").symlink_to(tmp_path / "outside")
    with pytest.raises(remote_lab.RemoteLabError, match="tunnel missing"):
        remote_transit._remote_ssh_args(config, folder)


def test_ssh_command_uses_pinned_private_socket_without_secret_argv(tmp_path):
    folder = remote_lab.ensure_private_directory(tmp_path / "private")
    (folder / ".innernet-ssh.sock").touch()
    config = {"ssh": "root@example.test", "container": "lab-abc-20261122T175015"}
    args = remote_transit._remote_ssh_args(config, folder)
    assert args[0] == "ssh" and "BatchMode=yes" in args
    assert "ControlPath=" in " ".join(args)
    assert args[-2] == "root@example.test"
    assert "docker" in args[-1] and "exec" in args[-1] and "-u" in args[-1]
    assert "X25519PrivateKey.generate()" in args[-1]
    assert "IN39" not in args[-1]


def test_dual_delivery_uses_same_synthetic_payload(monkeypatch, tmp_path):
    folder = remote_lab.ensure_private_directory(tmp_path / "private")
    monkeypatch.setattr(remote_lab, "audit_local", lambda _f: {"nodes_audited":9, "signatures_verified":9})
    monkeypatch.setattr(remote_lab, "capacity_local", lambda _f: {
        "failed": 0,
        "nodes": [{"node_id": f"node-{i:02d}", "advertised_available_bytes": 200_000_000}
                  for i in range(1, 10)],
        "topology": {"independent_infrastructure_verified": False,
                     "distinct_advertised_hostnames": 1}})
    monkeypatch.setattr(remote_lab, "refresh_container_reference", lambda _f: {"container_refreshed": False})
    seen = {}
    def fake_probe(_f, *, first_message, **_kw):
        seen["message"] = first_message
        return {"p50_ms": 5.0, "first_message_sha256": hashlib.sha256(first_message).hexdigest(),
                "tested": True}
    def fake_small(_f, *, synthetic_payload, **_kw):
        assert synthetic_payload == seen["message"]
        return {"tested": True, "message_sha256": hashlib.sha256(synthetic_payload).hexdigest(),
                "upload_ms": 20, "first_restore_ms": 25}
    def fake_trial(_f, **_kw):
        path = folder / "sample"
        path.mkdir(exist_ok=True)
        (path / "synthetic-input.bin").write_bytes(b"synthetic")
        return {"private_read_capability_file": str(path / "read.secret"),
                "upload_ms": 1, "ordinary_read_ms": 1, "ordinary_recovery": True,
                "three_remote_processes_offline_recovery": "not-tested"}
    monkeypatch.setattr(remote_lab, "probe_remote_transit", fake_probe)
    monkeypatch.setattr(remote_lab, "small_message_probe", fake_small)
    monkeypatch.setattr(remote_lab, "run_trial", fake_trial)
    monkeypatch.setattr(remote_lab, "baseline_remote", lambda *_args, **_kw: {
        "upload_ms": 1, "download_ms": 1, "sha256_verified": True})
    report = remote_lab.qualify_lab(folder, [1024], outage=False, profile=False,
                                    read_repeats=1, latency_probes=3,
                                    remote_probes=5, acknowledge=True)
    assert report["status"] == "PASS" and report["version"] == RELEASE_VERSION
    assert report["dual_delivery"]["same_synthetic_message_sha256_verified"]
    assert report["immediate_delivery_remote"]["tested"]
    assert report["dual_delivery"]["separate_storage_upload_ms"] == 20


def test_dual_delivery_detects_payload_mismatch(monkeypatch, tmp_path):
    folder = remote_lab.ensure_private_directory(tmp_path / "private")
    monkeypatch.setattr(remote_lab, "audit_local", lambda _f: {"nodes_audited":9,"signatures_verified":9})
    monkeypatch.setattr(remote_lab, "capacity_local", lambda _f: {
        "failed": 0, "nodes": [{"node_id": f"node-{i:02d}", "advertised_available_bytes": 200_000_000}
                               for i in range(1,10)],
        "topology": {"independent_infrastructure_verified": False,"distinct_advertised_hostnames":1}})
    monkeypatch.setattr(remote_lab, "refresh_container_reference", lambda _f: {"container_refreshed":False})
    monkeypatch.setattr(remote_lab, "probe_remote_transit", lambda *_args, **_kw: {
        "tested": True, "first_message_sha256": "0"*64})
    monkeypatch.setattr(remote_lab, "small_message_probe", lambda *_args, **_kw: {
        "tested": True, "message_sha256": "1"*64})
    with pytest.raises(remote_lab.RemoteLabError, match="SHA-256 mismatch"):
        remote_lab.qualify_lab(folder, [1024], outage=False, profile=False,
                               remote_probes=1, latency_probes=1, acknowledge=True)


def test_remote_samples_bounds_checked_early(tmp_path):
    with pytest.raises(ValueError, match="remote_probes"):
        remote_lab.qualify_lab(tmp_path, [1024], acknowledge=True, remote_probes=33)
