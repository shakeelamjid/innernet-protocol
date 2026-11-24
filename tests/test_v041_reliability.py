"""v0.4.1 reliability checks: localhost only, synthetic packets, no firewall changes."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import sys
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from innernet2.native_udp import NativeResponder, native_probe, pub_bytes, serve
from innernet2.native_udp_reliability import reliability_qualification

ROOT = Path(__file__).resolve().parents[1]


def test_fault_suite_five_scenarios_all_deliver_once():
    report = reliability_qualification(samples=8, clients=3, timeout=.06, attempts=4)
    assert report["status"] == "PASS"
    assert len(report["scenarios"]) == 5
    assert report["total_authenticated_receipts"] == report["total_requested_messages"] == 120
    assert all(s["server_unique_messages"] == s["requested_messages"] for s in report["scenarios"])
    scenarios = {s["scenario"]: s for s in report["scenarios"]}
    assert scenarios["first_handshake_response_lost"]["handshake_retransmissions"] >= 1
    assert scenarios["first_handshake_response_lost"]["server_duplicate_handshakes"] >= 1
    assert scenarios["first_receipt_lost"]["data_retransmissions"] >= 1
    assert scenarios["every_fourth_receipt_lost"]["faults_injected"]["dropped_receipts"] == 6
    assert scenarios["duplicate_data_ingress"]["server_duplicate_datagrams"] >= 24


def test_fault_suite_rejects_unbounded_inputs():
    for kwargs in ({"samples": 0}, {"clients": 9}, {"attempts": 2}, {"timeout": 5}):
        with pytest.raises(ValueError, match="qualification limits"):
            reliability_qualification(**kwargs)


def test_reliability_cli_runs_and_reports_five_scenarios():
    command = [sys.executable, "-m", "innernet2.native_udp", "reliability-qualify",
               "--samples", "4", "--clients", "2", "--timeout", ".06"]
    output = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=20)
    assert output.returncode == 0, output.stderr
    report = json.loads(output.stdout)
    assert report["status"] == "PASS"
    assert report["total_authenticated_receipts"] == 40
    assert report["wire_version"].startswith("IN40")
    assert "NOT public Internet" in report["scope"]


def test_interval_and_telemetry_and_multiple_sessions():
    server = Ed25519PrivateKey.generate()
    clients = [Ed25519PrivateKey.generate() for _ in range(2)]
    responder = NativeResponder(server, {pub_bytes(client) for client in clients})
    stop = threading.Event()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        thread = threading.Thread(target=serve, args=(sock, responder),
                                  kwargs={"stop": stop}, daemon=True)
        thread.start()
        try:
            for client in clients:
                result = native_probe("127.0.0.1", sock.getsockname()[1],
                                      client, pub_bytes(server), samples=4,
                                      timeout=.08, interval_ms=2)
                assert result["status"] == "PASS"
                assert result["handshake_attempts"] >= 1
                assert result["handshake_retransmissions"] == 0
                assert result["ack_timeouts"] == 0
                assert result["late_authenticated_receipts"] == 0
                assert result["delivery_ratio"] == 1.0
                assert result["acknowledged_payload_bytes"] == 1024
                assert result["application_goodput_kib_s"] > 0
                assert result["probe_elapsed_ms"] >= 5
                assert result["interval_ms"] == 2
        finally:
            stop.set()
            thread.join(timeout=2)
    assert responder.accepted_handshakes == 2
    assert responder.accepted_messages == 8


def test_firewall_plan_is_read_only_and_rejects_bad_ip():
    path = ROOT / "tools" / "native_udp_firewall.py"
    # The plan command requires globally routable addresses. These are used
    # for a read-only plan, never for applying firewall changes or networking.
    cmd = [sys.executable, str(path), "plan", "--client-ip", "8.8.8.8",
           "--server-ip", "1.1.1.1"]
    result = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=5)
    assert result.returncode == 0
    assert "No commands executed" in result.stdout
    assert "DOCKER-USER" in result.stdout
    assert "29410" in result.stdout
    assert "innernet-v041-udp-29410" in result.stdout
    assert "iptables -F" not in result.stdout
    for invalid in ("127.0.0.1", "1.2.3.999", "10.1.1.1",
                    "198.51.100.139", "203.0.113.10", "1.2.3.4; touch /tmp/oops"):
        cmd_bad = cmd[:]
        cmd_bad[cmd_bad.index("--client-ip") + 1] = invalid
        p = subprocess.run(cmd_bad, capture_output=True, text=True, timeout=5)
        assert p.returncode == 2
        assert "REFUSED" in p.stderr


def test_firewall_apply_refuses_without_root_or_verified_preflight(monkeypatch):
    """Smoke test the safety gate without touching the real system firewall."""
    path = ROOT / "tools" / "native_udp_firewall.py"
    spec = importlib.util.spec_from_file_location("v041_fw", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.os, "geteuid", lambda: 1000)
    with pytest.raises(RuntimeError, match="root"):
        module.ensure_preflight("198.51.100.139", "203.0.113.10", "eth0")


def test_legacy_compose_files_not_auto_exposing_udp_port():
    for name in ("compose.coolify.yaml", "compose.lab.coolify.yaml", "compose.ssh-tunnel.coolify.yaml"):
        assert "29410" not in (ROOT / name).read_text()
    source = (ROOT / "innernet2" / "native_udp.py").read_text()
    # Guard the handshake wire identity: do not silently fork the protocol.
    assert 'PROTOCOL = b"IN40"' in source
    assert 'HANDSHAKE_DOMAIN = b"INNERnet/native-udp/0.4.0-alpha/handshake"' in source


def _firewall_module():
    path = ROOT / "tools" / "native_udp_firewall.py"
    spec = importlib.util.spec_from_file_location("v041_firewall_mock", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_firewall_explicit_apply_and_safe_removal_with_fake_commands(monkeypatch):
    """No actual firewall commands run: check order, scope, tags, idempotence."""
    module = _firewall_module()
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    client, server = "198.51.100.139", "203.0.113.10"
    state = {"DOCKER-USER": set(), "INPUT": set(), "ufw": "", "published": ""}
    operations = []

    def fake_cmd(*args, check=True):
        operations.append(args)
        binary = args[0]
        if binary == "iptables" and args[1] in ("-C", "-I", "-D"):
            action, chain = args[1:3]
            tail = tuple(args[4:] if action == "-I" else args[3:])
            if action == "-C":
                present = tail in state[chain]
                return subprocess.CompletedProcess(args, 0 if present else 1, "", "")
            if action == "-I":
                state[chain].add(tail)
            else:
                state[chain].discard(tail)
            return subprocess.CompletedProcess(args, 0, "", "")
        if binary == "iptables" and args[1:3] == ("-S", "FORWARD"):
            return subprocess.CompletedProcess(args, 0, "-A FORWARD -j DOCKER-USER", "")
        if binary == "iptables" and args[1:3] == ("-S", "DOCKER-USER"):
            return subprocess.CompletedProcess(args, 0, "-N DOCKER-USER", "")
        if binary == "ufw":
            if args[1:3] == ("status", "verbose"):
                return subprocess.CompletedProcess(args, 0, "Status: active\nDefault: deny (incoming), allow (outgoing), allow (routed)", "")
            if args[1] == "status":
                return subprocess.CompletedProcess(args, 0, state["ufw"], "")
            if args[1] == "allow":
                assert "comment" in args and module.TAG in args
                state["ufw"] = f"29410/udp ALLOW {client} # {module.TAG}"
            if args[1] == "--force":
                state["ufw"] = ""
            return subprocess.CompletedProcess(args, 0, "", "")
        if binary == "ip":
            return subprocess.CompletedProcess(args, 0, f"1.1.1.1 via 13.140.128.1 dev eth0 src {server}", "")
        if binary == "docker":
            return subprocess.CompletedProcess(args, 0, state["published"], "")
        raise AssertionError(args)

    monkeypatch.setattr(module, "command", fake_cmd)
    module.apply(client, server, "eth0")
    assert len(state["DOCKER-USER"]) == 1 and len(state["INPUT"]) == 1
    assert module.TAG in state["ufw"]
    assert "--ctorigdstport" in next(iter(state["DOCKER-USER"]))
    assert "29410" in next(iter(state["DOCKER-USER"]))
    first_total = len([op for op in operations if op[:2] == ("iptables", "-I")])
    module.apply(client, server, "eth0")
    assert len([op for op in operations if op[:2] == ("iptables", "-I")]) == first_total
    state["published"] = "innernet-v041-live 203.0.113.10:29410->29410/udp"
    with pytest.raises(RuntimeError, match="stop the listener"):
        module.remove(client, server, "eth0")
    state["published"] = ""
    module.remove(client, server, "eth0")
    assert state["DOCKER-USER"] == set() and state["INPUT"] == set()
    assert state["ufw"] == ""
    assert not any(op[:2] == ("iptables", "-F") for op in operations)
