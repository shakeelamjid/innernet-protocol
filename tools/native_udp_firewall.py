#!/usr/bin/env python3
"""Opt-in, narrowly scoped VPS firewall gate for the INNERnet UDP test sidecar.

No automatic public Docker publication. Run as root on the VPS only after
reviewing the generated plan. Restricts the original public destination UDP
port, including Docker's forwarded packet path. Changes are temporary and may
be lost on reboot. This helper has not been validated on every Docker/UFW host.

Examples:
  sudo python3 tools/native_udp_firewall.py status
  sudo python3 tools/native_udp_firewall.py plan --client-ip 203.0.113.10 --server-ip 198.51.100.5
  sudo python3 tools/native_udp_firewall.py apply --client-ip ... --server-ip ...
  # Stop receiver BEFORE running remove
  sudo python3 tools/native_udp_firewall.py remove --client-ip ... --server-ip ...
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import re
import subprocess
import sys

TAG = "innernet-v041-udp-29410"
PORT = "29410"


def command(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), check=check, text=True,
                          capture_output=True)


def address(text: str) -> str:
    try:
        ip = ipaddress.IPv4Address(text)
    except ipaddress.AddressValueError as exc:
        raise ValueError("expected a valid IPv4 address") from exc
    if not ip.is_global:
        raise ValueError("a publicly routable IPv4 address is required")
    return str(ip)


def rules(client: str, server: str, interface: str) -> list[list[str]]:
    """Exact iptables tails, with module comment tag for safe removal."""
    return [
        ["-i", interface, "-p", "udp", "-m", "conntrack",
         "--ctorigdst", server, "--ctorigdstport", PORT,
         "!", "-s", client + "/32", "-m", "comment", "--comment", TAG, "-j", "DROP"],
        ["!", "-s", client + "/32", "-i", interface, "-p", "udp",
         "-m", "udp", "--dport", PORT,
         "-m", "comment", "--comment", TAG, "-j", "DROP"],
    ]


def show_status() -> None:
    for title, args in (
        ("DOCKER-USER rules", ["iptables", "-S", "DOCKER-USER"]),
        ("INPUT rules", ["iptables", "-S", "INPUT"]),
        ("UFW", ["ufw", "status", "verbose"]),
        ("Published UDP container ports", ["docker", "ps", "--format", "{{.Names}} {{.Ports}}"]),
    ):
        print("=====", title, "=====")
        result = command(*args, check=False)
        if title == "INPUT rules":
            print("\n".join(line for line in result.stdout.splitlines() if PORT in line) or "(no UDP rule mentioning port)")
        elif title == "DOCKER-USER rules":
            print(result.stdout.strip() or "(none)")
        elif title == "Published UDP container ports":
            print("\n".join(line for line in result.stdout.splitlines() if PORT in line) or "(none)")
        else:
            print(result.stdout.strip())
        if result.returncode:
            print(f"WARNING: {' '.join(args[:2])} returned {result.returncode}: {result.stderr.strip()}")


def ensure_preflight(client: str, server: str, interface: str) -> None:
    if os.geteuid() != 0:
        raise RuntimeError("must run as root on the Contabo VPS")
    if client == server:
        raise RuntimeError("client and server IP cannot be the same")
    forward = command("iptables", "-S", "FORWARD").stdout
    if "-j DOCKER-USER" not in forward:
        raise RuntimeError("Docker FORWARD chain does not jump to DOCKER-USER: stop; manual review required")
    docker_user = command("iptables", "-S", "DOCKER-USER").stdout
    # Existing unrelated port-specific rules need a manual review; don't override.
    for line in docker_user.splitlines():
        if PORT in line and TAG not in line:
            raise RuntimeError("unexpected existing DOCKER-USER rule for UDP port: stop; manual review required")
    ufw_status = command("ufw", "status", "verbose").stdout.lower()
    if "status: active" not in ufw_status or "deny (incoming)" not in ufw_status:
        raise RuntimeError("UFW must be active with default incoming deny")
    if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_.-]*", interface):
        raise RuntimeError("invalid interface name")
    route = command("ip", "-4", "route", "get", "1.1.1.1").stdout
    if f"dev {interface} " not in route or f"src {server}" not in route:
        raise RuntimeError("server IP/interface do not match public route; manual review required")


def contains(chain: str, tail: list[str]) -> bool:
    return command("iptables", "-C", chain, *tail, check=False).returncode == 0


def receiver_running() -> bool:
    result = command("docker", "ps", "--format", "{{.Names}} {{.Ports}}")
    return any(PORT + "->" in line or f":{PORT}->" in line
               for line in result.stdout.splitlines())


def apply(client: str, server: str, interface: str) -> None:
    ensure_preflight(client, server, interface)
    tails = rules(client, server, interface)
    entries = [("DOCKER-USER", tails[0]), ("INPUT", tails[1])]
    present = [contains(chain, tail) for chain, tail in entries]
    if any(present) and not all(present):
        raise RuntimeError("partial firewall rule set; stop for manual review")
    if all(present):
        print("Tagged iptables restrictions already installed; verifying UFW")
    inserted: list[tuple[str, list[str]]] = []
    try:
        for (chain, tail), exists in zip(entries, present):
            if not exists:
                command("iptables", "-I", chain, "1", *tail)
                inserted.append((chain, tail))
        status = command("ufw", "status").stdout
        existing = [line for line in status.splitlines()
                    if PORT + "/udp" in line and client in line and "ALLOW" in line]
        if existing and not all(TAG in line for line in existing):
            raise RuntimeError("UFW allowance already exists without INNERnet tag; manual review required")
        if not existing:
            command("ufw", "allow", "from", client, "to", "any", "port", PORT,
                    "proto", "udp", "comment", TAG)
    except (OSError, subprocess.CalledProcessError):
        for chain, tail in reversed(inserted):
            command("iptables", "-D", chain, *tail, check=False)
        raise
    print(f"Installed narrow test restrictions: UDP {server}:{PORT} from {client} only")
    print("The receiver remains unmodified. Docker public binding is a separate, explicit action.")
    print("iptables -I changes may disappear on reboot; do not assume they are persistent.")


def remove(client: str, server: str, interface: str) -> None:
    if os.geteuid() != 0:
        raise RuntimeError("must run as root on the VPS")
    if receiver_running():
        raise RuntimeError("a Docker container still publishes UDP 29410; stop the listener before removing restrictions")
    tails = rules(client, server, interface)
    for chain, tail in (("INPUT", tails[1]), ("DOCKER-USER", tails[0])):
        if contains(chain, tail):
            command("iptables", "-D", chain, *tail)
    status = command("ufw", "status").stdout
    if any(PORT + "/udp" in line and client in line and "ALLOW" in line and TAG in line
           for line in status.splitlines()):
        command("ufw", "--force", "delete", "allow", "from", client,
                "to", "any", "port", PORT, "proto", "udp")
    print("Removed matching test-specific rules; no other Docker/Coolify changes")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="INNERnet v0.4.1 opt-in UDP 29410 VPS firewall helper")
    parser.add_argument("mode", choices=["status", "plan", "apply", "remove"])
    parser.add_argument("--client-ip")
    parser.add_argument("--server-ip")
    parser.add_argument("--interface", default="eth0")
    args = parser.parse_args(argv)
    try:
        if args.mode == "status":
            show_status()
            return 0
        if not args.client_ip or not args.server_ip:
            raise ValueError("--client-ip and --server-ip are required")
        client = address(args.client_ip)
        server = address(args.server_ip)
        if args.mode == "plan":
            print(f"Read-only plan for client {client} and server {server}:{PORT}")
            for chain, tail in zip(("DOCKER-USER", "INPUT"), rules(client, server, args.interface)):
                print("iptables -I", chain, "1", " ".join(tail))
            print("ufw allow from", client, "to any port", PORT, "proto udp")
            print("No commands executed. Run apply only after reviewing the rules and VPS policy.")
        elif args.mode == "apply":
            apply(client, server, args.interface)
        else:
            remove(client, server, args.interface)
        return 0
    except (ValueError, RuntimeError, OSError, subprocess.CalledProcessError) as exc:
        print("REFUSED:", exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
