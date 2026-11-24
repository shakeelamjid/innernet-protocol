"""v0.4.1 loopback-only native-UDP reliability qualification.

Uses real local UDP sockets and the unchanged IN40 responder/client, but injects
controlled response drops and duplicated incoming packets. All peers/identities
are ephemeral and remain in memory; no VPS, Docker, or firewall changes.
This is a deterministic functional fault test, NOT an Internet packet-loss or
security certification. Run `python -m innernet2.native_udp reliability-qualify`.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import hashlib
import socket
import threading
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .native_udp import NativeResponder, RELEASE_VERSION, native_probe, pub_bytes


@dataclass(frozen=True)
class FaultPlan:
    label: str
    drop_handshake_responses: int = 0
    drop_first_receipt: bool = False
    drop_every_nth_receipt: int = 0
    duplicate_data_ingress: bool = False


PROFILES = (
    FaultPlan("baseline"),
    FaultPlan("first_handshake_response_lost", drop_handshake_responses=1),
    FaultPlan("first_receipt_lost", drop_first_receipt=True),
    FaultPlan("every_fourth_receipt_lost", drop_every_nth_receipt=4),
    FaultPlan("duplicate_data_ingress", duplicate_data_ingress=True),
)


def _exercise(plan: FaultPlan, *, samples: int, clients: int,
              timeout: float, attempts: int) -> dict[str, Any]:
    server = Ed25519PrivateKey.generate()
    client_secrets = [Ed25519PrivateKey.generate() for _ in range(clients)]
    responder = NativeResponder(server, {pub_bytes(client) for client in client_secrets})
    stop = threading.Event()
    faults = {"dropped_handshake_responses": 0, "dropped_receipts": 0,
              "duplicated_data_ingress": 0}
    unique_data: set[bytes] = set()
    seen_count = 0
    failures: list[str] = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(0.05)
        port = sock.getsockname()[1]

        def worker() -> None:
            nonlocal seen_count
            while not stop.is_set():
                try:
                    packet, addr = sock.recvfrom(2049)
                except socket.timeout:
                    continue
                except OSError:
                    return
                try:
                    response = responder.process(packet, addr)
                    if response is None:
                        continue
                    if packet.startswith(b"IN40C") and faults["dropped_handshake_responses"] < plan.drop_handshake_responses:
                        faults["dropped_handshake_responses"] += 1
                        continue
                    if packet.startswith(b"INL2"):
                        digest = hashlib.sha256(packet).digest()
                        fresh = digest not in unique_data
                        if fresh:
                            unique_data.add(digest)
                            seen_count += 1
                        if plan.duplicate_data_ingress:
                            # The same authenticated encrypted datagram must not
                            # be counted twice as a unique received message.
                            assert responder.process(packet, addr) == response
                            faults["duplicated_data_ingress"] += 1
                        drop = fresh and ((plan.drop_first_receipt and seen_count == 1)
                                          or (plan.drop_every_nth_receipt > 0
                                              and seen_count % plan.drop_every_nth_receipt == 0))
                        if drop:
                            faults["dropped_receipts"] += 1
                            continue
                    sock.sendto(response, addr)
                except (AssertionError, OSError, ValueError) as exc:
                    failures.append(type(exc).__name__)
                    stop.set()
                    return

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        try:
            def run(client: Ed25519PrivateKey) -> dict[str, Any]:
                return native_probe("127.0.0.1", port, client, pub_bytes(server),
                                    samples=samples, timeout=timeout, attempts=attempts)

            with ThreadPoolExecutor(max_workers=clients) as executor:
                futures = [executor.submit(run, identity) for identity in client_secrets]
                reports = [future.result() for future in futures]
        finally:
            stop.set()
            thread.join(timeout=3)
        if thread.is_alive():
            raise RuntimeError("loopback qualification responder did not stop")

    unique_expected = samples * clients
    receipts = sum(r["authenticated_receipts"] for r in reports)
    retransmits = sum(r["datagram_retransmissions"] for r in reports)
    handshakes_retried = sum(r["handshake_retransmissions"] for r in reports)
    faults_expected = (
        not plan.drop_handshake_responses or faults["dropped_handshake_responses"] == plan.drop_handshake_responses
    ) and (
        not plan.drop_first_receipt or faults["dropped_receipts"] >= 1
    ) and (
        not plan.drop_every_nth_receipt or faults["dropped_receipts"] >= unique_expected // plan.drop_every_nth_receipt
    ) and (
        not plan.duplicate_data_ingress or faults["duplicated_data_ingress"] >= unique_expected
    )
    accepted_once = responder.accepted_messages == unique_expected
    result_ok = (not failures and all(r["status"] == "PASS" for r in reports)
                 and receipts == unique_expected and accepted_once and faults_expected
                 and (not plan.drop_handshake_responses or handshakes_retried >= 1)
                 and (not faults["dropped_receipts"] or retransmits >= faults["dropped_receipts"]))
    return {
        "scenario": plan.label,
        "status": "PASS" if result_ok else "FAIL",
        "clients": clients,
        "requested_messages": unique_expected,
        "authenticated_receipts": receipts,
        "server_unique_messages": responder.accepted_messages,
        "server_duplicate_datagrams": responder.duplicate_datagrams,
        "server_handshakes": responder.accepted_handshakes,
        "server_duplicate_handshakes": responder.duplicate_handshakes,
        "handshake_retransmissions": handshakes_retried,
        "data_retransmissions": retransmits,
        "faults_injected": faults,
        "worker_errors": failures,
    }


def reliability_qualification(*, samples: int = 12, clients: int = 4,
                              timeout: float = 0.08, attempts: int = 4) -> dict[str, Any]:
    if not (1 <= samples <= 50 and 1 <= clients <= 8
            and 0.05 <= timeout <= 2.0 and 3 <= attempts <= 6):
        raise ValueError("invalid qualification limits; require samples 1-50, clients 1-8, timeout .05-2, attempts 3-6")
    scenarios = [
        _exercise(profile, samples=samples, clients=clients,
                  timeout=timeout, attempts=attempts)
        for profile in PROFILES
    ]
    return {
        "status": "PASS" if all(x["status"] == "PASS" for x in scenarios) else "FAIL",
        "release_version": RELEASE_VERSION,
        "scope": "deterministic IPv4 loopback fault injection only; NOT public Internet, production, or exact wire loss",
        "wire_version": "IN40 / 0.4.0-alpha (unchanged)",
        "scenarios": scenarios,
        "total_authenticated_receipts": sum(s["authenticated_receipts"] for s in scenarios),
        "total_requested_messages": sum(s["requested_messages"] for s in scenarios),
        "caution": "Unaudited synthetic-data prototype; deterministic response loss does not model the entire Internet",
    }
