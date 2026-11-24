"""Bounded multi-session IPv4 loopback soak qualification for v0.4.2.

Exercises repeated authenticated handshakes and synthetic in-memory responder
state reset between completed batches. Does NOT simulate roaming, sustained
internet packet loss, or mid-flight transparent reconnection.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import socket
import threading
import time
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .native_udp import (MAX_DATAGRAM, MAX_SESSIONS, NativeResponder, RELEASE_VERSION,
                         native_probe, pub_bytes)


def soak_qualification(*, cycles: int = 6, clients: int = 4,
                       messages_per_client: int = 20, payload_bytes: int = 256,
                       restart_at_cycle: int = 3, timeout: float = 0.1) -> dict[str, Any]:
    if not (1 <= cycles <= 20 and 1 <= clients <= 8 and
            1 <= messages_per_client <= 50 and 1 <= payload_bytes <= 1152 and
            0.05 <= timeout <= 1.0 and
            (restart_at_cycle == 0 or 1 < restart_at_cycle <= cycles)):
        raise ValueError("invalid bounded loopback soak limits")
    # Session table is intentionally capped. Refuse combinations that cannot
    # fit, rather than reporting protocol delivery loss due to our own test.
    first_segment = restart_at_cycle - 1 if restart_at_cycle else cycles
    last_segment = cycles - restart_at_cycle + 1 if restart_at_cycle else 0
    if max(first_segment, last_segment) * clients > MAX_SESSIONS:
        raise ValueError("bounded loopback soak limits exceed server session capacity")
    server_key = Ed25519PrivateKey.generate()
    client_keys = [Ed25519PrivateKey.generate() for _ in range(clients)]
    allowed = {pub_bytes(c) for c in client_keys}
    current = [NativeResponder(server_key, allowed)]
    all_responders = [current[0]]
    stop = threading.Event()
    errors: list[str] = []
    cycles_reports = []
    started = time.perf_counter()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_sock:
        server_sock.bind(("127.0.0.1", 0))
        server_sock.settimeout(0.05)
        port = server_sock.getsockname()[1]

        def worker() -> None:
            while not stop.is_set():
                try:
                    packet, source = server_sock.recvfrom(MAX_DATAGRAM + 1)
                except socket.timeout:
                    continue
                except OSError:
                    if not stop.is_set():
                        errors.append("receiver socket error")
                    break
                try:
                    reply = current[0].process(packet, source)
                    if reply is not None:
                        server_sock.sendto(reply, source)
                except (ValueError, OSError):
                    errors.append("receiver process failed")
                    stop.set()
                    break

        th = threading.Thread(target=worker, daemon=True)
        th.start()
        try:
            for cycle in range(1, cycles + 1):
                if cycle == restart_at_cycle:
                    # Reset in-memory server state while preserving its pinned identity.
                    # This is *not* a process or machine restart.
                    current[0] = NativeResponder(server_key, allowed)
                    all_responders.append(current[0])
                with ThreadPoolExecutor(max_workers=clients) as pool:
                    tasks = [pool.submit(native_probe, "127.0.0.1", port, key,
                                         pub_bytes(server_key), samples=messages_per_client,
                                         payload_bytes=payload_bytes, timeout=timeout,
                                         attempts=4) for key in client_keys]
                    results = [future.result() for future in tasks]
                cycles_reports.append({
                    "cycle": cycle,
                    "server_state_reset_before_cycle": cycle == restart_at_cycle,
                    "status": "PASS" if all(r["status"] == "PASS" for r in results) else "FAIL",
                    "requested_messages": clients * messages_per_client,
                    "authenticated_receipts": sum(r["authenticated_receipts"] for r in results),
                    "handshake_retransmissions": sum(r["handshake_retransmissions"] for r in results),
                    "data_retransmissions": sum(r["datagram_retransmissions"] for r in results),
                })
        finally:
            stop.set()
            th.join(timeout=3)
        if th.is_alive():
            errors.append("receiver worker would not stop")

    requested = cycles * clients * messages_per_client
    receipts = sum(r["authenticated_receipts"] for r in cycles_reports)
    accepted = sum(r.accepted_messages for r in all_responders)
    handshakes = sum(r.accepted_handshakes for r in all_responders)
    elapsed = time.perf_counter() - started
    passed = (not errors and len(cycles_reports) == cycles and receipts == requested
              and accepted == requested and handshakes == cycles * clients
              and all(c["status"] == "PASS" for c in cycles_reports))
    return {
        "status": "PASS" if passed else "FAIL",
        "release_version": RELEASE_VERSION,
        "wire_version": "IN40 / 0.4.0-alpha unchanged",
        "scope": "loopback IPv4 soak; synthetic-only; no production or public internet claim",
        "clients": clients,
        "cycles": cycles,
        "messages_per_client_per_cycle": messages_per_client,
        "payload_bytes": payload_bytes,
        "requested_messages": requested,
        "authenticated_receipts": receipts,
        "server_unique_messages": accepted,
        "authenticated_handshakes": handshakes,
        "in_memory_server_state_resets": 1 if restart_at_cycle else 0,
        "elapsed_seconds": round(elapsed, 3),
        "goodput_kib_s": round(receipts * payload_bytes / 1024 / elapsed, 3),
        "cycles_report": cycles_reports,
        "worker_errors": errors,
        "limitations": "Fresh client sessions per cycle; server state reset only between cycles; not failover or mid-message recovery",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="INNERnet 0.4.2 bounded loopback multi-session soak")
    parser.add_argument("--cycles", type=int, default=6)
    parser.add_argument("--clients", type=int, default=4)
    parser.add_argument("--messages", type=int, default=20)
    parser.add_argument("--bytes", type=int, default=256)
    parser.add_argument("--restart-at-cycle", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=0.1)
    args = parser.parse_args(argv)
    try:
        result = soak_qualification(cycles=args.cycles, clients=args.clients,
                                    messages_per_client=args.messages,
                                    payload_bytes=args.bytes,
                                    restart_at_cycle=args.restart_at_cycle,
                                    timeout=args.timeout)
    except (OSError, RuntimeError, ValueError) as exc:
        parser.exit(2, f"soak test refused: {type(exc).__name__}: {exc}\n")
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
