"""Experimental authenticated immediate-delivery probe on 127.0.0.1 only.

This exercises INNERnet Live's pre-established AEAD packet format over real UDP
sockets. It does NOT provide key exchange, routing, internet transport, a VPN,
third-party delivery, or persistent durability. Never pass application secrets.
"""
from __future__ import annotations

import hashlib
import math
import secrets
import socket
import statistics
import threading
import time
from typing import Any

from .live import LiveSession, MAX_PAYLOAD


class ImmediateProbeError(RuntimeError):
    """A local delivery probe failed authenticated acknowledgment."""


def _nearest_rank(values: list[float], percentile: float) -> float:
    if not values or not 0 < percentile <= 1:
        raise ValueError("invalid percentile")
    return sorted(values)[math.ceil(percentile * len(values)) - 1]


def probe_local_immediate_delivery(*, samples: int = 9, payload_bytes: int = 256,
                                   timeout_seconds: float = 2.0) -> dict[str, Any]:
    """Send a random message, receive an authenticated echo receipt via UDP loopback.

    Keeps the session key solely in memory and never writes data to remote nodes.
    Measures user-mode loopback request/receipt time, not internet latency.
    """
    if type(samples) is not int or not 1 <= samples <= 25:
        raise ValueError("samples must be 1 through 25")
    if type(payload_bytes) is not int or not 1 <= payload_bytes <= MAX_PAYLOAD:
        raise ValueError(f"payload_bytes must be 1 through {MAX_PAYLOAD}")
    if not isinstance(timeout_seconds, (int, float)) or not 0.2 <= timeout_seconds <= 10:
        raise ValueError("invalid timeout")
    secret, session_id = secrets.token_bytes(32), secrets.token_bytes(16)
    initiator = LiveSession(secret, session_id, "initiator")
    responder = LiveSession(secret, session_id, "responder")
    issue = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("127.0.0.1", 0))
        server.settimeout(timeout_seconds)
        address = server.getsockname()

        def respond() -> None:
            try:
                for _ in range(samples):
                    packet, sender = server.recvfrom(4096)
                    path, message = responder.decrypt_packet(packet)
                    if path != 0 or len(message) != payload_bytes:
                        raise ImmediateProbeError("incorrect authenticated payload")
                    digest = hashlib.sha256(message).digest()
                    response = responder.encrypt_packet(digest)
                    server.sendto(response, sender)
            except (OSError, ValueError, ImmediateProbeError) as exc:
                issue.append(type(exc).__name__)

        worker = threading.Thread(target=respond, daemon=True, name="innernet-local-immediate-probe")
        worker.start()
        timings = []
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.bind(("127.0.0.1", 0))
                client.settimeout(timeout_seconds)
                for _ in range(samples):
                    message = secrets.token_bytes(payload_bytes)
                    started = time.perf_counter_ns()
                    client.sendto(initiator.encrypt_packet(message), address)
                    ack, peer = client.recvfrom(4096)
                    if peer != address:
                        raise ImmediateProbeError("unauthorized receipt origin")
                    path, plaintext = initiator.decrypt_packet(ack)
                    if path != 0 or plaintext != hashlib.sha256(message).digest():
                        raise ImmediateProbeError("receipt integrity mismatch")
                    timings.append((time.perf_counter_ns() - started) / 1_000_000)
        except (OSError, ValueError) as exc:
            raise ImmediateProbeError("local authenticated delivery failed") from exc
        finally:
            worker.join(timeout=timeout_seconds + 0.25)
        if worker.is_alive() or issue or len(timings) != samples:
            raise ImmediateProbeError("local responder did not finish cleanly")
    return {"tested": True, "scope": "loopback-only", "payload_bytes": payload_bytes,
            "samples": len(timings), "p50_ms": round(statistics.median(timings), 3),
            "p95_ms": round(_nearest_rank(timings, .95), 3),
            "max_ms": round(max(timings), 3), "authenticated_receipts": samples,
            "durability": "none",
            "caution": "Local UDP with a pre-established test secret; NOT Internet RTT, VPN, delivery guarantee, key exchange or storage."}
