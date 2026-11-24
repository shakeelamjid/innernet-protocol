"""CPU benchmark only; no socket, operating-system VPN or network routing."""
from __future__ import annotations

import json
import secrets
import time
from datetime import datetime, timezone

from innernet2.live import LiveSession


def bench(number=1500, payload_bytes=512):
    out = {"benchmark": "INNERnet Live *cryptographic codec only*", "timestamp_utc": datetime.now(timezone.utc).isoformat(),
           "network_included": False, "vpn_tunnel_included": False, "packet_count_each_mode": number,
           "payload_bytes": payload_bytes, "modes": []}
    for mixing in (False, True):
        secret, ident = secrets.token_bytes(32), secrets.token_bytes(16)
        a = LiveSession(secret, ident, "initiator", mixing)
        b = LiveSession(secret, ident, "responder", mixing)
        payload = secrets.token_bytes(payload_bytes)
        start = time.perf_counter()
        for _ in range(number):
            packet = a.encrypt_packet(payload)
            assert b.decrypt_packet(packet)[1] == payload
        seconds = time.perf_counter() - start
        out["modes"].append({"mixing": mixing, "total_seconds": round(seconds, 4),
                             "roundtrip_packets_per_second": round(number / seconds),
                             "wire_packet_bytes": len(packet),
                             "overhead_bytes": len(packet) - payload_bytes,
                             "authentication_tested": True})
    return out


if __name__ == "__main__":
    print(json.dumps(bench(), indent=2))
