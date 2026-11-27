"""Reachability probes (IRM-1 section 3.4).

The registry tries each machine about once a round and records whether it answered. The record is
information for clients (shown as the share of checks answered); it is never held against a machine:
no machine is suspended or removed for being offline. A machine can come and go as its owner likes.
"""
from __future__ import annotations

import logging
import socket
import time
from typing import Callable

from .. import irm_registry as reg
from . import presence
from .store import Store

log = logging.getLogger("innernet.registry.probe")
WEEK = 7 * 86400

Connect = Callable[[str, int, float], float]


def tcp_connect(host: str, port: int, timeout: float = 5.0) -> float:
    start = time.monotonic()
    with socket.create_connection((host, port), timeout=timeout):
        pass
    return (time.monotonic() - start) * 1000


def uptime(store: Store, pid: str, *, since: int) -> tuple[float | None, int]:
    row = store.one("SELECT COUNT(*) AS n, SUM(ok) AS good FROM probes WHERE provider=? AND ts>=?", (pid, since))
    n = row["n"] or 0
    return ((row["good"] or 0) / n if n else None), n


def probe_once(store: Store, connect: Connect = tcp_connect, now: int | None = None, attached=lambda pid: False,
               payout_ok=lambda entry: (True, "")) -> None:
    now = int(time.time()) if now is None else now
    for p in store.providers():
        if p["state"] not in ("testing", "listed", "suspended", "paused", "leaving"):
            continue
        if not reg.in_hours(p["entry"], now):
            continue                       # outside its promised hours: neither good nor bad
        endpoints = p["entry"]["endpoints"]
        live = store.one("SELECT path, record, verified_host, verified_port, verified_at FROM presence WHERE provider=?",
                         (p["id"],))
        if live and live["path"] in ("relay", "tunnel"):
            if live["path"] == "tunnel":
                ok = bool(attached(p["id"]))  # HTTPS tunnel: reachable while attached
            else:                             # ST81 relay: through the relay, end to end
                import json as _json
                rec = _json.loads(live["record"])["payload"]
                ok = presence.relay_check(rec["endpoint"]["host"], rec["endpoint"]["port"], rec["relay_key"], p["id"])
            store.x("INSERT INTO probes(provider, ts, ok, latency_ms) VALUES (?,?,?,?)", (p["id"], now, int(ok), 0 if ok else None))
            store.x("UPDATE providers SET checked_at=? WHERE id=?", (now, p["id"]))
            continue
        if live and live["verified_host"] and now - (live["verified_at"] or 0) < 3600:
            endpoints = [{"host": live["verified_host"], "port": live["verified_port"]}]   # moved: probe where it is
        ok, latency = True, 0.0
        for ep in endpoints:
            try:
                latency = max(latency, connect(ep["host"], ep["port"], 5.0))
            except OSError:
                ok = False
        store.x("INSERT INTO probes(provider, ts, ok, latency_ms) VALUES (?,?,?,?)",
                (p["id"], now, int(ok), int(latency) if ok else None))
        store.x("UPDATE providers SET checked_at=? WHERE id=?", (now, p["id"]))
    presence.advance_states(store, uptime, now, payout_ok)
    store.x("DELETE FROM probes WHERE ts<?", (now - 31 * 86400,))
