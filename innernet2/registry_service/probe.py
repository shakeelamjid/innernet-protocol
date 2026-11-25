"""Reachability probes and automatic suspension (IRM-1 section 3.4, first stage).

Until the provider daemon ships, the probe is a plain TCP connect to each endpoint.
Storage challenges, relay tests and compute canaries are added with the daemon.
"""
from __future__ import annotations

import logging
import socket
import time
from typing import Callable

from .store import Store

log = logging.getLogger("innernet.registry.probe")
SUSPEND_BELOW = 0.95        # 7-day reachability (spec: unreachable > 5% of the time)
MIN_PROBES = 24             # do not judge on too little data
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


def probe_once(store: Store, connect: Connect = tcp_connect, now: int | None = None) -> None:
    now = int(time.time()) if now is None else now
    for p in store.providers():
        if p["state"] not in ("testing", "listed", "suspended"):
            continue
        ok, latency = True, 0.0
        for ep in p["entry"]["endpoints"]:
            try:
                latency = max(latency, connect(ep["host"], ep["port"], 5.0))
            except OSError:
                ok = False
        store.x("INSERT INTO probes(provider, ts, ok, latency_ms) VALUES (?,?,?,?)",
                (p["id"], now, int(ok), int(latency) if ok else None))
        store.x("UPDATE providers SET checked_at=? WHERE id=?", (now, p["id"]))
        if p["state"] == "listed":
            ratio, n = uptime(store, p["id"], since=now - WEEK)
            if n >= MIN_PROBES and ratio is not None and ratio < SUSPEND_BELOW:
                reason = f"reachable {ratio:.1%} of the time over 7 days (needs 95%)"
                store.x("UPDATE providers SET state='suspended', reason=?, updated_at=? WHERE id=?", (reason, now, p["id"]))
                store.audit(p["id"], "suspended", reason)
    store.x("DELETE FROM probes WHERE ts<?", (now - 31 * 86400,))
