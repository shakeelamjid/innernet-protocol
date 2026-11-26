"""Public network statistics for the website: prices, capacity, leaderboards.

Everything here is already public (the signed registry document and live presence records) or
an aggregate. Never per-provider earnings, wallet balances or IP addresses.
"""
from __future__ import annotations

import json
import time

from .. import irm_registry as reg
from . import presence, probe
from .offer import UNITS
from .store import Store

DAY = 86400
CACHE_SECONDS = 120


def _num(v) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def network_stats(store: Store, now: int | None = None) -> dict:
    now = int(time.time()) if now is None else now
    machines = []
    totals = {"machines": 0, "online": 0, "storage_gib": 0, "cpus": 0, "gpus": 0, "cpu_free": 0, "gpu_free": 0,
              "bandwidth_gib_month": 0, "regions": {}, "gpu_models": {}, "services": {s: 0 for s in sorted(reg.SERVICES)}}
    for p in store.providers("listed"):
        e = p["entry"]
        pid = p["id"]
        live = presence.live(store, pid, now) or {}
        rec_stats = ((live.get("record") or {}).get("payload") or {}).get("stats") or {}
        online = bool(live.get("online"))
        ratio, n = probe.uptime(store, pid, since=now - 7 * DAY)
        lim = e.get("limits", {})
        svc = e.get("services", [])
        storage = (lim.get("STO-1") or {}).get("max_storage_gib", 0)
        stored = rec_stats.get("stored_bytes", 0)
        cpus = (lim.get("CMP-1") or {}).get("max_cpus", 0)
        gpus = (lim.get("GPU-1") or {}).get("max_gpus", 0)
        bw = (lim.get("RLY-1") or lim.get("VPN-1") or {}).get("max_gib_per_month", 0)
        model = (e.get("hardware") or {}).get("gpu_model")
        totals["machines"] += 1
        totals["online"] += online
        totals["storage_gib"] += storage
        totals["cpus"] += cpus
        totals["gpus"] += gpus
        totals["bandwidth_gib_month"] += bw
        if online:
            totals["cpu_free"] += int(rec_stats.get("cpu_free", 0) or 0)
            totals["gpu_free"] += int(rec_stats.get("gpu_free", 0) or 0)
        totals["regions"][e.get("region", "unknown")] = totals["regions"].get(e.get("region", "unknown"), 0) + 1
        if model:
            totals["gpu_models"][model] = totals["gpu_models"].get(model, 0) + gpus
        for s in svc:
            totals["services"][s] = totals["services"].get(s, 0) + 1
        machines.append({
            "name": e.get("name"), "region": e.get("region"), "class": e.get("class", "unknown"), "services": svc,
            "prices": {s: (e.get("prices", {}).get(s) or {}).get("amount") for s in svc},
            "uptime_7d": None if ratio is None else round(ratio, 4), "checks_7d": n, "online": online,
            "hours_per_week": round(reg.available_minutes(e) / 60, 1),
            "storage_gib": storage, "storage_free_gib": max(0, round(storage - stored / 2**30, 1)) if storage else 0,
            "cpus": cpus, "cpu_free": int(rec_stats.get("cpu_free", 0) or 0) if online else 0,
            "gpus": gpus, "gpu_model": model, "gpu_free": int(rec_stats.get("gpu_free", 0) or 0) if online else 0,
            "listed_since": p.get("listed_at"),
        })
    # Leaderboards: reliable first (needs at least a day of checks), then cheapest per service.
    rated = [m for m in machines if m["uptime_7d"] is not None and m["checks_7d"] >= 24]
    reliable = sorted(rated, key=lambda m: (-m["uptime_7d"], -m["checks_7d"]))[:10]
    cheapest = {}
    for s in sorted(reg.SERVICES):
        offers = [m for m in machines if s in m["services"] and m["prices"].get(s)]
        cheapest[s] = sorted(offers, key=lambda m: (_num(m["prices"][s]), -(m["uptime_7d"] or 0)))[:5]
    by_net = {r["network"]: r for r in store.q("SELECT network, COUNT(*) AS n, COALESCE(SUM(amount), 0) AS total FROM payments "
                                              "WHERE ts>=? GROUP BY network", (now - 30 * DAY,))}
    main, test = by_net.get("eip155:8453"), by_net.get("eip155:84532")
    return {"generated_at": now, "totals": totals, "market": presence.market(store),
            "units": dict(UNITS),
            "leaders": {"reliable": reliable, "cheapest": cheapest},
            "machines": sorted(machines, key=lambda m: (not m["online"], -(m["uptime_7d"] or 0), m["name"] or "")),
            # Real and test USDC are never added together.
            "payments_30d": {"count": main["n"] if main else 0, "usdc": f"{(main['total'] if main else 0) / 1e6:.2f}",
                             "test_count": test["n"] if test else 0,
                             "test_usdc": f"{(test['total'] if test else 0) / 1e6:.2f}"}}


class StatsCache:
    def __init__(self, store: Store):
        self.store, self.at, self.value = store, 0, None

    def get(self) -> dict:
        now = time.time()
        if self.value is None or now - self.at > CACHE_SECONDS:
            self.value, self.at = network_stats(self.store), now
        return self.value


def as_json(stats: dict) -> str:
    return json.dumps(stats, separators=(",", ":"))
