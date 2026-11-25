"""Live presence, provider states and market prices (IRM-1 section 3.5, draft).

Presence: `innernet-provider serve` signs where it can be reached right now and a few
usage counters, about once a minute. The registry checks a new address by fetching the
provider's signed /sto/v1/info from it, keeps the latest record and gives it to clients
unchanged. Clients verify the signature, so the registry cannot invent an address.

States (providers.state):
  testing    applied or reinstated; checked before listing
  listed     in the signed registry document
  paused     by the provider: no new placements, keeps serving what it holds
  leaving    by the provider: clients move its shards away, then it stops
  suspended  by the registry: reachable less than 95% of its promised hours
  gone       nothing heard for 7 days
  removed    by the operator only
"""
from __future__ import annotations

import json
import time
import urllib.request
from statistics import median

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .. import irm_registry as reg
from .store import Store

ONLINE_WINDOW = 180          # seconds since the last presence record to count as online
GONE_AFTER = 7 * 86400
TRIAL = 86400                # a reinstated provider must pass checks this long
RESPONSE_DOMAIN = b"INNERnet/STO-1/response\x00"

SCHEMA = """
CREATE TABLE IF NOT EXISTS presence (
  provider TEXT PRIMARY KEY, record TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL, path TEXT NOT NULL,
  seq INTEGER NOT NULL, received_at INTEGER NOT NULL, verified_host TEXT, verified_port INTEGER, verified_at INTEGER
);
CREATE TABLE IF NOT EXISTS presence_log (
  provider TEXT NOT NULL, ts INTEGER NOT NULL, stats TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS presence_log_by_provider ON presence_log(provider, ts);
"""

PROVIDER_COLUMNS = {"resume_to": "TEXT", "trial_since": "INTEGER", "last_seen": "INTEGER"}


def migrate(store: Store) -> None:
    for stmt in SCHEMA.strip().split(";"):
        if stmt.strip():
            store.x(stmt)
    have = {r["name"] for r in store.q("PRAGMA table_info(providers)")}
    for col, kind in PROVIDER_COLUMNS.items():
        if col not in have:
            store.x(f"ALTER TABLE providers ADD COLUMN {col} {kind}")


def info_check(host: str, port: int, provider: str, timeout: float = 5.0) -> bool:
    """Fetch http://host:port/sto/v1/info and check it is signed by `provider` and fresh."""
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/sto/v1/info", timeout=timeout) as r:
            body = r.read(64 * 1024)
            sig = bytes.fromhex(r.headers.get("X-Innernet-Signature", ""))
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(provider)).verify(sig, RESPONSE_DOMAIN + body)
        info = json.loads(body)
        return info.get("provider") == provider and abs(int(info.get("time", 0)) - time.time()) < 300
    except (OSError, ValueError, InvalidSignature):
        return False


def record_presence(store: Store, record: dict, source_ip: str, check=info_check, now: int | None = None) -> dict:
    now = int(time.time()) if now is None else now
    p = reg.verify_presence(record, now=now)
    pid = p["provider"]
    prov = store.provider(pid)
    if prov is None:
        raise reg.BulkError("unknown provider: apply first")
    if prov["state"] == "removed":
        raise reg.BulkError("provider was removed by the operator")
    ep = p["endpoint"]
    if p["path"] != "relay" and ep["host"] != source_ip:
        raise reg.BulkError(f"presence says {ep['host']} but it came from {source_ip}")
    last = store.one("SELECT * FROM presence WHERE provider=?", (pid,))
    if last and p["seq"] <= last["seq"]:
        raise reg.BulkError("presence sequence went backwards")
    verified = last and last["verified_host"] == ep["host"] and last["verified_port"] == ep["port"] \
        and now - (last["verified_at"] or 0) < 3600
    v_host, v_port, v_at = (last["verified_host"], last["verified_port"], last["verified_at"]) if last else (None, None, None)
    if not verified:
        if check(ep["host"], ep["port"], pid):
            v_host, v_port, v_at, verified = ep["host"], ep["port"], now, True
    with store.tx() as db:
        db.execute("INSERT INTO presence(provider, record, host, port, path, seq, received_at, verified_host, verified_port, "
                   "verified_at) VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(provider) DO UPDATE SET record=excluded.record, "
                   "host=excluded.host, port=excluded.port, path=excluded.path, seq=excluded.seq, "
                   "received_at=excluded.received_at, verified_host=excluded.verified_host, "
                   "verified_port=excluded.verified_port, verified_at=excluded.verified_at",
                   (pid, json.dumps(record), ep["host"], ep["port"], p["path"], p["seq"], now, v_host, v_port, v_at))
        db.execute("INSERT INTO presence_log(provider, ts, stats) VALUES (?,?,?)", (pid, now, json.dumps(p["stats"])))
        db.execute("UPDATE providers SET last_seen=? WHERE id=?", (now, pid))
        if prov["state"] == "gone":       # back after a long absence: start a trial
            db.execute("UPDATE providers SET state='testing', reason=?, trial_since=?, updated_at=? WHERE id=?",
                       ("back online: trial before listing again", now, now, pid))
    if last is None or (last["host"], last["port"]) != (ep["host"], ep["port"]):
        store.audit(pid, "address", f"{ep['host']}:{ep['port']} via {p['path']}" + ("" if verified else " (not reachable yet)"),
                    source_ip)
    store.x("DELETE FROM presence_log WHERE ts<?", (now - 31 * 86400,))
    return {"ok": True, "state": state_of(store, pid), "reachable": bool(verified)}


def live(store: Store, pid: str, now: int | None = None) -> dict | None:
    now = int(time.time()) if now is None else now
    row = store.one("SELECT * FROM presence WHERE provider=?", (pid,))
    if row is None:
        return None
    return {"record": json.loads(row["record"]), "received_at": row["received_at"],
            "online": now - row["received_at"] <= ONLINE_WINDOW,
            "reachable": row["verified_host"] == row["host"] and row["verified_port"] == row["port"]}


def state_of(store: Store, pid: str) -> str:
    row = store.one("SELECT state FROM providers WHERE id=?", (pid,))
    return row["state"] if row else "unknown"


# ---- intents ---------------------------------------------------------------------

def apply_intent(store: Store, pid: str, action: str, *, via: str, ip: str | None = None,
                 now: int | None = None) -> dict:
    now = int(time.time()) if now is None else now
    p = store.provider(pid)
    if p is None:
        raise reg.BulkError("unknown provider")
    state = p["state"]
    if state == "removed":
        raise reg.BulkError("removed by the operator; only the operator can reinstate it")
    new, resume_to, reason, trial = state, p.get("resume_to"), p["reason"], p.get("trial_since")
    if action == "pause":
        if state not in ("listed", "testing"):
            raise reg.BulkError(f"cannot pause while {state}")
        new, resume_to, reason = "paused", state, "paused by the provider: no new files, existing ones still served"
    elif action == "leave":
        if state not in ("listed", "testing", "paused", "suspended"):
            raise reg.BulkError(f"cannot leave while {state}")
        new, resume_to = "leaving", resume_to if state == "paused" else state
        reason = "leaving: clients move their files away, then this machine can stop"
    elif action == "resume":
        if state not in ("paused", "leaving"):
            raise reg.BulkError(f"nothing to resume while {state}")
        new, resume_to, reason = (resume_to or "testing"), None, ""
        if new == "suspended":
            new, trial, reason = "testing", now, "trial: needs 24 h of passing checks"
    elif action == "reinstate":
        if state not in ("suspended", "gone"):
            raise reg.BulkError(f"nothing to reinstate while {state}")
        new, trial, reason = "testing", now, "trial: needs 24 h of passing checks"
    else:
        raise reg.BulkError("unknown action")
    store.x("UPDATE providers SET state=?, resume_to=?, reason=?, trial_since=?, updated_at=? WHERE id=?",
            (new, resume_to, reason, trial, now, pid))
    store.audit(pid, action, f"{state} -> {new} ({via})", ip)
    return {"provider": pid, "state": new, "reason": reason}


# ---- states over time (called after each probe round) -----------------------------

def advance_states(store: Store, uptime, now: int | None = None) -> None:
    now = int(time.time()) if now is None else now
    for p in store.providers():
        seen = max(p.get("last_seen") or 0, p.get("checked_at") or 0, p["applied_at"])
        if p["state"] in ("listed", "suspended", "paused") and now - seen > GONE_AFTER:
            good = store.one("SELECT MAX(ts) AS t FROM probes WHERE provider=? AND ok=1", (p["id"],))["t"] or 0
            if now - max(good, p.get("last_seen") or 0) > GONE_AFTER:
                store.x("UPDATE providers SET state='gone', reason=?, updated_at=? WHERE id=?",
                        ("nothing heard for 7 days; reinstate when it is back", now, p["id"]))
                store.audit(p["id"], "gone", "nothing heard for 7 days")
                continue
        # A reinstated provider that was listed before is listed again after a clean trial.
        trial = p.get("trial_since")
        if p["state"] == "testing" and trial and p["listed_at"] and now - trial >= TRIAL:
            ratio, n = uptime(store, p["id"], since=trial)
            if n >= 12 and ratio is not None and ratio >= 0.95:
                store.x("UPDATE providers SET state='listed', reason='', trial_since=NULL, updated_at=? WHERE id=?",
                        (now, p["id"]))
                store.audit(p["id"], "listed", f"trial passed ({ratio:.0%})")


# ---- usage and market ---------------------------------------------------------------

def usage(store: Store, pid: str, now: int | None = None) -> dict:
    now = int(time.time()) if now is None else now
    rows = store.q("SELECT ts, stats FROM presence_log WHERE provider=? AND ts>=? ORDER BY ts", (pid, now - 30 * 86400))
    latest = json.loads(rows[-1]["stats"]) if rows else {}
    days: dict[int, dict] = {}
    for r in rows:                          # last record of each day carries that day's 24 h counters
        days[r["ts"] // 86400] = json.loads(r["stats"])
    return {"now": latest, "reported_at": rows[-1]["ts"] if rows else None,
            "daily": [{"day": d * 86400, **s} for d, s in sorted(days.items())],
            "note": "reported by your machine (signed); money and uptime are checked independently"}


def market(store: Store) -> dict:
    """Typical prices over listed providers, per service, overall and per machine class."""
    out: dict[str, dict] = {}
    entries = [p["entry"] for p in store.providers("listed")]
    for svc in sorted(reg.SERVICES):
        offers = [(e, float(e["prices"][svc]["amount"])) for e in entries if svc in e.get("prices", {})]
        if not offers:
            out[svc] = {"providers": 0}
            continue
        out[svc] = {"providers": len(offers), "unit": offers[0][0]["prices"][svc]["unit"], **_spread([v for _, v in offers])}
        by_class: dict[str, list[float]] = {}
        for e, v in offers:
            by_class.setdefault(e.get("class", "unknown"), []).append(v)
        out[svc]["by_class"] = {c: {"providers": len(v), **_spread(v)} for c, v in sorted(by_class.items())}
    return out


def _spread(values: list[float]) -> dict:
    v = sorted(values)
    q = lambda f: v[min(len(v) - 1, int(f * (len(v) - 1) + 0.5))]  # noqa: E731
    return {"median": f"{median(v):.6f}".rstrip("0").rstrip("."), "low": f"{q(0.25):.6f}".rstrip("0").rstrip("."),
            "high": f"{q(0.75):.6f}".rstrip("0").rstrip(".")}


def _size(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def activity(entry: dict, u: dict) -> dict:
    """One line per offered service for the dashboard."""
    s = u.get("now") or {}
    out = {}
    for svc in entry["services"]:
        if not s:
            out[svc] = "not reported yet: start the provider service"
        elif svc == "STO-1":
            limit = s.get("storage_limit_bytes") or 0
            share = f" of {_size(limit)}" if limit else ""
            out[svc] = (f"{_size(s.get('stored_bytes', 0))}{share} stored · {s.get('leases', 0)} leases · "
                        f"{s.get('requests_24h', 0)} requests and {s.get('challenges_24h', 0)} checks in 24 h")
        else:
            out[svc] = "not served yet by this version"
    return out
