"""Super-admin web page for the registry operator.

The operator signs in with the username and password set in the registry's environment
(INNERNET_ADMIN_USER, INNERNET_ADMIN_PASSWORD; the password needs 16+ characters, otherwise password
sign-in is off), or with an admin passkey. A passkey can be added from the page once signed in, or
through a one-time link printed by `registry-admin login` (run inside the registry's container). Admin sessions are separate
from provider sessions; every action is written to the audit log.

What it can do: list every machine, approve (list), suspend, remove, or delete a machine with all its
records (which frees its payout contract for another machine), delete a provider passkey, log out a
machine's web sessions, and manage admin passkeys. Payout contracts live on-chain and cannot be
deleted; deleting the machine that uses one is what frees it.
"""
from __future__ import annotations

import hmac
import json
import os
import secrets
import time

from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse
from webauthn import (generate_authentication_options, generate_registration_options, options_to_json,
                      verify_authentication_response, verify_registration_response)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement, UserVerificationRequirement)

from .store import Store, token_hash

ADMIN_SESSION_TTL = 4 * 3600
LOGIN_LINK_TTL = 600
ADMIN_USER = b"innernet-registry-admin"

SCHEMA = """
CREATE TABLE IF NOT EXISTS admin_passkeys (
  cred_id TEXT PRIMARY KEY, public_key BLOB NOT NULL, sign_count INTEGER NOT NULL, name TEXT NOT NULL,
  created_at INTEGER NOT NULL, last_used INTEGER
);
CREATE TABLE IF NOT EXISTS admin_sessions (
  token_hash TEXT PRIMARY KEY, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, ip TEXT,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS admin_tokens (
  token_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0
);
"""

# Tables whose rows belong to one machine (deleted with it). Payments stay: they are history.
MACHINE_TABLES = ("probes", "passkeys", "sessions", "pairing", "claims", "presence", "presence_log",
                  "enroll_tokens", "login_challenges")


MIN_PASSWORD = 16


def password_login() -> tuple[str, str] | None:
    """(user, password) from the environment, or None when password sign-in is off."""
    user = os.environ.get("INNERNET_ADMIN_USER", "").strip()
    pw = os.environ.get("INNERNET_ADMIN_PASSWORD", "")
    if not user or len(pw) < MIN_PASSWORD:
        return None
    return user, pw


def migrate(store: Store) -> None:
    for stmt in SCHEMA.strip().split(";"):
        if stmt.strip():
            store.x(stmt)


def new_login_link(store: Store, origin: str, prefix: str) -> str:
    """One-time link (10 minutes) that adds an admin passkey. Printed by `registry-admin login`."""
    migrate(store)
    token = secrets.token_urlsafe(24)
    store.x("INSERT INTO admin_tokens(token_hash, expires_at) VALUES (?,?)",
            (token_hash(token), int(time.time()) + LOGIN_LINK_TTL))
    return f"{origin}{prefix}/admin#token={token}"


def register(app, *, store: Store, settings, P: str, guard, client_ip, body_json, new_flow, take_flow, limiter,
             cookie_secure: bool, page, payout_ok=lambda entry: (True, ""), rpc=None) -> None:
    migrate(store)
    cookie = "__Host-innernet_admin" if cookie_secure else "innernet_admin"

    def admin_session(request: Request) -> dict:
        token = request.cookies.get(cookie)
        row = store.one("SELECT * FROM admin_sessions WHERE token_hash=? AND revoked=0 AND expires_at>?",
                        (token_hash(token or ""), int(time.time()))) if token else None
        if row is None:
            raise HTTPException(401, "admin sign-in required")
        return dict(row)

    def start(request: Request, response: Response) -> None:
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        store.x("INSERT INTO admin_sessions(token_hash, created_at, expires_at, ip) VALUES (?,?,?,?)",
                (token_hash(token), now, now + ADMIN_SESSION_TTL, client_ip(request)))
        response.set_cookie(cookie, token, max_age=ADMIN_SESSION_TTL, path="/", secure=cookie_secure,
                            httponly=True, samesite="strict")

    def log(event: str, target: str, detail: str, request: Request) -> None:
        store.audit(target or "-", "admin-" + event, detail, client_ip(request))

    @app.get(P + "/admin")
    def admin_page():
        return page("admin.html")

    # ---- sign-in ---------------------------------------------------------
    @app.get(P + "/api/admin/config")
    def admin_config():
        return {"password": password_login() is not None,
                "passkey": store.one("SELECT 1 FROM admin_passkeys") is not None}

    @app.post(P + "/api/admin/login/password")
    async def login_password(request: Request):
        guard(request)
        ip = client_ip(request)
        limiter.check("admin-pw", ip, 8, 900)            # per address
        limiter.check("admin-pw", "*", 60, 3600)         # everyone together
        creds = password_login()
        if creds is None:
            raise HTTPException(404, "Password sign-in is off: set INNERNET_ADMIN_USER and INNERNET_ADMIN_PASSWORD "
                                     f"({MIN_PASSWORD}+ characters) on the registry.")
        data = await body_json(request)
        user_ok = hmac.compare_digest(str(data.get("user", "")).encode(), creds[0].encode())
        pw_ok = hmac.compare_digest(str(data.get("password", "")).encode(), creds[1].encode())
        if not (user_ok and pw_ok):
            log("login-failed", "-", "wrong username or password", request)
            raise HTTPException(401, "Wrong username or password.")
        log("login", "-", "password", request)
        response = JSONResponse({"ok": True})
        start(request, response)
        return response

    @app.post(P + "/api/admin/enroll/options")
    async def enroll_options(request: Request):
        guard(request)
        limiter.check("admin", client_ip(request), 30, 600)
        data = await body_json(request)
        token = str(data.get("token") or "")
        if token:
            row = store.one("SELECT * FROM admin_tokens WHERE token_hash=? AND used=0 AND expires_at>?",
                            (token_hash(token), int(time.time())))
            if row is None:
                raise HTTPException(401, "This admin link expired or was used. Run registry-admin login again.")
        else:
            admin_session(request)        # signed in: adding another admin passkey
        existing = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["cred_id"]))
                    for r in store.q("SELECT cred_id FROM admin_passkeys")]
        options = generate_registration_options(
            rp_id=settings.rp_id, rp_name="INNERNET registry admin", user_id=ADMIN_USER,
            user_name="registry-admin", user_display_name="INNERNET registry admin", exclude_credentials=existing,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED, user_verification=UserVerificationRequirement.REQUIRED))
        return {"flow": new_flow("admin-enroll", options.challenge, None, token or None),
                "options": json.loads(options_to_json(options))}

    @app.post(P + "/api/admin/enroll/verify")
    async def enroll_verify(request: Request):
        guard(request)
        ip = client_ip(request)
        limiter.check("admin", ip, 30, 600)
        data = await body_json(request)
        f = take_flow(data.get("flow", ""), "admin-enroll")
        if f["token_hash"] is None:
            admin_session(request)
        try:
            v = verify_registration_response(credential=data.get("credential"), expected_challenge=f["challenge"],
                                             expected_origin=settings.origin, expected_rp_id=settings.rp_id,
                                             require_user_verification=True)
        except Exception as exc:
            raise HTTPException(400, f"passkey was not accepted: {exc}") from None
        now = int(time.time())
        with store.tx() as db:
            if f["token_hash"]:
                cur = db.execute("UPDATE admin_tokens SET used=1 WHERE token_hash=? AND used=0 AND expires_at>?",
                                 (f["token_hash"], now))
                if cur.rowcount != 1:
                    raise HTTPException(401, "This admin link expired or was used.")
            name = str(data.get("name") or "Admin passkey").strip()[:40] or "Admin passkey"
            db.execute("INSERT INTO admin_passkeys(cred_id, public_key, sign_count, name, created_at) VALUES (?,?,?,?,?)",
                       (bytes_to_base64url(v.credential_id), v.credential_public_key, v.sign_count, name, now))
        log("passkey-added", "-", name, request)
        response = JSONResponse({"ok": True})
        start(request, response)
        return response

    @app.post(P + "/api/admin/login/options")
    async def login_options(request: Request):
        guard(request)
        limiter.check("admin", client_ip(request), 30, 600)
        rows = store.q("SELECT cred_id FROM admin_passkeys")
        if not rows:
            raise HTTPException(404, "No admin passkey yet. Run registry-admin login in the registry container.")
        options = generate_authentication_options(
            rp_id=settings.rp_id, user_verification=UserVerificationRequirement.REQUIRED,
            allow_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["cred_id"])) for r in rows])
        return {"flow": new_flow("admin-login", options.challenge, None, None),
                "options": json.loads(options_to_json(options))}

    @app.post(P + "/api/admin/login/verify")
    async def login_verify(request: Request):
        guard(request)
        ip = client_ip(request)
        limiter.check("admin", ip, 30, 600)
        data = await body_json(request)
        f = take_flow(data.get("flow", ""), "admin-login")
        cred = data.get("credential") or {}
        row = store.one("SELECT * FROM admin_passkeys WHERE cred_id=?", (str(cred.get("rawId", cred.get("id", ""))),))
        if row is None:
            raise HTTPException(401, "This is not an admin passkey.")
        try:
            v = verify_authentication_response(
                credential=cred, expected_challenge=f["challenge"], expected_rp_id=settings.rp_id,
                expected_origin=settings.origin, credential_public_key=row["public_key"],
                credential_current_sign_count=row["sign_count"], require_user_verification=True)
        except Exception as exc:
            raise HTTPException(401, f"passkey was not accepted: {exc}") from None
        store.x("UPDATE admin_passkeys SET sign_count=?, last_used=? WHERE cred_id=?",
                (v.new_sign_count, int(time.time()), row["cred_id"]))
        log("login", "-", row["name"], request)
        response = JSONResponse({"ok": True})
        start(request, response)
        return response

    @app.post(P + "/api/admin/logout")
    def logout(request: Request):
        guard(request)
        token = request.cookies.get(cookie) or ""
        store.x("UPDATE admin_sessions SET revoked=1 WHERE token_hash=?", (token_hash(token),))
        response = JSONResponse({"ok": True})
        response.delete_cookie(cookie, path="/", secure=cookie_secure, httponly=True, samesite="strict")
        return response

    # ---- overview and actions --------------------------------------------
    @app.get(P + "/api/admin/overview")
    def overview(request: Request):
        admin_session(request)
        now = int(time.time())
        machines = []
        for p in store.providers():
            pid = p["id"]
            e = p["entry"]
            machines.append({
                "id": pid, "name": e.get("name"), "region": e.get("region"), "state": p["state"], "reason": p["reason"],
                "services": e.get("services", []), "payto": e.get("payto", {}),
                "endpoints": e.get("endpoints", []), "applied_at": p["applied_at"], "listed_at": p["listed_at"],
                "last_seen": p.get("last_seen"),
                "passkeys": [{"id": r["cred_id"], "name": r["name"], "created_at": r["created_at"], "last_used": r["last_used"]}
                             for r in store.q("SELECT * FROM passkeys WHERE provider=? ORDER BY created_at", (pid,))],
                "sessions": store.one("SELECT COUNT(*) AS n FROM sessions WHERE provider=? AND revoked=0 AND expires_at>?",
                                      (pid, now))["n"],
            })
        # Machines that started setup but never applied (no listing yet).
        pending = [{"provider": r["provider"], "status": r["status"], "created_at": r["created_at"],
                    "name": (json.loads(r["detected"] or "{}") or {}).get("name")}
                   for r in store.q("SELECT * FROM claims WHERE provider NOT IN (SELECT id FROM providers) "
                                    "AND expires_at>? ORDER BY created_at DESC LIMIT 50", (now,))]
        admins = [{"id": r["cred_id"], "name": r["name"], "created_at": r["created_at"], "last_used": r["last_used"]}
                  for r in store.q("SELECT * FROM admin_passkeys ORDER BY created_at")]
        audit = [dict(ts=r["ts"], provider=r["provider"], event=r["event"], detail=r["detail"], ip=r["ip"])
                 for r in store.q("SELECT * FROM audit ORDER BY id DESC LIMIT 200")]
        return {"machines": machines, "pending": pending, "admins": admins, "audit": audit}

    # ---- at scale: summary, paged and filtered tables, details, bulk actions ----
    from . import owners as own, presence, probe as probe_mod

    def rows_all(now: int) -> list[dict]:
        out = []
        for p in store.providers():
            pid, e = p["id"], p["entry"]
            live = presence.live(store, pid, now) or {}
            ratio, n = probe_mod.uptime(store, pid, since=now - 7 * 86400)
            owner = own.owner_of(store, pid)
            out.append({"id": pid, "name": e.get("name") or "", "owner": owner, "state": p["state"],
                        "held": bool(p.get("admin_lock")), "reason": p["reason"], "online": bool(live.get("online")),
                        "path": ((live.get("record") or {}).get("payload") or {}).get("path"),
                        "services": e.get("services", []), "region": e.get("region") or "", "class": e.get("class") or "",
                        "uptime_7d": None if ratio is None else round(ratio, 4), "checks_7d": n,
                        "last_seen": p.get("last_seen"), "applied_at": p["applied_at"],
                        "payto": ", ".join(e.get("payto", {}).values())})
        return out

    @app.get(P + "/api/admin/summary")
    def summary(request: Request):
        admin_session(request)
        now = int(time.time())
        rows = rows_all(now)
        states: dict[str, int] = {}
        for r in rows:
            states[r["state"]] = states.get(r["state"], 0) + 1
        waiting = sorted([r for r in rows if r["state"] == "testing" and not r["held"]], key=lambda r: r["applied_at"])
        setups = store.one("SELECT COUNT(*) AS n FROM claims WHERE provider NOT IN (SELECT id FROM providers) AND expires_at>? "
                           "AND status NOT IN ('superseded','done')", (now,))["n"]
        return {"machines": len(rows), "online": sum(r["online"] for r in rows), "states": states,
                "owners": len({r["owner"] for r in rows}), "held": sum(r["held"] for r in rows),
                "waiting": waiting[:20], "waiting_total": len(waiting), "setups": setups,
                "auto_list_hours": presence.auto_list_after() / 3600}

    SORTS = {"name", "owner", "state", "online", "region", "uptime_7d", "last_seen", "applied_at"}

    @app.get(P + "/api/admin/machines")
    def machines_page(request: Request, q: str = "", state: str = "", online: str = "", owner: str = "", sort: str = "applied_at",
                      dir: str = "desc", page: int = 1, size: int = 50):
        admin_session(request)
        rows = rows_all(int(time.time()))
        ql = q.strip().lower()
        if ql:
            rows = [r for r in rows if ql in r["name"].lower() or r["id"].startswith(ql) or ql in r["owner"]
                    or ql in r["payto"].lower() or ql in r["region"].lower()]
        if state:
            rows = [r for r in rows if r["state"] == state or (state == "held" and r["held"])]
        if online in ("yes", "no"):
            rows = [r for r in rows if r["online"] == (online == "yes")]
        if owner:
            rows = [r for r in rows if r["owner"] == owner.lower()]
        key = sort if sort in SORTS else "applied_at"
        rows.sort(key=lambda r: (r[key] is None, r[key] if r[key] is not None else 0), reverse=dir == "desc")
        size = max(10, min(200, size))
        total = len(rows)
        page = max(1, page)
        return {"total": total, "page": page, "size": size, "rows": rows[(page - 1) * size: page * size]}

    @app.get(P + "/api/admin/machines/{pid}")
    def machine_detail(pid: str, request: Request):
        admin_session(request)
        p = machine(pid)
        now = int(time.time())
        owner = own.owner_of(store, p["id"])
        e = p["entry"]
        return {"id": p["id"], "name": e.get("name"), "state": p["state"], "held": bool(p.get("admin_lock")),
                "reason": p["reason"], "owner": owner, "owner_machines": own.machines_of(store, owner),
                "services": e.get("services", []), "prices": {k: v.get("amount") for k, v in e.get("prices", {}).items()},
                "limits": e.get("limits", {}), "endpoints": e.get("endpoints", []), "payto": e.get("payto", {}),
                "availability": e.get("availability"), "region": e.get("region"), "class": e.get("class"),
                "applied_at": p["applied_at"], "listed_at": p["listed_at"], "last_seen": p.get("last_seen"),
                "presence": presence.live(store, p["id"], now),
                "passkeys": [{"id": r["cred_id"], "name": r["name"], "created_at": r["created_at"], "last_used": r["last_used"]}
                             for r in store.q("SELECT * FROM passkeys WHERE provider=? ORDER BY created_at", (owner,))],
                "sessions": store.one("SELECT COUNT(*) AS n FROM sessions WHERE provider=? AND revoked=0 AND expires_at>?",
                                      (owner, now))["n"],
                "payout": [payout_status(network, address) for network, address in e.get("payto", {}).items()],
                "audit": [dict(ts=r["ts"], event=r["event"], detail=r["detail"], ip=r["ip"])
                          for r in store.q("SELECT * FROM audit WHERE provider=? ORDER BY id DESC LIMIT 40", (p["id"],))]}

    def payout_status(network: str, address: str) -> dict:
        """What the admin needs to see about one payout: valid contract, a wallet still waiting for its
        contract (the admin may create it and pay the gas), or a check that could not run."""
        from . import chain
        ok, why = payout_ok({"network": network, "payout": address})
        out = {"network": network, "address": address, "ok": ok and not why, "note": why, "wallet": False,
               "contract": None, "factory": settings.split_factory.get(network)}
        if rpc is not None and settings.rpc.get(network):
            try:
                out["wallet"] = chain.is_wallet_code(rpc(settings.rpc[network], "eth_getCode", [address, "latest"]))
                if out["wallet"]:
                    out["contract"] = chain.split_of(settings, network, address, rpc)
            except Exception as exc:  # the chain may be unreachable for a moment
                out["note"] = out["note"] or f"could not check on-chain: {exc}"
        return out

    @app.get(P + "/api/admin/owners")
    def owners_page(request: Request, q: str = "", page: int = 1, size: int = 50):
        admin_session(request)
        now = int(time.time())
        by: dict[str, dict] = {}
        for r in rows_all(now):
            o = by.setdefault(r["owner"], {"owner": r["owner"], "machines": 0, "online": 0, "states": {}, "payouts": set(),
                                           "names": []})
            o["machines"] += 1
            o["online"] += r["online"]
            o["states"][r["state"]] = o["states"].get(r["state"], 0) + 1
            if r["payto"]:
                o["payouts"].add(r["payto"])
            o["names"].append(r["name"])
        rows = []
        for o in by.values():
            o["payouts"] = sorted(o["payouts"])
            o["passkeys"] = store.one("SELECT COUNT(*) AS n FROM passkeys WHERE provider=?", (o["owner"],))["n"]
            o["sessions"] = store.one("SELECT COUNT(*) AS n FROM sessions WHERE provider=? AND revoked=0 AND expires_at>?",
                                      (o["owner"], now))["n"]
            rows.append(o)
        ql = q.strip().lower()
        if ql:
            rows = [o for o in rows if o["owner"].startswith(ql) or any(ql in n.lower() for n in o["names"])
                    or any(ql in x.lower() for x in o["payouts"])]
        rows.sort(key=lambda o: -o["machines"])
        page, size = max(1, page), max(10, min(200, size))
        return {"total": len(rows), "page": page, "size": size, "rows": rows[(page - 1) * size: page * size]}

    @app.get(P + "/api/admin/setups")
    def setups_page(request: Request):
        admin_session(request)
        now = int(time.time())
        return {"rows": [{"provider": r["provider"], "status": r["status"], "created_at": r["created_at"],
                          "name": (json.loads(r["detected"] or "{}") or {}).get("name"),
                          "os": (json.loads(r["detected"] or "{}") or {}).get("os")}
                         for r in store.q("SELECT * FROM claims WHERE provider NOT IN (SELECT id FROM providers) AND expires_at>? "
                                          "AND status NOT IN ('superseded','done') ORDER BY created_at DESC LIMIT 200", (now,))]}

    @app.get(P + "/api/admin/audit")
    def audit_page(request: Request, q: str = "", page: int = 1, size: int = 100):
        admin_session(request)
        page, size = max(1, page), max(20, min(500, size))
        like = f"%{q.strip()}%"
        where = "WHERE provider LIKE ? OR event LIKE ? OR detail LIKE ?" if q.strip() else ""
        args = (like, like, like) if q.strip() else ()
        total = store.one(f"SELECT COUNT(*) AS n FROM audit {where}", args)["n"]
        rows = [dict(ts=r["ts"], provider=r["provider"], event=r["event"], detail=r["detail"], ip=r["ip"])
                for r in store.q(f"SELECT * FROM audit {where} ORDER BY id DESC LIMIT ? OFFSET ?", (*args, size, (page - 1) * size))]
        return {"total": total, "page": page, "size": size, "rows": rows}

    @app.post(P + "/api/admin/bulk")
    async def bulk(request: Request):
        guard(request)
        admin_session(request)
        data = await body_json(request)
        ids = data.get("ids") or []
        if not isinstance(ids, list) or not 1 <= len(ids) <= 500:
            raise HTTPException(422, "ids: 1 to 500 machine ids")
        state, reason = str(data.get("state", "")), str(data.get("reason", "")).strip()[:200]
        done, failed = 0, []
        for pid in ids:
            try:
                set_machine_state(str(pid), state, reason, request)
                done += 1
            except HTTPException as exc:
                failed.append({"id": pid, "error": exc.detail})
        return {"done": done, "failed": failed}

    def machine(pid: str) -> dict:
        p = store.provider(str(pid).lower())
        if p is None:
            raise HTTPException(404, "unknown machine")
        return p

    @app.post(P + "/api/admin/machines/{pid}/state")
    async def set_state(pid: str, request: Request):
        guard(request)
        admin_session(request)
        data = await body_json(request)
        state = str(data.get("state", ""))
        reason = str(data.get("reason", "")).strip()[:200]
        return set_machine_state(pid, state, reason, request)

    def set_machine_state(pid: str, state: str, reason: str, request: Request) -> dict:
        """listed (approve; automation keeps watching), suspended or removed (held by the admin: automation
        leaves it alone), auto (give it back to automation)."""
        if state not in ("listed", "suspended", "removed", "auto"):
            raise HTTPException(422, "state: listed, suspended, removed or auto")
        if state in ("suspended", "removed") and not reason:
            raise HTTPException(422, "give a reason; the owner sees it")
        p = machine(pid)
        now = int(time.time())
        if state == "auto":
            new = "testing" if p["state"] in ("suspended", "removed") else p["state"]
            store.x("UPDATE providers SET admin_lock=0, state=?, reason=?, trial_since=CASE WHEN ?='testing' THEN ? "
                    "ELSE trial_since END, updated_at=? WHERE id=?",
                    (new, "" if new != "testing" else "checked again before listing", new, now, now, p["id"]))
            log("automatic", p["id"], f"{p['state']} -> {new}, automation resumed", request)
            return {"ok": True, "state": new}
        if state == "listed":
            # Listing is never possible without a valid payout contract, not even by hand.
            for network, address in p["entry"].get("payto", {}).items():
                ok, why = payout_ok({"network": network, "payout": address})
                if not ok:
                    raise HTTPException(422, f"Not listed: {why}")
                if "postponed" in why:
                    raise HTTPException(503, f"Not listed yet: {why}. Try again in a minute.")
        lock = 0 if state == "listed" else 1
        store.x("UPDATE providers SET state=?, reason=?, admin_lock=?, trial_since=NULL, listed_at=CASE WHEN ?='listed' "
                "THEN COALESCE(listed_at, ?) ELSE listed_at END, updated_at=? WHERE id=?",
                (state, reason, lock, state, now, now, p["id"]))
        log(state, p["id"], (reason or "by admin") + (" (held by admin)" if lock else ""), request)
        return {"ok": True, "state": state}

    @app.post(P + "/api/admin/machines/{pid}/check")
    async def ask_machine_check(pid: str, request: Request):
        """Ask one machine to check now: for a new release and/or its payout contract."""
        guard(request)
        admin_session(request)
        what = str((await body_json(request)).get("what") or "update,payout")
        p = machine(pid)
        own.ask_check(store, p["id"], what)
        log("check-now", p["id"], what, request)
        return {"ok": True}

    @app.post(P + "/api/admin/check-all")
    async def ask_all_check(request: Request):
        """Ask every machine that is not removed to check now."""
        guard(request)
        admin_session(request)
        what = str((await body_json(request)).get("what") or "update,payout")
        n = 0
        for p in store.providers():
            if p["state"] not in ("removed", "gone"):
                own.ask_check(store, p["id"], what)
                n += 1
        log("check-now", "", f"{what} on {n} machines", request)
        return {"ok": True, "machines": n}

    @app.post(P + "/api/admin/machines/{pid}/delete")
    async def delete_machine(pid: str, request: Request):
        """Delete a machine and everything that belongs to it. Its payout contract is free again."""
        guard(request)
        admin_session(request)
        data = await body_json(request)
        pid = str(pid).lower()
        if data.get("confirm") != pid[:8]:
            raise HTTPException(422, "type the first 8 characters of the machine id to confirm")
        exists = store.one("SELECT 1 FROM providers WHERE id=?", (pid,)) or store.one(
            "SELECT 1 FROM claims WHERE provider=?", (pid,))
        if not exists:
            raise HTTPException(404, "unknown machine")
        # This machine's id may also be its account's id: keep the account's passkeys and sign-ins while
        # other machines still belong to it.
        others = [r["provider"] for r in store.q("SELECT provider FROM machine_owner WHERE owner=? AND provider!=?", (pid, pid))]
        with store.tx() as db:
            db.execute("DELETE FROM providers WHERE id=?", (pid,))
            for t in MACHINE_TABLES + ("machine_owner", "key_backups"):
                if others and t in ("passkeys", "sessions"):
                    continue
                db.execute(f"DELETE FROM {t} WHERE provider=?", (pid,))
        log("deleted", pid, "machine and its records deleted; payments history kept"
            + (f"; its account keeps {len(others)} other machines" if others else ""), request)
        return {"ok": True}

    @app.post(P + "/api/admin/machines/{pid}/logout")
    def machine_logout(pid: str, request: Request):
        guard(request)
        admin_session(request)
        n = store.x("UPDATE sessions SET revoked=1 WHERE provider=? AND revoked=0", (str(pid).lower(),))
        log("sessions-revoked", str(pid).lower(), f"{n} web sessions", request)
        return {"ok": True, "revoked": n}

    @app.post(P + "/api/admin/passkeys/{cred_id}/delete")
    def delete_passkey(cred_id: str, request: Request):
        guard(request)
        admin_session(request)
        row = store.one("SELECT * FROM passkeys WHERE cred_id=?", (cred_id,))
        if row is None:
            raise HTTPException(404, "unknown passkey")
        with store.tx() as db:
            db.execute("DELETE FROM passkeys WHERE cred_id=?", (cred_id,))
            db.execute("UPDATE sessions SET revoked=1 WHERE provider=?", (row["provider"],))
        log("passkey-deleted", row["provider"], row["name"], request)
        return {"ok": True}

    @app.post(P + "/api/admin/admins/{cred_id}/delete")
    def delete_admin(cred_id: str, request: Request):
        guard(request)
        admin_session(request)
        if store.one("SELECT COUNT(*) AS n FROM admin_passkeys")["n"] <= 1:
            raise HTTPException(409, "This is the last admin passkey; add another one first.")
        if store.x("DELETE FROM admin_passkeys WHERE cred_id=?", (cred_id,)) != 1:
            raise HTTPException(404, "unknown admin passkey")
        log("admin-passkey-deleted", "-", cred_id[:12], request)
        return {"ok": True}
