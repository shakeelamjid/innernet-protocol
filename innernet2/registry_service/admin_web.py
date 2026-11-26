"""Super-admin web page for the registry operator.

The operator signs in with an admin passkey. The first passkey is added through a one-time link
printed by `registry-admin login` (run inside the registry's container). Admin sessions are separate
from provider sessions; every action is written to the audit log.

What it can do: list every machine, approve (list), suspend, remove, or delete a machine with all its
records (which frees its payout contract for another machine), delete a provider passkey, log out a
machine's web sessions, and manage admin passkeys. Payout contracts live on-chain and cannot be
deleted; deleting the machine that uses one is what frees it.
"""
from __future__ import annotations

import json
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
             cookie_secure: bool, page) -> None:
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
            rp_id=settings.rp_id, rp_name="INNERnet registry admin", user_id=ADMIN_USER,
            user_name="registry-admin", user_display_name="INNERnet registry admin", exclude_credentials=existing,
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
        if state not in ("listed", "suspended", "removed"):
            raise HTTPException(422, "state: listed, suspended or removed")
        if state != "listed" and not reason:
            raise HTTPException(422, "give a reason; the owner sees it")
        p = machine(pid)
        now = int(time.time())
        store.x("UPDATE providers SET state=?, reason=?, listed_at=CASE WHEN ?='listed' THEN COALESCE(listed_at, ?) "
                "ELSE listed_at END, updated_at=? WHERE id=?", (state, reason, state, now, now, p["id"]))
        log(state, p["id"], reason or "by admin", request)
        return {"ok": True}

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
        with store.tx() as db:
            db.execute("DELETE FROM providers WHERE id=?", (pid,))
            for t in MACHINE_TABLES:
                db.execute(f"DELETE FROM {t} WHERE provider=?", (pid,))
        log("deleted", pid, "machine and its records deleted; payments history kept", request)
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
