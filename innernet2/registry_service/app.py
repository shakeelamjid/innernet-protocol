"""HTTP service: REG-1 registry API, provider dashboard and passkey login."""
from __future__ import annotations

import json
import logging
import secrets
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from webauthn import (generate_authentication_options, generate_registration_options, options_to_json,
                      verify_authentication_response, verify_registration_response)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement, UserVerificationRequirement)

from ..bulk_v080 import BulkError
from ..irm_registry import make_login_challenge, sign_registry, verify_descriptor, verify_login
from . import chain, probe
from .config import NETWORK_NAMES, Settings
from .store import Store, token_hash

log = logging.getLogger("innernet.registry")
STATIC = Path(__file__).with_name("static")
SESSION_TTL = 12 * 3600
ENROLL_TTL = 600
FLOW_TTL = 300
MAX_BODY = 64 << 10
DAY = 86400
HTML_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
            "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def load_registry_key(path: str, *, create: bool = True) -> Ed25519PrivateKey | None:
    """Load the registry signing key. On first start, create it (0600) inside the private data volume."""
    if not path:
        return None
    if create and not Path(path).exists():
        import os
        key = Ed25519PrivateKey.generate()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(key.private_bytes_raw().hex() + "\n")
        log.warning("created registry signing key %s", path)
    raw = Path(path).read_bytes()
    text = raw.strip()
    if text.startswith(b"-----BEGIN"):
        key = serialization.load_pem_private_key(raw, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise SystemExit("registry key must be Ed25519")
        return key
    if len(text) == 64:
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(text.decode()))
    if len(raw) == 32:
        return Ed25519PrivateKey.from_private_bytes(raw)
    raise SystemExit("registry key file: expected PEM, 64 hex characters or 32 raw bytes")


class RateLimit:
    def __init__(self):
        self._hits: dict[tuple[str, str], deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, bucket: str, ip: str, limit: int, window: int) -> None:
        now = time.monotonic()
        with self._lock:
            q = self._hits[(bucket, ip)]
            while q and q[0] <= now - window:
                q.popleft()
            if len(q) >= limit:
                raise HTTPException(429, "too many requests; try again later")
            q.append(now)


def pct(ratio: float | None) -> str:
    return "n/a" if ratio is None else f"{ratio * 100:.1f}%"


def create_app(settings: Settings, *, store: Store | None = None, rpc=chain.http_rpc,
               connect=probe.tcp_connect) -> FastAPI:
    store = store or Store(settings.db_path)
    registry_key = load_registry_key(settings.key_file)
    if registry_key is not None:
        log.info("registry public key (pin this in clients): %s",
                 registry_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())
    limiter = RateLimit()
    P = settings.prefix.rstrip("/")
    cookie_name = "__Host-innernet_registry" if settings.cookie_secure else "innernet_registry"
    stop = threading.Event()

    def worker(fn, interval):
        while not stop.wait(interval):
            try:
                fn()
            except Exception:  # keep the loop alive; errors are logged
                log.exception("background task failed")

    @asynccontextmanager
    async def lifespan(_app):
        threads = []
        if settings.workers:
            for fn, iv in ((lambda: probe.probe_once(store, connect), settings.probe_interval),
                           (lambda: chain.scan_once(store, settings, rpc), settings.chain_interval)):
                t = threading.Thread(target=worker, args=(fn, iv), daemon=True)
                t.start()
                threads.append(t)
        yield
        stop.set()

    app = FastAPI(title="INNERnet registry", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.store = store

    # Works whether or not the reverse proxy strips the /registry prefix.
    @app.middleware("http")
    async def add_prefix(request: Request, call_next):
        path = request.scope["path"]
        if P and path != P and not path.startswith(P + "/"):
            request.scope["path"] = P + path
            request.scope["raw_path"] = (P + path).encode()
        return await call_next(request)

    # ---- helpers -------------------------------------------------------
    def client_ip(request: Request) -> str:
        if settings.trust_proxy:
            fwd = request.headers.get("x-forwarded-for", "")
            if fwd:
                return fwd.split(",")[-1].strip()[:64]
        return request.client.host if request.client else "unknown"

    async def body_json(request: Request) -> dict:
        raw = await request.body()
        if len(raw) > MAX_BODY:
            raise HTTPException(413, "request too large")
        try:
            data = json.loads(raw)
        except ValueError:
            raise HTTPException(400, "body must be JSON") from None
        if not isinstance(data, dict):
            raise HTTPException(400, "body must be a JSON object")
        return data

    def guard(request: Request) -> None:
        """CSRF defence for browser APIs: custom header (forces CORS preflight) + same Origin."""
        if request.headers.get("x-innernet") != "1":
            raise HTTPException(403, "missing request header")
        origin = request.headers.get("origin")
        if origin and origin != settings.origin:
            raise HTTPException(403, "cross-origin request refused")

    def session(request: Request) -> dict | None:
        token = request.cookies.get(cookie_name)
        if not token:
            return None
        row = store.one("SELECT * FROM sessions WHERE token_hash=? AND revoked=0 AND expires_at>?",
                        (token_hash(token), int(time.time())))
        return dict(row) if row else None

    def need_session(request: Request) -> dict:
        s = session(request)
        if s is None:
            raise HTTPException(401, "log in first")
        return s

    def start_session(request: Request, pid: str, response: Response) -> None:
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        store.x("INSERT INTO sessions(token_hash, id, provider, created_at, expires_at, ip, user_agent) VALUES (?,?,?,?,?,?,?)",
                (token_hash(token), secrets.token_hex(8), pid, now, now + SESSION_TTL, client_ip(request),
                 request.headers.get("user-agent", "")[:200]))
        response.set_cookie(cookie_name, token, max_age=SESSION_TTL, path="/", secure=settings.cookie_secure,
                            httponly=True, samesite="strict")

    def health(pid: str) -> dict:
        now = int(time.time())
        out = {}
        for label, span in (("24h", DAY), ("7d", 7 * DAY), ("30d", 30 * DAY)):
            ratio, n = probe.uptime(store, pid, since=now - span)
            out[label] = {"uptime": pct(ratio), "probes": n}
        return out

    # ---- security headers ---------------------------------------------
    @app.middleware("http")
    async def headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        if response.headers.get("content-type", "").startswith("text/html"):
            response.headers["Content-Security-Policy"] = HTML_CSP
        if request.url.path.startswith((P + "/api", P + "/v1/login")):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(BulkError)
    async def bulk_error(_request, exc: BulkError):
        return JSONResponse({"detail": str(exc)}, status_code=422)

    # ---- REG-1 API (used by the CLI and clients) -------------------------
    @app.get(P + "/healthz")
    def healthz():
        return {"ok": True}

    @app.post(P + "/v1/apply")
    async def apply(request: Request):
        ip = client_ip(request)
        limiter.check("apply", ip, 20, 3600)
        record = await body_json(request)
        entry = verify_descriptor(record)
        pid = entry["id"]
        for network, address in entry["payto"].items():
            if network not in settings.fee_payto:
                raise HTTPException(422, f"payments on {network} are not accepted yet; use Base Sepolia (eip155:84532)")
            clash = [p for p in store.providers() if p["id"] != pid and p["state"] != "removed"
                     and str(p["entry"]["payto"].get(network, "")).lower() == address.lower()]
            if clash:
                raise HTTPException(422, "this payout contract is already used by another provider")
        notes = []
        for network, address in entry["payto"].items():
            ok, why = chain.payout_check(settings, network, address, rpc)
            if not ok:
                raise HTTPException(422, why)
            if why:
                notes.append(why)
        now = int(time.time())
        current = store.provider(pid)
        if current and current["state"] == "removed":
            raise HTTPException(403, "this provider was removed: " + current["reason"])
        same_route = current and (current["entry"]["endpoints"] == entry["endpoints"]
                                  and current["entry"]["payto"] == entry["payto"])
        if current and current["state"] == "listed" and same_route:
            state, reason = "listed", ""
        elif current and current["state"] == "suspended":
            state, reason = "suspended", current["reason"]
        else:
            state = "testing"
            reason = "checking reachability; listing follows review"
        if notes and state == "testing":
            reason += " (" + "; ".join(notes) + ")"
        with store.tx() as db:
            if current:
                db.execute("UPDATE providers SET record=?, state=?, reason=?, updated_at=? WHERE id=?",
                           (json.dumps(record), state, reason, now, pid))
            else:
                db.execute("INSERT INTO providers(id, record, state, reason, applied_at, updated_at) VALUES (?,?,?,?,?,?)",
                           (pid, json.dumps(record), state, reason, now, now))
        store.audit(pid, "applied" if not current else "updated", ", ".join(entry["services"]), ip)
        return {"provider": pid, "state": state, "reason": reason}

    def public_status(pid: str) -> dict:
        p = store.provider(pid)
        if p is None:
            raise HTTPException(404, "unknown provider")
        h = health(pid)
        e = chain.earnings(store, pid, settings.fee_bps, since=int(time.time()) - 30 * DAY)
        return {"provider": pid, "name": p["entry"]["name"], "state": p["state"], "reason": p["reason"],
                "checked_at": p["checked_at"] or 0,
                "health": {"uptime_7d": h["7d"]["uptime"], "challenge_pass_7d": "n/a"},
                "earnings": {"asset": "USDC", "gross_30d": chain.usdc(e["gross"]), "fee_30d": chain.usdc(e["fee"]),
                             "net_30d": chain.usdc(e["net"])}}

    @app.get(P + "/v1/providers/{pid}/status")
    def status(pid: str):
        return public_status(pid.lower())

    @app.get(P + "/v1/providers/{pid}")
    def public_provider(pid: str):
        p = store.provider(pid.lower())
        if p is None:
            raise HTTPException(404, "unknown provider")
        return {"entry": p["entry"], "state": p["state"], "listed_at": p["listed_at"],
                "networks": {n: NETWORK_NAMES.get(n, n) for n in p["entry"]["payto"]}}

    @app.get(P + "/v1/login/challenge")
    def login_challenge(request: Request, provider: str):
        limiter.check("challenge", client_ip(request), 30, 600)
        pid = provider.lower()
        if store.provider(pid) is None:
            raise HTTPException(404, "unknown provider; run innernet-provider apply first")
        ch = make_login_challenge()
        store.x("INSERT INTO login_challenges(challenge, provider, expires_at) VALUES (?,?,?)",
                (ch["challenge"], pid, ch["expires_at"]))
        store.x("DELETE FROM login_challenges WHERE expires_at<?", (int(time.time()) - 3600,))
        return ch

    @app.post(P + "/v1/login")
    async def login(request: Request):
        ip = client_ip(request)
        limiter.check("login", ip, 30, 600)
        record = await body_json(request)
        challenge = str(record.get("payload", {}).get("challenge", ""))
        row = store.one("SELECT * FROM login_challenges WHERE challenge=? AND used=0", (challenge,))
        if row is None:
            raise HTTPException(401, "unknown or used challenge")
        pid = verify_login(record, expected_challenge=challenge, registry_host=settings.login_host).hex()
        if pid != row["provider"]:
            raise HTTPException(401, "challenge was issued for another provider")
        if store.x("UPDATE login_challenges SET used=1 WHERE challenge=? AND used=0", (challenge,)) != 1:
            raise HTTPException(401, "challenge already used")
        token = secrets.token_urlsafe(32)
        store.x("INSERT INTO enroll_tokens(token_hash, provider, expires_at) VALUES (?,?,?)",
                (token_hash(token), pid, int(time.time()) + ENROLL_TTL))
        store.audit(pid, "cli-login", "one-time dashboard link issued", ip)
        # The token sits in the fragment so it never reaches server logs or Referer headers.
        return {"url": f"{settings.origin}{P}/enroll#t={token}", "expires_in": ENROLL_TTL}

    @app.get(P + "/v1/registry-key")
    def registry_public_key():
        if registry_key is None:
            raise HTTPException(503, "registry signing is not configured yet")
        return {"registry_key": registry_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()}

    cached_doc: dict = {}

    @app.get(P + "/v1/registry.json")
    def registry_document():
        if registry_key is None or not settings.fee_payto:
            raise HTTPException(503, "registry signing is not configured yet")
        now = int(time.time())
        if cached_doc.get("until", 0) > now:
            return cached_doc["doc"]
        providers = []
        for p in store.providers("listed"):
            if not set(p["entry"]["payto"]) <= set(settings.fee_payto):
                continue
            ratio, n = probe.uptime(store, p["id"], since=now - 7 * DAY)
            entry = dict(p["entry"], listed_at=p["listed_at"] or p["updated_at"])
            if ratio is not None:
                entry["reputation"] = {"uptime_7d": f"{ratio:.4f}", "probes_7d": str(n)}
            providers.append(entry)
        with store.tx():
            seq = max(int(store.meta("registry_sequence", "0")) + 1, now)
            store.set_meta("registry_sequence", str(seq))
        payload = {"version": "REG-1", "sequence": seq, "issued_at": now,
                   "expires_at": now + min(settings.document_ttl, 86_400), "fee_bps": settings.fee_bps,
                   "fee_payto": dict(settings.fee_payto), "providers": providers}
        doc = sign_registry(payload, registry_key, now=now)
        cached_doc.update(doc=doc, until=now + 300)
        return doc

    # ---- pages ---------------------------------------------------------
    def page(name: str) -> FileResponse:
        return FileResponse(STATIC / name, media_type="text/html", headers={"Cache-Control": "no-cache"})

    @app.get(P + "/dashboard")
    def dashboard_page():
        return page("dashboard.html")

    @app.get(P + "/enroll")
    def enroll_page():
        return page("enroll.html")

    @app.get(P + "/providers/{pid}")
    def provider_page(pid: str):
        return page("provider.html")

    @app.get(P + "/static/{name}")
    def static(name: str):
        path = (STATIC / name).resolve()
        if path.parent != STATIC.resolve() or not path.is_file() or path.suffix == ".html":
            raise HTTPException(404)
        types = {".css": "text/css", ".js": "text/javascript", ".woff2": "font/woff2", ".svg": "image/svg+xml"}
        return FileResponse(path, media_type=types.get(path.suffix, "application/octet-stream"),
                            headers={"Cache-Control": "public, max-age=3600"})

    # ---- passkeys (WebAuthn) ------------------------------------------
    def new_flow(kind: str, challenge: bytes, provider: str | None, token: str | None) -> str:
        flow = secrets.token_urlsafe(16)
        now = int(time.time())
        store.x("INSERT INTO webauthn_flows(id, kind, provider, challenge, token_hash, expires_at) VALUES (?,?,?,?,?,?)",
                (flow, kind, provider, challenge, token_hash(token) if token else None, now + FLOW_TTL))
        store.x("DELETE FROM webauthn_flows WHERE expires_at<?", (now,))
        return flow

    def take_flow(flow: str, kind: str) -> dict:
        row = store.one("SELECT * FROM webauthn_flows WHERE id=? AND kind=? AND expires_at>?",
                        (str(flow), kind, int(time.time())))
        if row is None:
            raise HTTPException(400, "this step expired; start again")
        store.x("DELETE FROM webauthn_flows WHERE id=?", (row["id"],))
        return dict(row)

    @app.post(P + "/api/enroll/options")
    async def enroll_options(request: Request):
        guard(request)
        limiter.check("webauthn", client_ip(request), 60, 600)
        data = await body_json(request)
        token = data.get("token")
        if token:
            row = store.one("SELECT * FROM enroll_tokens WHERE token_hash=? AND used=0 AND expires_at>?",
                            (token_hash(str(token)), int(time.time())))
            if row is None:
                raise HTTPException(401, "this link has expired or was used; run innernet-provider login again")
            pid = row["provider"]
        else:
            pid = need_session(request)["provider"]
            token = None
        p = store.provider(pid)
        existing = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["cred_id"]))
                    for r in store.q("SELECT cred_id FROM passkeys WHERE provider=?", (pid,))]
        options = generate_registration_options(
            rp_id=settings.rp_id, rp_name="INNERnet providers", user_id=bytes.fromhex(pid),
            user_name=p["entry"]["name"], user_display_name=f"{p['entry']['name']} ({pid[:8]})",
            exclude_credentials=existing,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED, user_verification=UserVerificationRequirement.PREFERRED))
        flow = new_flow("enroll", options.challenge, pid, token)
        return {"flow": flow, "options": json.loads(options_to_json(options)), "provider": pid,
                "name": p["entry"]["name"]}

    @app.post(P + "/api/enroll/verify")
    async def enroll_verify(request: Request):
        guard(request)
        ip = client_ip(request)
        limiter.check("webauthn", ip, 60, 600)
        data = await body_json(request)
        f = take_flow(data.get("flow", ""), "enroll")
        pid = f["provider"]
        if f["token_hash"] is None and (session(request) or {}).get("provider") != pid:
            raise HTTPException(401, "log in first")
        try:
            v = verify_registration_response(credential=data.get("credential"), expected_challenge=f["challenge"],
                                             expected_origin=settings.origin, expected_rp_id=settings.rp_id)
        except Exception as exc:
            raise HTTPException(400, f"passkey was not accepted: {exc}") from None
        name = str(data.get("name") or "Passkey").strip()[:40] or "Passkey"
        now = int(time.time())
        with store.tx() as db:
            if f["token_hash"]:
                cur = db.execute("UPDATE enroll_tokens SET used=1 WHERE token_hash=? AND used=0 AND expires_at>?",
                                 (f["token_hash"], now))
                if cur.rowcount != 1:
                    raise HTTPException(401, "this link has expired or was used")
            db.execute("INSERT INTO passkeys(cred_id, provider, public_key, sign_count, name, created_at) VALUES (?,?,?,?,?,?)",
                       (bytes_to_base64url(v.credential_id), pid, v.credential_public_key, v.sign_count, name, now))
        store.audit(pid, "passkey-added", name, ip)
        response = JSONResponse({"ok": True})
        if f["token_hash"]:
            start_session(request, pid, response)
        return response

    @app.post(P + "/api/login/options")
    async def passkey_login_options(request: Request):
        guard(request)
        limiter.check("webauthn", client_ip(request), 60, 600)
        options = generate_authentication_options(rp_id=settings.rp_id,
                                                  user_verification=UserVerificationRequirement.PREFERRED)
        return {"flow": new_flow("login", options.challenge, None, None),
                "options": json.loads(options_to_json(options))}

    @app.post(P + "/api/login/verify")
    async def passkey_login_verify(request: Request):
        guard(request)
        ip = client_ip(request)
        limiter.check("webauthn", ip, 60, 600)
        data = await body_json(request)
        f = take_flow(data.get("flow", ""), "login")
        cred = data.get("credential") or {}
        row = store.one("SELECT * FROM passkeys WHERE cred_id=?", (str(cred.get("rawId", cred.get("id", ""))),))
        if row is None:
            raise HTTPException(401, "this passkey is not registered here")
        try:
            v = verify_authentication_response(
                credential=cred, expected_challenge=f["challenge"], expected_rp_id=settings.rp_id,
                expected_origin=settings.origin, credential_public_key=row["public_key"],
                credential_current_sign_count=row["sign_count"])
        except Exception as exc:
            raise HTTPException(401, f"passkey was not accepted: {exc}") from None
        store.x("UPDATE passkeys SET sign_count=?, last_used=? WHERE cred_id=?",
                (v.new_sign_count, int(time.time()), row["cred_id"]))
        store.audit(row["provider"], "login", row["name"], ip)
        response = JSONResponse({"ok": True})
        start_session(request, row["provider"], response)
        return response

    @app.post(P + "/api/logout")
    def logout(request: Request):
        guard(request)
        s = session(request)
        if s:
            store.x("UPDATE sessions SET revoked=1 WHERE token_hash=?", (s["token_hash"],))
            store.audit(s["provider"], "logout", "", client_ip(request))
        response = JSONResponse({"ok": True})
        response.delete_cookie(cookie_name, path="/", secure=settings.cookie_secure, httponly=True, samesite="strict")
        return response

    # ---- dashboard data -------------------------------------------------
    @app.get(P + "/api/me")
    def me(request: Request):
        s = need_session(request)
        pid = s["provider"]
        p = store.provider(pid)
        now = int(time.time())
        e30 = chain.earnings(store, pid, settings.fee_bps, since=now - 30 * DAY)
        eall = chain.earnings(store, pid, settings.fee_bps, since=0)
        fmt = lambda e: {k: (chain.usdc(v) if k != "asset" else v) for k, v in e.items()}  # noqa: E731
        return {
            "provider": p["entry"], "state": p["state"], "reason": p["reason"], "applied_at": p["applied_at"],
            "listed_at": p["listed_at"], "checked_at": p["checked_at"], "fee_bps": settings.fee_bps,
            "networks": {n: NETWORK_NAMES.get(n, n) for n in p["entry"]["payto"]},
            "health": health(pid),
            "activity": {svc: "not reported yet" for svc in p["entry"]["services"]},
            "earnings": {"30d": fmt(e30), "all": fmt(eall)},
            "daily": chain.daily(store, pid, settings.fee_bps),
            "splits": chain.recent_splits(store, pid, settings.fee_bps),
            "passkeys": [{"id": r["cred_id"], "name": r["name"], "created_at": r["created_at"], "last_used": r["last_used"]}
                         for r in store.q("SELECT * FROM passkeys WHERE provider=? ORDER BY created_at", (pid,))],
            "sessions": [{"id": r["id"], "created_at": r["created_at"], "ip": r["ip"], "user_agent": r["user_agent"],
                          "current": r["token_hash"] == s["token_hash"]}
                         for r in store.q("SELECT * FROM sessions WHERE provider=? AND revoked=0 AND expires_at>? "
                                          "ORDER BY created_at DESC", (pid, now))],
            "audit": [dict(ts=r["ts"], event=r["event"], detail=r["detail"], ip=r["ip"])
                      for r in store.q("SELECT * FROM audit WHERE provider=? ORDER BY id DESC LIMIT 100", (pid,))],
        }

    @app.post(P + "/api/passkeys/{cred_id}/rename")
    async def rename_passkey(cred_id: str, request: Request):
        guard(request)
        s = need_session(request)
        name = str((await body_json(request)).get("name", "")).strip()[:40]
        if not name:
            raise HTTPException(400, "name is empty")
        if store.x("UPDATE passkeys SET name=? WHERE cred_id=? AND provider=?", (name, cred_id, s["provider"])) != 1:
            raise HTTPException(404, "no such passkey")
        store.audit(s["provider"], "passkey-renamed", name, client_ip(request))
        return {"ok": True}

    @app.post(P + "/api/passkeys/{cred_id}/delete")
    def delete_passkey(cred_id: str, request: Request):
        guard(request)
        s = need_session(request)
        count = store.one("SELECT COUNT(*) AS n FROM passkeys WHERE provider=?", (s["provider"],))["n"]
        if count <= 1:
            raise HTTPException(409, "this is your only passkey; add another one first")
        row = store.one("SELECT name FROM passkeys WHERE cred_id=? AND provider=?", (cred_id, s["provider"]))
        if row is None:
            raise HTTPException(404, "no such passkey")
        store.x("DELETE FROM passkeys WHERE cred_id=?", (cred_id,))
        store.audit(s["provider"], "passkey-removed", row["name"], client_ip(request))
        return {"ok": True}

    @app.post(P + "/api/sessions/{sid}/revoke")
    def revoke_session(sid: str, request: Request):
        guard(request)
        s = need_session(request)
        if store.x("UPDATE sessions SET revoked=1 WHERE id=? AND provider=?", (sid, s["provider"])) != 1:
            raise HTTPException(404, "no such session")
        store.audit(s["provider"], "session-revoked", sid, client_ip(request))
        return {"ok": True}

    return app
