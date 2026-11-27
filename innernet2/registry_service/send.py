"""INNERNET Send (SEND-1, draft): hand one sealed file to one person, under rules the sender sets.

The sender's browser seals the file before anything leaves the device. The key that opens it is made
from three parts: a link secret (in the link's #fragment, which browsers never send to a server), a
PIN the sender tells the receiver by another channel, and a keeper share deposited here. This service
is the keeper: it holds the sealed bytes and the keeper share, and releases the share only while the
sender's rules allow it. It never sees the link secret or the PIN, so it cannot open a file.

Rules (set by the sender, enforced here):
  keep        how long the file lives (hard end)
  fade        half-life: the keeper share is destroyed at a random moment, so the chance the file can
              still be opened halves every half-life (and it always ends at the hard end)
  opens       how many times the share is released (1, 3, or any number until the end)
  forward     off: bound to the first device that opens it; on: anyone with link + PIN
  take back   the sender's device key can kill the file at any time
When a rule ends a file, the keeper share and the sealed bytes are deleted; link and PIN are then useless.

These rules control what the keeper releases. A person who has opened a file can keep what they saw.

Today the keeper and the storage are this registry (the free tier). The same rules move to several
independent keeper machines, and the sealed pieces to storage providers, without changing the client.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import random
import re
import secrets
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from fastapi import HTTPException, Request
from fastapi.responses import Response

PART = 4 << 20                 # plaintext bytes per part
TAG = 16                       # AES-GCM tag added to each part
SMALL = 4096                   # sealed preview / meta blobs
PIN_TRIES = 5
UPLOAD_WINDOW = 3600           # an upload that is not finished in this time is dropped
DOWNLOAD_WINDOW = 2 * 3600     # how long one release may fetch the sealed bytes
FRESH = 300                    # signed requests must be this recent (seconds)
KEEPS = (86400, 7 * 86400, 30 * 86400)
OPENS = (1, 3, 0)              # 0: any number until the end
HALF_LIFE = 86400
DOMAIN = "INNERNET/SEND-1"
ID = re.compile(r"^[0-9a-f]{32}$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS send_files (
  id TEXT PRIMARY KEY, state TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, die_at INTEGER NOT NULL, half_life INTEGER NOT NULL DEFAULT 0,
  size INTEGER NOT NULL, parts INTEGER NOT NULL, got INTEGER NOT NULL DEFAULT 0,
  max_opens INTEGER NOT NULL, opens INTEGER NOT NULL DEFAULT 0, forward INTEGER NOT NULL DEFAULT 0,
  auth_hash TEXT NOT NULL, pin_tag TEXT NOT NULL, pin_fails INTEGER NOT NULL DEFAULT 0,
  owner_pub TEXT NOT NULL, bound_pub TEXT, keeper_share TEXT, upload_hash TEXT,
  preview TEXT NOT NULL, meta TEXT NOT NULL, ip TEXT
);
CREATE TABLE IF NOT EXISTS send_tokens (token_hash TEXT PRIMARY KEY, file TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS send_events (id INTEGER PRIMARY KEY AUTOINCREMENT, file TEXT NOT NULL, ts INTEGER NOT NULL, event TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS send_events_file ON send_events(file)
"""


def migrate(store) -> None:
    for stmt in SCHEMA.strip().split(";"):
        if stmt.strip():
            store.x(stmt)


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(text, size: int | None = None, most: int | None = None) -> bytes:
    try:
        raw = base64.urlsafe_b64decode(str(text) + "=" * (-len(str(text)) % 4))
    except (ValueError, TypeError):
        raise HTTPException(422, "not base64url")
    if (size is not None and len(raw) != size) or (most is not None and len(raw) > most):
        raise HTTPException(422, "wrong length")
    return raw


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def signed_message(action: str, file_id: str, ts: int) -> bytes:
    return f"{DOMAIN}/{action}\n{file_id}\n{ts}".encode()


def verify(pub_b64: str, action: str, file_id: str, ts, sig_b64) -> bool:
    """An ECDSA P-256 / SHA-256 signature as browsers make it (raw r||s), over signed_message()."""
    try:
        ts = int(ts)
        if abs(time.time() - ts) > FRESH:
            return False
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), unb64u(pub_b64, 65))
        sig = unb64u(sig_b64, 64)
        der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        key.verify(der, signed_message(action, file_id, ts), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError, HTTPException):
        return False


def fade_moment(now: int, half_life: int, end: int, rng=random) -> int:
    """When a fading file's keeper share is destroyed: exponential, so that P(still alive after t) is
    0.5 ** (t / half_life), and never later than the hard end."""
    return min(end, now + int(rng.expovariate(math.log(2) / half_life)))


def limits() -> dict:
    def num(name: str, default: float) -> float:
        try:
            return max(0.0, float(os.environ.get(name, default)))
        except ValueError:
            return default
    return {"max_bytes": int(num("INNERNET_SEND_MAX_MB", 100) * (1 << 20)),
            "max_keep": int(num("INNERNET_SEND_MAX_DAYS", 7) * 86400),
            "total_bytes": int(num("INNERNET_SEND_TOTAL_GB", 10) * (1 << 30)),
            "per_ip_day": int(num("INNERNET_SEND_PER_IP_DAY", 30)),
            "on": os.environ.get("INNERNET_SEND", "1") == "1"}


def take_down(store, db_path: str, fid: str, reason: str) -> bool:
    """Operator: end a file for good (abuse report, legal request). Returns False if there is no such
    live file. The operator cannot read a file, only destroy it."""
    migrate(store)
    r = store.one("SELECT state FROM send_files WHERE id=?", (fid,))
    if r is None or r["state"] == "dead":
        return False
    store.x("UPDATE send_files SET state='dead', reason=?, keeper_share=NULL, upload_hash=NULL WHERE id=?",
            ("removed by the operator: " + reason[:200], fid))
    store.x("DELETE FROM send_tokens WHERE file=?", (fid,))
    store.x("INSERT INTO send_events(file, ts, event) VALUES (?,?,?)", (fid, int(time.time()), "ended: removed by the operator"))
    try:
        os.remove(os.path.join(os.path.dirname(db_path) or ".", "send", fid + ".bin"))
    except FileNotFoundError:
        pass
    return True


def register(app, *, store, settings, P: str, guard, client_ip, limiter, page) -> None:
    migrate(store)
    root = os.path.join(os.path.dirname(settings.db_path) or ".", "send")
    os.makedirs(root, mode=0o700, exist_ok=True)
    api = P + "/send/api"

    def path(fid: str) -> str:
        return os.path.join(root, fid + ".bin")

    def row(fid: str):
        if not ID.match(fid):
            raise HTTPException(404, "no such file")
        r = store.one("SELECT * FROM send_files WHERE id=?", (fid,))
        if r is None:
            raise HTTPException(404, "no such file")
        return dict(r)

    def event(fid: str, what: str, now: int | None = None) -> None:
        store.x("INSERT INTO send_events(file, ts, event) VALUES (?,?,?)", (fid, int(now or time.time()), what))

    def drop_bytes(fid: str) -> None:
        try:
            os.remove(path(fid))
        except FileNotFoundError:
            pass

    def kill(fid: str, reason: str, now: int | None = None) -> None:
        """End a file for good: the keeper share and the sealed bytes are deleted."""
        store.x("UPDATE send_files SET state='dead', reason=?, keeper_share=NULL, upload_hash=NULL WHERE id=? AND state!='dead'",
                (reason, fid))
        store.x("DELETE FROM send_tokens WHERE file=?", (fid,))
        drop_bytes(fid)
        event(fid, "ended: " + reason, now)

    def sweep(now: int | None = None) -> None:
        now = int(now or time.time())
        for r in store.q("SELECT id, state, expires_at, die_at, half_life, created_at FROM send_files WHERE state!='dead'"):
            if r["state"] == "uploading":
                if now - r["created_at"] > UPLOAD_WINDOW:
                    kill(r["id"], "upload not finished", now)
            elif r["state"] == "live" and now >= r["expires_at"]:
                kill(r["id"], "expired", now)
            elif r["state"] == "live" and now >= r["die_at"]:
                kill(r["id"], "faded", now)
            elif r["state"] == "spent":
                left = store.one("SELECT MAX(expires_at) AS t FROM send_tokens WHERE file=?", (r["id"],))["t"] or 0
                if now >= left or now >= r["expires_at"]:
                    kill(r["id"], "opened", now)
        store.x("DELETE FROM send_tokens WHERE expires_at<?", (now,))
        # Records of ended files are kept 30 days so the sender can still see what happened, then removed.
        old = [r["id"] for r in store.q("SELECT id FROM send_files WHERE state='dead' AND expires_at<?", (now - 30 * 86400,))]
        for fid in old:
            store.x("DELETE FROM send_events WHERE file=?", (fid,))
            store.x("DELETE FROM send_files WHERE id=?", (fid,))

    app.state.send_sweep, app.state.send_kill = sweep, kill

    def stored() -> int:
        return store.one("SELECT COALESCE(SUM(size),0) AS n FROM send_files WHERE state!='dead'")["n"]

    def rules(r: dict) -> dict:
        return {"expires_at": r["expires_at"], "fade": bool(r["half_life"]), "half_life": r["half_life"],
                "max_opens": r["max_opens"], "opens": r["opens"], "forward": bool(r["forward"])}

    async def body(request: Request, most: int = 16384) -> dict:
        raw = await request.body()
        if len(raw) > most:
            raise HTTPException(413, "request too large")
        try:
            data = json.loads(raw or b"{}")
        except ValueError:
            raise HTTPException(422, "not JSON")
        if not isinstance(data, dict):
            raise HTTPException(422, "not a JSON object")
        return data

    def check_on() -> dict:
        lim = limits()
        if not lim["on"]:
            raise HTTPException(503, "sending files is switched off on this registry")
        return lim

    def check_auth(r: dict, data: dict) -> None:
        """Whoever asks about a file must hold its link (the auth value is derived from the link secret)."""
        if not hmac.compare_digest(sha(unb64u(data.get("auth"), 32)), r["auth_hash"]):
            raise HTTPException(403, "this link does not match the file")

    # ---- pages ----------------------------------------------------------------------------------

    @app.get(P + "/send")
    def send_page():
        return page("send.html")

    @app.get(P + "/send/o/{fid}")
    def open_page(fid: str):
        return page("send-open.html")

    # ---- sender ---------------------------------------------------------------------------------

    @app.get(api + "/limits")
    def send_limits():
        lim = limits()
        return {"on": lim["on"], "max_bytes": lim["max_bytes"], "part": PART,
                "keeps": [k for k in KEEPS if k <= lim["max_keep"]], "opens": list(OPENS), "half_life": HALF_LIFE,
                "pin_tries": PIN_TRIES}

    @app.post(api + "/files")
    async def create(request: Request):
        guard(request)
        lim = check_on()
        ip = client_ip(request)
        limiter.check("send-create", ip, lim["per_ip_day"], 86400)
        d = await body(request)
        fid = str(d.get("id", ""))
        if not ID.match(fid):
            raise HTTPException(422, "id must be 32 hex characters")
        try:
            size, parts, keep, opens = int(d["size"]), int(d["parts"]), int(d["keep"]), int(d["max_opens"])
        except (KeyError, TypeError, ValueError):
            raise HTTPException(422, "size, parts, keep and max_opens are needed")
        plain = size - parts * TAG
        if parts < 1 or plain < 1 or parts != math.ceil(plain / PART):
            raise HTTPException(422, "size and parts do not fit together")
        if plain > lim["max_bytes"]:
            raise HTTPException(413, f"the largest file is {lim['max_bytes'] >> 20} MB")
        if keep not in KEEPS or keep > lim["max_keep"]:
            raise HTTPException(422, "that lifetime is not offered")
        if opens not in OPENS:
            raise HTTPException(422, "opens must be 1, 3 or 0 (any number)")
        if stored() + size > lim["total_bytes"]:
            raise HTTPException(507, "the free store is full right now; try again later")
        auth_hash, pin_tag = str(d.get("auth_hash", "")), str(d.get("pin_tag", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", auth_hash) or not re.fullmatch(r"[0-9a-f]{64}", pin_tag):
            raise HTTPException(422, "auth_hash and pin_tag must be 64 hex characters")
        owner = b64u(unb64u(d.get("owner_pub"), 65))
        share = b64u(unb64u(d.get("keeper_share"), 32))
        preview, meta = b64u(unb64u(d.get("preview"), most=SMALL)), b64u(unb64u(d.get("meta"), most=SMALL))
        now = int(time.time())
        fade = bool(d.get("fade"))
        end = now + keep
        die = fade_moment(now, HALF_LIFE, end) if fade else end
        upload = secrets.token_bytes(32)
        try:
            store.x("INSERT INTO send_files(id, state, created_at, expires_at, die_at, half_life, size, parts, max_opens, "
                    "forward, auth_hash, pin_tag, owner_pub, keeper_share, upload_hash, preview, meta, ip) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (fid, "uploading", now, end, die, HALF_LIFE if fade else 0, size, parts, opens,
                     int(bool(d.get("forward"))), auth_hash, pin_tag, owner, share, sha(upload), preview, meta, ip))
        except Exception:  # noqa: BLE001  (duplicate id)
            raise HTTPException(409, "that id is taken")
        open(path(fid), "wb").close()
        os.chmod(path(fid), 0o600)
        return {"id": fid, "upload": b64u(upload), "part": PART, "expires_at": end}

    @app.put(api + "/files/{fid}/parts/{n}")
    async def put_part(fid: str, n: int, request: Request):
        guard(request)
        r = row(fid)
        if r["state"] != "uploading" or not r["upload_hash"]:
            raise HTTPException(409, "this file is not being uploaded")
        if not hmac.compare_digest(sha(unb64u(request.headers.get("x-send-upload"), 32)), r["upload_hash"]):
            raise HTTPException(403, "wrong upload token")
        if n != r["got"]:
            raise HTTPException(409, f"part {r['got']} is next")
        want = PART + TAG if n < r["parts"] - 1 else r["size"] - (r["parts"] - 1) * (PART + TAG)
        data = await request.body()
        if len(data) != want:
            raise HTTPException(422, f"part {n} must be {want} bytes")
        with open(path(fid), "ab") as f:
            f.write(data)
        got = n + 1
        done = got == r["parts"]
        store.x("UPDATE send_files SET got=?, state=?, upload_hash=? WHERE id=?",
                (got, "live" if done else "uploading", None if done else r["upload_hash"], fid))
        if done:
            event(fid, "sent")
        return {"got": got, "live": done}

    def owner_call(fid: str, action: str, d: dict) -> dict:
        r = row(fid)
        if not verify(r["owner_pub"], action, fid, d.get("ts"), d.get("sig")):
            raise HTTPException(403, "only the sender's device can do this")
        return r

    @app.post(api + "/files/{fid}/status")
    async def status(fid: str, request: Request):
        guard(request)
        sweep()
        r = owner_call(fid, "status", await body(request))
        return {"id": fid, "state": r["state"], "reason": r["reason"], "created_at": r["created_at"], **rules(r),
                "bound": bool(r["bound_pub"]), "pin_fails": r["pin_fails"],
                "events": [{"ts": e["ts"], "event": e["event"]} for e in
                           store.q("SELECT ts, event FROM send_events WHERE file=? ORDER BY id", (fid,))]}

    @app.post(api + "/files/{fid}/revoke")
    async def revoke(fid: str, request: Request):
        guard(request)
        r = owner_call(fid, "revoke", await body(request))
        if r["state"] != "dead":
            kill(fid, "taken back by the sender")
        return {"id": fid, "state": "dead"}

    # ---- receiver -------------------------------------------------------------------------------

    @app.post(api + "/files/{fid}/info")
    async def info(fid: str, request: Request):
        guard(request)
        sweep()
        r = row(fid)
        check_auth(r, await body(request))
        if r["state"] in ("dead", "uploading"):
            return {"id": fid, "state": "dead" if r["state"] == "dead" else "uploading", "reason": r["reason"]}
        return {"id": fid, "state": r["state"], "size": r["size"], "parts": r["parts"], "part": PART, "preview": r["preview"],
                **rules(r), "bound": bool(r["bound_pub"]), "pin_tries_left": PIN_TRIES - r["pin_fails"]}

    @app.post(api + "/files/{fid}/open")
    async def open_file(fid: str, request: Request):
        """Release the keeper share once more, if the rules still allow it."""
        guard(request)
        sweep()
        r = row(fid)
        d = await body(request)
        check_auth(r, d)
        if r["state"] != "live" or not r["keeper_share"]:
            raise HTTPException(410, "this file can no longer be opened" + (f" ({r['reason']})" if r["reason"] else ""))
        limiter.check("send-open", client_ip(request), 60, 3600)
        device = b64u(unb64u(d.get("device_pub"), 65))
        if not verify(device, "open", fid, d.get("ts"), d.get("sig")):
            raise HTTPException(403, "this device could not prove its key")
        if not r["forward"] and r["bound_pub"] and not hmac.compare_digest(device, r["bound_pub"]):
            raise HTTPException(403, "this file was already opened on another device and cannot be passed on")
        proof = str(d.get("pin_proof", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", proof) or not hmac.compare_digest(proof, r["pin_tag"]):
            fails = r["pin_fails"] + 1
            store.x("UPDATE send_files SET pin_fails=? WHERE id=?", (fails, fid))
            if fails >= PIN_TRIES:
                kill(fid, "too many wrong PINs")
                raise HTTPException(410, "too many wrong PINs: the file has been destroyed")
            raise HTTPException(403, f"wrong PIN ({PIN_TRIES - fails} tries left)")
        now = int(time.time())
        opens = r["opens"] + 1
        last = bool(r["max_opens"]) and opens >= r["max_opens"]
        token = secrets.token_bytes(32)
        store.x("INSERT INTO send_tokens(token_hash, file, expires_at) VALUES (?,?,?)",
                (sha(token), fid, min(now + DOWNLOAD_WINDOW, r["expires_at"])))
        store.x("UPDATE send_files SET opens=?, pin_fails=0, bound_pub=COALESCE(bound_pub, ?), state=?, keeper_share=? WHERE id=?",
                (opens, None if r["forward"] else device, "spent" if last else "live", None if last else r["keeper_share"], fid))
        event(fid, "opened", now)
        return {"keeper_share": r["keeper_share"], "token": b64u(token), "meta": r["meta"], "size": r["size"],
                "parts": r["parts"], "part": PART, "opens": opens, "max_opens": r["max_opens"], "last": last}

    @app.get(api + "/files/{fid}/parts/{n}")
    def get_part(fid: str, n: int, request: Request):
        r = row(fid)
        token = request.headers.get("x-send-token", "")
        t = store.one("SELECT file, expires_at FROM send_tokens WHERE token_hash=?", (sha(unb64u(token, 32)),))
        if t is None or t["file"] != fid or t["expires_at"] < time.time() or r["state"] == "dead":
            raise HTTPException(403, "this download is no longer allowed")
        if not 0 <= n < r["parts"]:
            raise HTTPException(404, "no such part")
        try:
            with open(path(fid), "rb") as f:
                f.seek(n * (PART + TAG))
                data = f.read(PART + TAG)
        except FileNotFoundError:
            raise HTTPException(410, "the sealed bytes are gone")
        return Response(data, media_type="application/octet-stream", headers={"Cache-Control": "no-store"})
