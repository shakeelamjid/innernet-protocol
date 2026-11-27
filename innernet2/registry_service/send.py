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

Two tiers. Free: one file up to 10 MB or one note, link and PIN, one opening on the first device, then
destroyed (or after 7 days unopened); no settings. Anything added to that (size, life, openings, passing
on, an opening date, a read receipt, a reply, taking it back) is priced, and the whole price is paid
before the upload, in USDC on Base, to the operator's public address. The amount carries a few random
last digits, so the payment is found on the chain by its amount alone; the service holds no wallet.
A file can be extended (paid the same way) before its end; otherwise it is destroyed at its end.
INNERNET_SEND_ALL_RULES=1 allows every rule without payment (tests).

Today the keeper and the storage are this registry. The same rules move to several independent keeper
machines, and the sealed pieces to storage providers, without changing the client.
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
from fastapi.responses import JSONResponse, Response

PART = 4 << 20                 # plaintext bytes per part
TAG = 16                       # AES-GCM tag added to each part
SMALL = 4096                   # sealed preview / meta blobs
PIN_TRIES = 5
UPLOAD_WINDOW = 3600           # an upload that is not finished in this time is dropped
DOWNLOAD_WINDOW = 2 * 3600     # how long one release may fetch the sealed bytes
FRESH = 300                    # signed requests must be this recent (seconds)
NOTE_BYTES = 16384             # a note (shown on screen, not downloaded) is at most this long
PAY_WINDOW = 1800              # a price is held this long, waiting for the payment
PAY_GRACE = 900
SCAN_BLOCKS = 1500             # how far back a payment is looked for (about 50 minutes on Base)
MB, DAY, USDC1 = 1 << 20, 86400, 1_000_000
PRICES = {"size_100mb": 50_000, "size_1gb": 250_000, "size_5gb": 1_000_000, "life_30d_100mb": 50_000,
          "opening": 10_000, "unlimited": 250_000, "forward": 50_000, "open_after": 50_000,
          "receipt": 30_000, "reply": 50_000, "control": 50_000}      # micro-USDC (6 decimals)
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
TX = re.compile(r"^0x[0-9a-f]{64}$")
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
CREATE INDEX IF NOT EXISTS send_events_file ON send_events(file);
CREATE TABLE IF NOT EXISTS send_payments (tx TEXT PRIMARY KEY, file TEXT NOT NULL, amount INTEGER NOT NULL, payer TEXT, ts INTEGER NOT NULL, what TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS send_totals (k TEXT PRIMARY KEY, n INTEGER NOT NULL)
"""
ADDED = {"kind": "TEXT NOT NULL DEFAULT 'file'", "open_after": "INTEGER NOT NULL DEFAULT 0", "receipt": "INTEGER NOT NULL DEFAULT 0",
         "reply_on": "INTEGER NOT NULL DEFAULT 0", "reply": "TEXT", "control": "INTEGER NOT NULL DEFAULT 0",
         "price": "INTEGER NOT NULL DEFAULT 0", "pay_by": "INTEGER NOT NULL DEFAULT 0", "paid_at": "INTEGER NOT NULL DEFAULT 0",
         "ext_price": "INTEGER NOT NULL DEFAULT 0", "ext_keep": "INTEGER NOT NULL DEFAULT 0", "ext_by": "INTEGER NOT NULL DEFAULT 0"}


def migrate(store) -> None:
    for stmt in SCHEMA.strip().split(";"):
        if stmt.strip():
            store.x(stmt)
    have = {r["name"] for r in store.q("PRAGMA table_info(send_files)")}
    for name, kind in ADDED.items():
        if name not in have:
            store.x(f"ALTER TABLE send_files ADD COLUMN {name} {kind}")
    if store.one("SELECT COUNT(*) AS n FROM send_totals")["n"] == 0:      # first run: count what is on record
        sent = store.one("SELECT COUNT(*) AS n, COALESCE(SUM(size),0) AS b FROM send_files WHERE state IN ('live','spent','dead') AND got=parts")
        for k, n in (("sent", sent["n"]), ("bytes", sent["b"]),
                     ("opened", store.one("SELECT COUNT(*) AS n FROM send_events WHERE event='opened'")["n"]),
                     ("destroyed", store.one("SELECT COUNT(*) AS n FROM send_files WHERE state='dead'")["n"]),
                     ("paid", 0), ("paid_micro", 0)):
            store.x("INSERT OR IGNORE INTO send_totals(k, n) VALUES (?,?)", (k, n))


def usdc(micro: int) -> str:
    return f"{micro // USDC1}.{micro % USDC1:06d}"


def price_lines(*, plain: int, keep: int, opens: int, forward: bool, open_after: int, receipt: bool, reply: bool,
                control: bool, free_bytes: int, free_keep: int) -> list[tuple[str, int]]:
    """What a send costs, line by line (micro-USDC). No lines: it is the free send."""
    lines = []
    if plain > free_bytes:
        tier = ("Up to 100 MB", "size_100mb") if plain <= 100 * MB else ("Up to 1 GB", "size_1gb") if plain <= 1024 * MB else ("Up to 5 GB", "size_5gb")
        lines.append((tier[0], PRICES[tier[1]]))
    if keep > free_keep:
        days = math.ceil(keep / DAY)
        lines.append((f"Kept {days} days", math.ceil(days / 30) * max(1, math.ceil(plain / (100 * MB))) * PRICES["life_30d_100mb"]))
    if opens == 0:
        lines.append(("Any number of openings", PRICES["unlimited"]))
    elif opens > 1:
        lines.append((f"{opens} openings", (opens - 1) * PRICES["opening"]))
    for on, label, key in ((forward, "May be passed on", "forward"), (open_after, "Opens after a date", "open_after"),
                           (receipt, "Read receipt with time", "receipt"), (reply, "One sealed reply", "reply"),
                           (control, "Take it back", "control")):
        if on:
            lines.append((label, PRICES[key]))
    return lines


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
    return {"max_bytes": int(num("INNERNET_SEND_MAX_MB", 10) * (1 << 20)),
            "paid_max_bytes": int(num("INNERNET_SEND_PAID_MAX_MB", 1024) * (1 << 20)),
            "paid_max_keep": int(num("INNERNET_SEND_PAID_MAX_DAYS", 365) * 86400),
            "all_rules": os.environ.get("INNERNET_SEND_ALL_RULES", "0") == "1",
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


def register(app, *, store, settings, P: str, guard, client_ip, limiter, page, rpc=None) -> None:
    migrate(store)
    from .config import CHAIN_IDS, EXPLORER_TX, NETWORK_NAMES, USDC
    network = os.environ.get("INNERNET_SEND_NETWORK", "eip155:8453")
    payto = os.environ.get("INNERNET_SEND_PAYTO", "") or settings.fee_payto.get(network, "")
    if network not in USDC or not ADDRESS.match(payto or "") or not settings.rpc.get(network) or rpc is None:
        payto = ""                                         # paid sends are off until a public receiving address is set

    def bump(k: str, n: int = 1) -> None:
        store.x("INSERT INTO send_totals(k, n) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET n=n+excluded.n", (k, n))

    def pay_info(amount: int, by: int) -> dict:
        return {"amount": usdc(amount), "micro": amount, "to": payto, "network": network, "network_name": NETWORK_NAMES[network],
                "chain_id": CHAIN_IDS[network], "usdc": USDC[network], "pay_by": by, "explorer": EXPLORER_TX[network]}

    def unique(total: int) -> int:
        """The price plus a few random last digits (under 0.001 USDC), so the payment is known by its amount."""
        while True:
            amount = total + 1 + secrets.randbelow(999)
            if store.one("SELECT 1 AS x FROM send_files WHERE state!='dead' AND (price=? OR ext_price=?)", (amount, amount)) is None:
                return amount

    def find_payment(amount: int, tx: str | None):
        """A confirmed USDC transfer of exactly this amount to the receiving address, not used before.
        Returns (tx, payer) or None."""
        url, token, to = settings.rpc[network], USDC[network].lower(), "0x" + "0" * 24 + payto[2:].lower()
        try:
            if tx:
                receipt = rpc(url, "eth_getTransactionReceipt", [tx])
                if not receipt:
                    return None
                if receipt.get("status") != "0x1":
                    raise HTTPException(422, "that transaction failed on the chain")
                logs = receipt.get("logs", [])
            else:
                head = int(rpc(url, "eth_blockNumber", []), 16)
                logs = rpc(url, "eth_getLogs", [{"address": USDC[network], "fromBlock": hex(max(0, head - SCAN_BLOCKS)),
                                                 "toBlock": hex(head), "topics": [TRANSFER_TOPIC, None, to]}])
        except HTTPException:
            raise
        except Exception:  # noqa: BLE001
            raise HTTPException(503, "could not read the chain just now; try again in a moment")
        for entry in logs:
            topics = entry.get("topics", [])
            if (entry.get("removed") or len(topics) < 3 or str(entry.get("address", token)).lower() != token
                    or topics[0] != TRANSFER_TOPIC or topics[2].lower() != to or int(entry["data"], 16) != amount):
                continue
            h = entry["transactionHash"].lower()
            if store.one("SELECT 1 AS x FROM send_payments WHERE tx=?", (h,)) is None:
                return h, "0x" + topics[1][-40:]
        return None
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
        was = store.one("SELECT state FROM send_files WHERE id=?", (fid,))
        if was is None or was["state"] == "dead":
            return
        store.x("UPDATE send_files SET state='dead', reason=?, keeper_share=NULL, upload_hash=NULL, ext_price=0 WHERE id=?",
                (reason, fid))
        store.x("DELETE FROM send_tokens WHERE file=?", (fid,))
        drop_bytes(fid)
        event(fid, "ended: " + reason, now)
        if was["state"] in ("live", "spent"):
            bump("destroyed")

    def sweep(now: int | None = None) -> None:
        now = int(now or time.time())
        for r in store.q("SELECT id, state, expires_at, die_at, half_life, created_at, price, pay_by, paid_at FROM send_files WHERE state!='dead'"):
            if r["state"] == "unpaid":
                if now > r["pay_by"] + PAY_GRACE:
                    kill(r["id"], "not paid", now)
            elif r["state"] == "uploading":
                if now - max(r["created_at"], r["paid_at"]) > UPLOAD_WINDOW * (6 if r["price"] else 1):
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
                "max_opens": r["max_opens"], "opens": r["opens"], "forward": bool(r["forward"]), "kind": r["kind"],
                "open_after": r["open_after"], "receipt": bool(r["receipt"]), "reply_on": bool(r["reply_on"]),
                "control": bool(r["control"])}

    def options(d: dict, lim: dict) -> dict:
        """The sender's choices, checked, with their price."""
        try:
            plain, keep, opens = int(d["plain"]), int(d.get("keep") or lim["max_keep"]), int(d.get("max_opens", 1))
            open_after = int(d.get("open_after") or 0)
        except (KeyError, TypeError, ValueError):
            raise HTTPException(422, "plain, keep, max_opens and open_after must be numbers")
        kind = str(d.get("kind", "file"))
        now = int(time.time())
        if kind not in ("file", "note"):
            raise HTTPException(422, "kind is file or note")
        if plain < 1:
            raise HTTPException(422, "there is nothing to send")
        if kind == "note" and plain > NOTE_BYTES:
            raise HTTPException(413, "that note is too long")
        if not 3600 <= keep <= max(lim["paid_max_keep"], lim["max_keep"]):
            raise HTTPException(422, f"a send is kept between 1 hour and {lim['paid_max_keep'] // DAY} days")
        if not 0 <= opens <= 1000:
            raise HTTPException(422, "openings: 1 to 1000, or 0 for any number")
        if open_after and not now < open_after < now + keep - 3600:
            raise HTTPException(422, "the opening date must be in the future and at least an hour before the end")
        o = {"plain": plain, "kind": kind, "keep": keep, "opens": opens, "forward": bool(d.get("forward")),
             "open_after": open_after, "receipt": bool(d.get("receipt")), "reply": bool(d.get("reply")),
             "control": bool(d.get("control")), "fade": bool(d.get("fade")) and lim["all_rules"]}
        o["lines"] = [] if lim["all_rules"] else price_lines(
            plain=plain, keep=keep, opens=opens, forward=o["forward"], open_after=open_after, receipt=o["receipt"],
            reply=o["reply"], control=o["control"], free_bytes=lim["max_bytes"], free_keep=lim["max_keep"])
        o["total"] = sum(n for _, n in o["lines"])
        most = lim["max_bytes"] if lim["all_rules"] else max(lim["max_bytes"], lim["paid_max_bytes"] if payto else 0)
        if plain > most:
            raise HTTPException(413, f"the largest file is {most >> 20} MB")
        if o["total"] and not payto:
            raise HTTPException(402, "paid options are not switched on on this registry yet; the free send is one file "
                                     "up to 10 MB or one note, opened once")
        return o

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
        return {"on": lim["on"], "max_bytes": lim["max_bytes"], "note_bytes": NOTE_BYTES, "part": PART, "free_keep": lim["max_keep"],
                "tier": "all" if lim["all_rules"] else "paid" if payto else "free", "pin_tries": PIN_TRIES,
                "paid": {"on": bool(payto) and not lim["all_rules"], "max_bytes": lim["paid_max_bytes"], "max_keep": lim["paid_max_keep"],
                         "to": payto, "network": NETWORK_NAMES.get(network, network), "prices": {k: usdc(v) for k, v in PRICES.items()}}}

    @app.get(api + "/stats")
    def send_stats():
        t = {r["k"]: r["n"] for r in store.q("SELECT k, n FROM send_totals")}
        live = store.one("SELECT COUNT(*) AS n FROM send_files WHERE state='live'")["n"]
        return JSONResponse({"sent": t.get("sent", 0), "opened": t.get("opened", 0), "destroyed": t.get("destroyed", 0),
                             "bytes": t.get("bytes", 0), "waiting": live, "paid": t.get("paid", 0),
                             "paid_usdc": usdc(t.get("paid_micro", 0))}, headers={"Cache-Control": "public, max-age=60"})

    @app.post(api + "/quote")
    async def quote(request: Request):
        guard(request)
        o = options(await body(request), check_on())
        return {"lines": [{"label": k, "usdc": usdc(n)} for k, n in o["lines"]], "micro": o["total"], "total": usdc(o["total"])}

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
            size, parts = int(d["size"]), int(d["parts"])
        except (KeyError, TypeError, ValueError):
            raise HTTPException(422, "size and parts are needed")
        plain = size - parts * TAG
        if parts < 1 or plain < 1 or parts != math.ceil(plain / PART):
            raise HTTPException(422, "size and parts do not fit together")
        o = options({**d, "plain": plain}, lim)
        keep, opens = o["keep"], o["opens"]
        if stored() + size > lim["total_bytes"]:
            raise HTTPException(507, "the store is full right now; try again later")
        auth_hash, pin_tag = str(d.get("auth_hash", "")), str(d.get("pin_tag", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", auth_hash) or not re.fullmatch(r"[0-9a-f]{64}", pin_tag):
            raise HTTPException(422, "auth_hash and pin_tag must be 64 hex characters")
        owner = b64u(unb64u(d.get("owner_pub"), 65))
        share = b64u(unb64u(d.get("keeper_share"), 32))
        preview, meta = b64u(unb64u(d.get("preview"), most=SMALL)), b64u(unb64u(d.get("meta"), most=SMALL))
        now = int(time.time())
        fade = o["fade"]
        end = now + keep
        price = unique(o["total"]) if o["total"] else 0
        die = fade_moment(now, HALF_LIFE, end) if fade else end
        upload = secrets.token_bytes(32)
        try:
            store.x("INSERT INTO send_files(id, state, created_at, expires_at, die_at, half_life, size, parts, max_opens, "
                    "forward, auth_hash, pin_tag, owner_pub, keeper_share, upload_hash, preview, meta, ip, kind, open_after, "
                    "receipt, reply_on, control, price, pay_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (fid, "unpaid" if price else "uploading", now, end, die, HALF_LIFE if fade else 0, size, parts, opens,
                     int(o["forward"]), auth_hash, pin_tag, owner, share, sha(upload), preview, meta, ip, o["kind"],
                     o["open_after"], int(o["receipt"]), int(o["reply"]), int(o["control"]), price, now + PAY_WINDOW if price else 0))
        except Exception:  # noqa: BLE001  (duplicate id)
            raise HTTPException(409, "that id is taken")
        open(path(fid), "wb").close()
        os.chmod(path(fid), 0o600)
        return {"id": fid, "upload": b64u(upload), "part": PART, "expires_at": end,
                "lines": [{"label": k, "usdc": usdc(n)} for k, n in o["lines"]],
                "pay": pay_info(price, now + PAY_WINDOW) if price else None}

    @app.put(api + "/files/{fid}/parts/{n}")
    async def put_part(fid: str, n: int, request: Request):
        guard(request)
        r = row(fid)
        if r["state"] == "unpaid":
            raise HTTPException(402, "this send is paid for before it is uploaded")
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
            bump("sent")
            bump("bytes", r["size"])
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
        timed = bool(r["receipt"]) or limits()["all_rules"]        # the time of an opening is the paid read receipt
        now = int(time.time())
        return {"id": fid, "state": r["state"], "reason": r["reason"], "created_at": r["created_at"], **rules(r),
                "bound": bool(r["bound_pub"]), "pin_fails": r["pin_fails"], "got": r["got"], "parts": r["parts"],
                "reply": r["reply"], "paid": usdc(r["price"]) if r["paid_at"] else None,
                "pay": pay_info(r["price"], r["pay_by"]) if r["state"] == "unpaid" else
                       pay_info(r["ext_price"], r["ext_by"]) if r["state"] == "live" and r["ext_price"] and now <= r["ext_by"] + PAY_GRACE else None,
                "extend_keep": r["ext_keep"] if r["ext_price"] else 0,
                "events": [{"ts": e["ts"] if timed or e["event"] != "opened" else 0, "event": e["event"]} for e in
                           store.q("SELECT ts, event FROM send_events WHERE file=? ORDER BY id", (fid,))]}

    @app.post(api + "/files/{fid}/pay")
    async def pay(fid: str, request: Request):
        """Look for the payment of this send (or of its extension) on the chain. Safe to call again and again."""
        guard(request)
        d = await body(request)
        r = owner_call(fid, "pay", d)
        now = int(time.time())
        if r["state"] == "unpaid":
            want, what = r["price"], "send"
        elif r["state"] == "live" and r["ext_price"]:
            want, what = r["ext_price"], "extend"
        elif r["state"] in ("uploading", "live", "spent"):
            return {"paid": True, "state": r["state"], "expires_at": r["expires_at"]}
        else:
            raise HTTPException(410, "this send has ended" + (f" ({r['reason']})" if r["reason"] else ""))
        if not payto:
            raise HTTPException(503, "payments are switched off on this registry")
        tx = str(d.get("tx") or "").lower()
        if tx and not TX.match(tx):
            raise HTTPException(422, "tx must be a transaction hash")
        limiter.check("send-pay", client_ip(request), 600, 3600)
        found = find_payment(want, tx or None)
        if found is None:
            return {"paid": False, "state": r["state"]}
        try:
            store.x("INSERT INTO send_payments(tx, file, amount, payer, ts, what) VALUES (?,?,?,?,?,?)", (found[0], fid, want, found[1], now, what))
        except Exception:  # noqa: BLE001  (another request recorded it first)
            return {"paid": False, "state": r["state"]}
        bump("paid")
        bump("paid_micro", want)
        if what == "send":
            store.x("UPDATE send_files SET state='uploading', paid_at=? WHERE id=?", (now, fid))
            event(fid, "paid " + usdc(want) + " USDC", now)
            return {"paid": True, "state": "uploading", "tx": found[0], "expires_at": r["expires_at"]}
        end = r["expires_at"] + r["ext_keep"]
        store.x("UPDATE send_files SET expires_at=?, die_at=die_at+?, ext_price=0, ext_keep=0 WHERE id=?", (end, r["ext_keep"], fid))
        event(fid, f"extended {r['ext_keep'] // DAY} days, paid {usdc(want)} USDC", now)
        return {"paid": True, "state": "live", "tx": found[0], "expires_at": end}

    @app.post(api + "/files/{fid}/extend")
    async def extend(fid: str, request: Request):
        """Before a send ends, its sender can buy more time. Unextended, it is destroyed at its end."""
        guard(request)
        d = await body(request)
        r = owner_call(fid, "extend", d)
        lim = limits()
        try:
            days = int(d["days"])
        except (KeyError, TypeError, ValueError):
            raise HTTPException(422, "days is needed")
        now = int(time.time())
        if r["state"] != "live":
            raise HTTPException(409, "only a send that is waiting to be opened can be extended")
        if days < 1 or r["expires_at"] + days * DAY > now + lim["paid_max_keep"]:
            raise HTTPException(422, f"a send can reach at most {lim['paid_max_keep'] // DAY} days from today")
        plain = r["size"] - r["parts"] * TAG
        total = math.ceil(days / 30) * max(1, math.ceil(plain / (100 * MB))) * PRICES["life_30d_100mb"]
        if lim["all_rules"]:
            store.x("UPDATE send_files SET expires_at=expires_at+?, die_at=die_at+? WHERE id=?", (days * DAY, days * DAY, fid))
            event(fid, f"extended {days} days", now)
            return {"paid": True, "expires_at": r["expires_at"] + days * DAY, "pay": None}
        if not payto:
            raise HTTPException(402, "paid options are not switched on on this registry yet")
        amount = unique(total)
        store.x("UPDATE send_files SET ext_price=?, ext_keep=?, ext_by=? WHERE id=?", (amount, days * DAY, now + PAY_WINDOW, fid))
        return {"paid": False, "pay": pay_info(amount, now + PAY_WINDOW), "days": days}

    @app.post(api + "/files/{fid}/revoke")
    async def revoke(fid: str, request: Request):
        guard(request)
        r = owner_call(fid, "revoke", await body(request))
        if not r["control"] and not limits()["all_rules"]:
            raise HTTPException(402, "taking it back is a paid option, chosen when sending")
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
        if r["state"] in ("dead", "uploading", "unpaid"):
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
        if r["open_after"] and time.time() < r["open_after"]:
            raise HTTPException(403, "this cannot be opened yet; the sender set a later opening time")
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
        bump("opened")
        return {"keeper_share": r["keeper_share"], "token": b64u(token), "meta": r["meta"], "size": r["size"],
                "kind": r["kind"], "reply_on": bool(r["reply_on"]) and r["reply"] is None,
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

    @app.post(api + "/files/{fid}/reply")
    async def reply(fid: str, request: Request):
        """One sealed message back to the sender, from someone who has just opened the send."""
        guard(request)
        r = row(fid)
        t = store.one("SELECT file, expires_at FROM send_tokens WHERE token_hash=?",
                      (sha(unb64u(request.headers.get("x-send-token", ""), 32)),))
        if t is None or t["file"] != fid or t["expires_at"] < time.time():
            raise HTTPException(403, "a reply is sent right after opening")
        if not r["reply_on"]:
            raise HTTPException(402, "the sender did not ask for a reply")
        if r["reply"] is not None:
            raise HTTPException(409, "a reply was already sent")
        sealed = b64u(unb64u((await body(request)).get("sealed"), most=SMALL))
        store.x("UPDATE send_files SET reply=? WHERE id=?", (sealed, fid))
        event(fid, "reply received")
        return {"ok": True}
