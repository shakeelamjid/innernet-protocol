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
TERMS = (7, 30, 90, 365)       # storage periods, days
SIZES = (10, 100, 1024)        # storage sizes, MB (the first is the free size)
# The storage plan: one price for a size and a period (USDC, 6 decimals). Renewing costs the plan price again.
PLAN = {(0, 7): 0, (0, 30): 500_000, (0, 90): 1_250_000, (0, 365): 4_000_000,
        (1, 7): 500_000, (1, 30): 1_500_000, (1, 90): 4_000_000, (1, 365): 12_000_000,
        (2, 7): 2_000_000, (2, 30): 5_000_000, (2, 90): 12_000_000, (2, 365): 40_000_000}
# Add-ons: paid once, kept for the life of the send.
PRICES = {"opening": 50_000, "unlimited": 500_000, "forward": 100_000, "open_after": 100_000, "open_until": 100_000,
          "receipt": 50_000, "reply": 100_000, "control": 0, "holder": 250_000, "checkin": 1_000_000,
          **{f"plan_{s}_{t}": v for (s, t), v in PLAN.items()}}
ROOM_WINDOW = 600              # split custody: the needed keys must all arrive within this time
RELEASE_DELAY = 86400          # a missed check-in can still be made good for this long, then the send is released
ROOM_HOLD = 120                # once enough keys are in, the sealed keys stay available this long for every place to fetch
ROOM_SEEN = 20                 # a location counts as present this long after it last asked
MORE = {"recipient": 50_000, "succession": 500_000, "approver": 250_000, "duress": 500_000, "recovery": 0,
        "view_only": 100_000, "view_timer": 100_000, "presence": 250_000, "card": 50_000, "summary": 50_000, "alarm": 100_000,
        "record": 100_000, "witness": 100_000, "origin": 500_000, "name": 250_000, "chain": 100_000, "qr": 100_000,
        "seat": 500_000, "version": 100_000, "device": 250_000}
PRICES.update(MORE)
LISTING_BPS = 500              # payment lock: the listing fee is 5% of what the lock can take in, paid upfront
CARDS = ("gift", "invite", "voucher", "letter")
FLAGS = (("view_only", "Shown on screen only"), ("presence", "Visible only while all are present"), ("record", "Signed record"),
         ("chain", "May be handed on, with a recorded chain"), ("qr", "Printed seal"), ("recovery", "Recovery code"),
         ("device", "Opens only on a device you approve"))
ADD_BYTES = PART + TAG + 64    # one contribution: at most one sealed part
SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{2,39}$")
DOMAIN_NAME = re.compile(r"^(?=.{4,120}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
GRACE = 3 * 86400              # a paid send whose time ended is locked this long (renewable), then destroyed
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
CREATE TABLE IF NOT EXISTS send_totals (k TEXT PRIMARY KEY, n INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS send_room (file TEXT NOT NULL, seat INTEGER NOT NULL, device TEXT NOT NULL, ct TEXT NOT NULL, added_at INTEGER NOT NULL, PRIMARY KEY (file, seat));
CREATE TABLE IF NOT EXISTS send_recipients (file TEXT NOT NULL, idx INTEGER NOT NULL, pin_tag TEXT NOT NULL, wrap TEXT NOT NULL, after INTEGER NOT NULL DEFAULT 0, until INTEGER NOT NULL DEFAULT 0, unless INTEGER, opened_at INTEGER NOT NULL DEFAULT 0, device TEXT, PRIMARY KEY (file, idx));
CREATE TABLE IF NOT EXISTS send_approvals (file TEXT NOT NULL, idx INTEGER NOT NULL, token_hash TEXT NOT NULL, approved_at INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (file, idx));
CREATE TABLE IF NOT EXISTS send_claims (file TEXT NOT NULL, device TEXT NOT NULL, name TEXT NOT NULL, code TEXT NOT NULL, at INTEGER NOT NULL, approved INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (file, device));
CREATE TABLE IF NOT EXISTS send_names (name TEXT PRIMARY KEY, file TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS send_adds (file TEXT NOT NULL, n INTEGER NOT NULL, device TEXT NOT NULL, size INTEGER NOT NULL, hash TEXT NOT NULL, first_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, changes INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (file, n));
CREATE TABLE IF NOT EXISTS send_access (file TEXT NOT NULL, device TEXT NOT NULL, amount INTEGER NOT NULL, tx TEXT NOT NULL, until INTEGER NOT NULL DEFAULT 0, at INTEGER NOT NULL, PRIMARY KEY (file, device, tx));
CREATE TABLE IF NOT EXISTS send_quotes (amount INTEGER PRIMARY KEY, file TEXT NOT NULL, device TEXT NOT NULL, pay_by INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS send_room_seen (file TEXT NOT NULL, device TEXT NOT NULL, seen_at INTEGER NOT NULL, PRIMARY KEY (file, device))
"""
ADDED = {"kind": "TEXT NOT NULL DEFAULT 'file'", "open_after": "INTEGER NOT NULL DEFAULT 0", "receipt": "INTEGER NOT NULL DEFAULT 0",
         "reply_on": "INTEGER NOT NULL DEFAULT 0", "reply": "TEXT", "control": "INTEGER NOT NULL DEFAULT 0",
         "price": "INTEGER NOT NULL DEFAULT 0", "pay_by": "INTEGER NOT NULL DEFAULT 0", "paid_at": "INTEGER NOT NULL DEFAULT 0",
         "open_until": "INTEGER NOT NULL DEFAULT 0", "holders": "INTEGER NOT NULL DEFAULT 0", "need": "INTEGER NOT NULL DEFAULT 0",
         "extras": "TEXT NOT NULL DEFAULT '{}'", "summary": "TEXT", "seal_hash": "TEXT", "recover_hash": "TEXT", "witness_hash": "TEXT",
         "approve_need": "INTEGER NOT NULL DEFAULT 0", "duress_tag": "TEXT", "decoy_share": "TEXT", "decoy_meta": "TEXT",
         "decoy_size": "INTEGER NOT NULL DEFAULT 0", "collect": "TEXT", "pay": "TEXT", "parent": "TEXT",
         "version": "INTEGER NOT NULL DEFAULT 1", "versions_left": "INTEGER NOT NULL DEFAULT 0", "origin_ok": "INTEGER NOT NULL DEFAULT 0",
         "next_share": "TEXT", "next_meta": "TEXT", "next_size": "INTEGER NOT NULL DEFAULT 0", "next_parts": "INTEGER NOT NULL DEFAULT 0",
         "next_got": "INTEGER NOT NULL DEFAULT 0", "next_upload": "TEXT",
         "paused": "INTEGER NOT NULL DEFAULT 0", "pack": "TEXT", "room_hash": "TEXT", "seat_hashes": "TEXT", "room_until": "INTEGER NOT NULL DEFAULT 0", "checkin_every": "INTEGER NOT NULL DEFAULT 0", "checkin_due": "INTEGER NOT NULL DEFAULT 0",
         "ext_price": "INTEGER NOT NULL DEFAULT 0", "ext_keep": "INTEGER NOT NULL DEFAULT 0", "ext_by": "INTEGER NOT NULL DEFAULT 0"}


def migrate(store) -> None:
    for stmt in SCHEMA.strip().split(";"):
        if stmt.strip():
            store.x(stmt)
    have = {r["name"] for r in store.q("PRAGMA table_info(send_files)")}
    for name, kind in ADDED.items():
        if name not in have:
            store.x(f"ALTER TABLE send_files ADD COLUMN {name} {kind}")
    if "kind" not in {r["name"] for r in store.q("PRAGMA table_info(send_tokens)")}:
        store.x("ALTER TABLE send_tokens ADD COLUMN kind TEXT NOT NULL DEFAULT 'real'")
    if store.one("SELECT COUNT(*) AS n FROM send_totals")["n"] == 0:      # first run: count what is on record
        sent = store.one("SELECT COUNT(*) AS n, COALESCE(SUM(size),0) AS b FROM send_files WHERE state IN ('live','spent','dead') AND got=parts")
        for k, n in (("sent", sent["n"]), ("bytes", sent["b"]),
                     ("opened", store.one("SELECT COUNT(*) AS n FROM send_events WHERE event='opened'")["n"]),
                     ("destroyed", store.one("SELECT COUNT(*) AS n FROM send_files WHERE state='dead'")["n"]),
                     ("paid", 0), ("paid_micro", 0)):
            store.x("INSERT OR IGNORE INTO send_totals(k, n) VALUES (?,?)", (k, n))


def usdc(micro: int) -> str:
    return f"{micro // USDC1}.{micro % USDC1:06d}"


def prices() -> dict:
    """The price list. The operator can change any price without a release: INNERNET_SEND_PRICES='{"term_30": "0.75"}'."""
    out = dict(PRICES)
    try:
        for k, v in json.loads(os.environ.get("INNERNET_SEND_PRICES") or "{}").items():
            if k in out:
                out[k] = max(0, round(float(v) * USDC1))
    except (ValueError, TypeError, AttributeError):
        pass
    return out


def size_row(plain: int, free_bytes: int) -> int:
    return 0 if plain <= free_bytes else 1 if plain <= SIZES[1] * MB else 2


def term_price(days: int, plain: int, P: dict, free_bytes: int) -> tuple[int, int]:
    """(period in days, price) of the shortest storage period that covers days, for this size."""
    pkg = next((t for t in TERMS if days <= t), TERMS[-1])
    return pkg, P[f"plan_{size_row(plain, free_bytes)}_{pkg}"]


def price_lines(*, plain: int, keep: int, opens: int, forward: bool, open_after: int, open_until: int, receipt: bool,
                reply: bool, control: bool, holders: int, checkin: int, free_bytes: int) -> list[tuple[str, int]]:
    """What a send costs, line by line (micro-USDC). No lines: it is the free send."""
    P, lines = prices(), []
    pkg, cost = term_price(math.ceil(keep / DAY), plain, P, free_bytes)
    if cost:
        lines.append((f"Storage plan: up to {('10 MB', '100 MB', '1 GB')[size_row(plain, free_bytes)]}, {pkg} days", cost))
    if opens == 0:
        lines.append(("Any number of openings", P["unlimited"]))
    elif opens > 1:
        lines.append((f"{opens} openings", (opens - 1) * P["opening"]))
    if holders:
        lines.append((f"A key each for {holders} people", holders * P["holder"]))
    for on, label, key in ((checkin, "Released if you stop checking in", "checkin"), (open_after, "Not before a date", "open_after"),
                           (open_until, "Not after a date", "open_until"), (forward and not holders, "More than one device", "forward"),
                           (receipt, "Read receipt with time", "receipt"), (reply, "One sealed reply", "reply"),
                           (control, "Take it back", "control")):
        if on and P[key]:
            lines.append((label, P[key]))
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


def micro(text) -> int:
    try:
        v = round(float(str(text)) * USDC1)
    except (TypeError, ValueError):
        raise HTTPException(422, "an amount must be a number of USDC")
    if not 10_000 <= v <= 100_000 * USDC1:
        raise HTTPException(422, "an amount is between 0.01 and 100000 USDC")
    return v


def register(app, *, store, settings, P: str, guard, client_ip, limiter, page, rpc=None, signer=None) -> None:
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
            if (store.one("SELECT 1 AS x FROM send_files WHERE state!='dead' AND (price=? OR ext_price=?)", (amount, amount)) is None
                    and store.one("SELECT 1 AS x FROM send_quotes WHERE amount=?", (amount,)) is None):
                return amount

    def find_payment(amount: int, tx: str | None, dest: str | None = None):
        """A confirmed USDC transfer of exactly this amount to the receiving address, not used before.
        Returns (tx, payer) or None."""
        url, token, to = settings.rpc[network], USDC[network].lower(), "0x" + "0" * 24 + (dest or payto)[2:].lower()
        try:
            receipt = rpc(url, "eth_getTransactionReceipt", [tx]) if tx else None
            if receipt:
                if receipt.get("status") != "0x1":
                    raise HTTPException(422, "that transaction failed on the chain")
                logs = receipt.get("logs", [])
            else:                                          # no hash, or one the chain does not know yet: look for the amount itself
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

    def side(fid: str, what: str) -> str:
        return os.path.join(root, f"{fid}.{what}.bin")

    def extras(r: dict) -> dict:
        try:
            return json.loads(r.get("extras") or "{}")
        except ValueError:
            return {}

    def sign_record(payload: dict) -> dict:
        """A statement by this registry, signed with its Ed25519 key, that anyone can check."""
        if signer is None:
            raise HTTPException(503, "this registry has no signing key")
        from cryptography.hazmat.primitives import serialization
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        key = signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        return {"record": payload, "alg": "Ed25519", "key": key, "sig": b64u(signer.sign(raw)),
                "how": "sig is Ed25519 over the record as JSON with sorted keys and no spaces"}

    def http_out(url: str, data: dict | None = None) -> str:
        """Fetch or post to an address the sender named. Only https, only public hosts, no redirects."""
        custom = getattr(app.state, "send_http", None)
        if custom is not None:
            return custom(url, data)
        import ipaddress
        import socket
        import urllib.parse
        import urllib.request
        u = urllib.parse.urlsplit(url)
        if u.scheme != "https" or not u.hostname:
            raise ValueError("https only")
        for info in socket.getaddrinfo(u.hostname, u.port or 443, proto=socket.IPPROTO_TCP):
            if not ipaddress.ip_address(info[4][0]).is_global:
                raise ValueError("not a public host")

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None,
                                     headers={"Content-Type": "application/json", "User-Agent": "innernet-send/1.0"})
        with urllib.request.build_opener(NoRedirect).open(req, timeout=6) as resp:  # noqa: S310
            return resp.read(65536).decode("utf-8", "replace")

    def alarm(fid: str, what: str, now: int | None = None) -> None:
        """Tell the people the sender named that something happened to this send. Never the content."""
        r = store.one("SELECT extras FROM send_files WHERE id=?", (fid,))
        e = extras(dict(r)) if r else {}
        note = {"send": fid, "event": what, "at": int(now or time.time()), "from": "INNERNET Send"}
        import threading

        def go():
            if e.get("alarm_url"):
                try:
                    http_out(e["alarm_url"], note)
                except Exception:  # noqa: BLE001
                    pass
            host = os.environ.get("INNERNET_SMTP_HOST")
            if e.get("alarm_email") and host:
                try:
                    import smtplib
                    from email.message import EmailMessage
                    m = EmailMessage()
                    m["Subject"], m["From"], m["To"] = f"INNERNET Send: {what}", os.environ.get("INNERNET_SMTP_FROM", "send@localhost"), ", ".join(e["alarm_email"])
                    m.set_content(f"A sealed send you were named on ({fid[:8]}...) reports: {what}.\nTime: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(note['at']))}\n")
                    with smtplib.SMTP(host, int(os.environ.get("INNERNET_SMTP_PORT", "587")), timeout=10) as smtp:
                        smtp.starttls()
                        if os.environ.get("INNERNET_SMTP_USER"):
                            smtp.login(os.environ["INNERNET_SMTP_USER"], os.environ.get("INNERNET_SMTP_PASSWORD", ""))
                        smtp.send_message(m)
                except Exception:  # noqa: BLE001
                    pass
        if e.get("alarm_url") or e.get("alarm_email"):
            if getattr(app.state, "send_http", None) is not None:
                go()
            else:
                threading.Thread(target=go, daemon=True).start()

    def more_check(d: dict, strict: bool) -> dict:
        """Everything beyond the basic rules: checked, priced, and prepared for storing."""
        Pm, lines, x, ex = prices(), [], {}, {}
        e = d.get("extras") if isinstance(d.get("extras"), dict) else {}
        for key, label in FLAGS:
            if e.get(key):
                ex[key] = 1
                if Pm[key]:
                    lines.append((label, Pm[key]))
        try:
            secs, versions = int(e.get("view_secs") or 0), int(e.get("versions") or 0)
        except (TypeError, ValueError):
            raise HTTPException(422, "view_secs and versions are numbers")
        if secs:
            if not 10 <= secs <= 86400:
                raise HTTPException(422, "the view timer is between 10 seconds and 1 day")
            ex["view_secs"] = secs
            lines.append(("Leaves the screen after a set time", Pm["view_timer"]))
        if versions:
            if not 1 <= versions <= 50:
                raise HTTPException(422, "1 to 50 new versions")
            x["versions"] = versions
            lines.append((f"{versions} new versions on the same link", versions * Pm["version"]))
        if e.get("card"):
            if e["card"] not in CARDS:
                raise HTTPException(422, "no such card")
            ex["card"] = e["card"]
            lines.append(("Card design", Pm["card"]))
        if e.get("pin_in_link"):
            ex["pin_in_link"] = 1
        url, mails = str(e.get("alarm_url") or "").strip(), e.get("alarm_email") or []
        if url or mails:
            if url and not (url.startswith("https://") and len(url) <= 300):
                raise HTTPException(422, "the alarm address must be an https:// address")
            if not isinstance(mails, list) or len(mails) > 5 or not all(isinstance(m, str) and re.fullmatch(r"[^@\s]{1,64}@[^@\s]{3,120}", m) for m in mails):
                raise HTTPException(422, "up to 5 email addresses for the alarm")
            if mails and not os.environ.get("INNERNET_SMTP_HOST"):
                raise HTTPException(422, "email alarms are not set up on this registry; use a webhook address or a witness link")
            if url:
                ex["alarm_url"] = url
            if mails:
                ex["alarm_email"] = mails
            lines.append(("Alarm when it is opened", Pm["alarm"]))
        if e.get("origin"):
            dom = str(e["origin"]).strip().lower()
            if not DOMAIN_NAME.match(dom):
                raise HTTPException(422, "the origin is a domain name, such as example.com")
            ex["origin"] = dom
            lines.append(("Signed origin", Pm["origin"]))
        if e.get("name"):
            name = str(e["name"]).strip().lower()
            if not SLUG.match(name):
                raise HTTPException(422, "a link name is 3 to 40 letters, digits or dashes")
            if store.one("SELECT 1 AS x FROM send_names WHERE name=?", (name,)) is not None:
                raise HTTPException(409, "that link name is taken")
            ex["name"] = name
            lines.append(("Your own link name", Pm["name"]))
        if d.get("summary"):
            x["summary"] = b64u(unb64u(d["summary"], most=2 * SMALL)) if strict else "1"
            lines.append(("Summary anyone with the link can read", Pm["summary"]))
        if d.get("witness_hash") or e.get("witness"):
            if strict and not HEX64.match(str(d.get("witness_hash", ""))):
                raise HTTPException(422, "witness_hash is needed")
            x["witness_hash"] = d.get("witness_hash")
            lines.append(("Witness link", Pm["witness"]))
        if d.get("recover_hash"):                          # the sender key: every send can have one
            if not HEX64.match(str(d["recover_hash"])):
                raise HTTPException(422, "recover_hash is not well formed")
            x["recover_hash"] = d["recover_hash"]
        rc = d.get("recipients")
        n = len(rc) if isinstance(rc, list) else int(rc or 0) if isinstance(rc, (int, str)) else 0
        if n:
            if not 1 <= n <= 20:
                raise HTTPException(422, "1 to 20 named recipients")
            lines.append((f"{n} named recipients, each with their own PIN", n * Pm["recipient"]))
            if d.get("succession"):
                lines.append(("Passes on if it is not claimed in time", Pm["succession"]))
            if strict:
                if not isinstance(rc, list):
                    raise HTTPException(422, "recipients must be a list")
                out = []
                for i, it in enumerate(rc):
                    try:
                        tag, wrap = str(it["pin_tag"]), b64u(unb64u(it["wrap"], most=96))
                        after, until = int(it.get("after") or 0), int(it.get("until") or 0)
                        unless = it.get("unless")
                        unless = None if unless is None else int(unless)
                    except (KeyError, TypeError, ValueError, AttributeError):
                        raise HTTPException(422, "each recipient needs pin_tag and wrap")
                    if not HEX64.match(tag) or (unless is not None and not 0 <= unless < n) or unless == i:
                        raise HTTPException(422, "a recipient is not well formed")
                    out.append((i, tag, wrap, after, until, unless))
                if len({t[1] for t in out}) != n:
                    raise HTTPException(422, "two recipients have the same PIN")
                x["recipients"] = out
        ap = d.get("approvers")
        if ap:
            hashes = ap.get("hashes") if isinstance(ap, dict) else None
            try:
                count, need = (len(hashes) if isinstance(hashes, list) else int(ap.get("count") or 0)), int(ap.get("need") or 0)
            except (TypeError, ValueError, AttributeError):
                raise HTTPException(422, "approvers need a count and how many must approve")
            if not (1 <= count <= 10 and 1 <= need <= count):
                raise HTTPException(422, "1 to 10 approvers, and at least 1 of them to approve")
            lines.append((f"{count} approvers ({need} must approve)", count * Pm["approver"]))
            if strict:
                if not isinstance(hashes, list) or not all(isinstance(h, str) and HEX64.match(h) for h in hashes):
                    raise HTTPException(422, "one token hash per approver")
                x["approvers"] = (need, hashes)
        du = d.get("duress")
        if du:
            lines.append(("Duress PIN with a decoy", Pm["duress"]))
            if strict:
                try:
                    x["duress"] = (str(du["pin_tag"]), b64u(unb64u(du["share"], 32)), b64u(unb64u(du["meta"], most=SMALL)), int(du["size"]))
                except (KeyError, TypeError, ValueError):
                    raise HTTPException(422, "duress needs pin_tag, share, meta and size")
                if not HEX64.match(x["duress"][0]) or not 17 <= x["duress"][3] <= PART + TAG:
                    raise HTTPException(422, "the decoy is at most one part")
        c = d.get("collect")
        if c:
            try:
                col = {"audience": "all" if c.get("audience") == "all" else "owner", "anon": bool(c.get("anon")),
                       "seats": int(c.get("seats") or 0), "reveal_count": int(c.get("reveal_count") or 0)}
            except (TypeError, ValueError, AttributeError):
                raise HTTPException(422, "collect needs seats")
            if not (1 <= col["seats"] <= 200 and 0 <= col["reveal_count"] <= col["seats"]):
                raise HTTPException(422, "1 to 200 people can add; the count that opens it cannot be more than that")
            if strict:
                if col["audience"] == "owner":
                    col["pub"] = b64u(unb64u(c.get("pub"), 65))
                col["form"] = b64u(unb64u(c.get("form") or "", most=2 * SMALL)) if c.get("form") else ""
            x["collect"] = col
            lines.append((f"{col['seats']} people can add to it", col["seats"] * Pm["seat"]))
        pl = d.get("pay")
        if pl:
            if not isinstance(pl, dict) or pl.get("mode") not in ("each", "crowd", "period"):
                raise HTTPException(422, "the payment lock is each, crowd or period")
            pay = {"mode": pl["mode"], "price": micro(pl.get("price")), "to": str(pl.get("to", ""))}
            if (strict or pay["to"]) and not ADDRESS.match(pay["to"]):
                raise HTTPException(422, "the payment lock needs your receiving address (0x and 40 characters)")
            try:
                pay["buyers"], pay["period"] = int(pl.get("buyers") or 1), int(pl.get("period_days") or 0) * DAY
            except (TypeError, ValueError):
                raise HTTPException(422, "buyers and period_days are numbers")
            if not 1 <= pay["buyers"] <= 1000:
                raise HTTPException(422, "1 to 1000 buyers")
            if pay["mode"] == "crowd":
                pay["target"] = micro(pl.get("target"))
                take = pay["target"]
            else:
                take = pay["price"] * pay["buyers"]
            if pay["mode"] == "period" and not DAY <= pay["period"] <= 365 * DAY:
                raise HTTPException(422, "a paid period is 1 to 365 days")
            x["pay"] = pay
            lines.append(("Payment lock, listing fee (5% of what it can take in)", max(100_000, take * LISTING_BPS // 10_000)))
        if d.get("parent"):
            x["parent"] = str(d["parent"])
            if strict:
                pr = store.one("SELECT extras, state FROM send_files WHERE id=?", (x["parent"],)) if ID.match(x["parent"]) else None
                t = store.one("SELECT file FROM send_tokens WHERE token_hash=? AND expires_at>?", (sha(unb64u(d.get("parent_token"), 32)), int(time.time())))
                if pr is None or t is None or t["file"] != x["parent"] or not extras(dict(pr)).get("chain"):
                    raise HTTPException(403, "this cannot be handed on")
                ex["chain"] = 1                             # the chain goes on, at no charge to the next hand
        x["extras"], x["lines"] = ex, lines
        return x


    def kill(fid: str, reason: str, now: int | None = None) -> None:
        """End a file for good: the keeper share and the sealed bytes are deleted."""
        was = store.one("SELECT state FROM send_files WHERE id=?", (fid,))
        if was is None or was["state"] == "dead":
            return
        store.x("UPDATE send_files SET state='dead', reason=?, keeper_share=NULL, upload_hash=NULL, ext_price=0 WHERE id=?",
                (reason, fid))
        store.x("DELETE FROM send_tokens WHERE file=?", (fid,))
        store.x("DELETE FROM send_room WHERE file=?", (fid,))
        store.x("DELETE FROM send_room_seen WHERE file=?", (fid,))
        drop_bytes(fid)
        for name in os.listdir(root):                      # decoy, contributions, a version being uploaded
            if name.startswith(fid + "."):
                try:
                    os.remove(os.path.join(root, name))
                except FileNotFoundError:
                    pass
        store.x("DELETE FROM send_names WHERE file=?", (fid,))
        store.x("DELETE FROM send_claims WHERE file=?", (fid,))
        store.x("DELETE FROM send_quotes WHERE file=?", (fid,))
        event(fid, "ended: " + reason, now)
        if was["state"] in ("live", "spent"):
            bump("destroyed")

    def sweep(now: int | None = None) -> None:
        now = int(now or time.time())
        for r in store.q("SELECT id FROM send_files WHERE state='live' AND checkin_every>0 AND checkin_due<=?", (now - RELEASE_DELAY,)):
            store.x("UPDATE send_files SET checkin_every=0 WHERE id=?", (r["id"],))
            event(r["id"], "released: the sender did not check in", now)
            alarm(r["id"], "released: the sender did not check in", now)
        for r in store.q("SELECT id FROM send_files WHERE state='live' AND open_until>0 AND open_until<=?", (now,)):
            kill(r["id"], "its opening window closed", now)
        for r in store.q("SELECT id, state, expires_at, die_at, half_life, created_at, price, pay_by, paid_at FROM send_files WHERE state!='dead'"):
            if r["state"] == "unpaid":
                if now > r["pay_by"] + PAY_GRACE:
                    kill(r["id"], "not paid", now)
            elif r["state"] == "uploading":
                if now - max(r["created_at"], r["paid_at"]) > UPLOAD_WINDOW * (6 if r["price"] else 1):
                    kill(r["id"], "upload not finished", now)
            elif r["state"] == "live" and now >= r["expires_at"] + (GRACE if r["paid_at"] else 0):
                kill(r["id"], "its time ended and it was not renewed" if r["paid_at"] else "expired", now)
            elif r["state"] == "live" and r["half_life"] and now >= r["die_at"]:
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

    app.state.send_sweep, app.state.send_kill, app.state.send_store = sweep, kill, store

    def stored() -> int:
        return store.one("SELECT COALESCE(SUM(size),0) AS n FROM send_files WHERE state!='dead'")["n"]

    def rules(r: dict) -> dict:
        return {"expires_at": r["expires_at"], "fade": bool(r["half_life"]), "half_life": r["half_life"],
                "max_opens": r["max_opens"], "opens": r["opens"], "forward": bool(r["forward"]), "kind": r["kind"],
                "open_after": r["open_after"], "receipt": bool(r["receipt"]), "reply_on": bool(r["reply_on"]),
                "control": bool(r["control"]), "open_until": r["open_until"], "holders": r["holders"], "need": r["need"],
                "held": r["checkin_every"] > 0, "checkin_every": r["checkin_every"], "checkin_due": r["checkin_due"],
                "release_at": r["checkin_due"] + RELEASE_DELAY if r["checkin_every"] > 0 else 0, "paused": bool(r.get("paused")),
                "has_key": bool(r.get("recover_hash")), **more_rules(r)}

    def more_rules(r: dict) -> dict:
        e = extras(r)
        out = {"extras": {k: e[k] for k in ("view_only", "view_secs", "presence", "card", "record", "chain", "qr", "name", "device") if k in e},
               "summary": r.get("summary"), "version": r.get("version", 1), "versions_left": r.get("versions_left", 0),
               "origin": e.get("origin") if r.get("origin_ok") else None, "origin_pending": e.get("origin") if not r.get("origin_ok") else None,
               "named": store.one("SELECT COUNT(*) AS n FROM send_recipients WHERE file=?", (r["id"],))["n"]}
        if r.get("approve_need"):
            out["approvals"] = {"need": r["approve_need"], "have": store.one(
                "SELECT COUNT(*) AS n FROM send_approvals WHERE file=? AND approved_at>0", (r["id"],))["n"],
                "of": store.one("SELECT COUNT(*) AS n FROM send_approvals WHERE file=?", (r["id"],))["n"]}
        if r.get("collect"):
            c = json.loads(r["collect"])
            count = store.one("SELECT COUNT(*) AS n FROM send_adds WHERE file=?", (r["id"],))["n"]
            out["collect"] = {**c, "count": count, "revealed": revealed(r, c, count), "closes_at": r["open_after"] or r["open_until"] or r["expires_at"]}
        if r.get("pay"):
            p = json.loads(r["pay"])
            paid = store.one("SELECT COALESCE(SUM(amount),0) AS a, COUNT(DISTINCT device) AS n FROM send_access WHERE file=?", (r["id"],))
            out["paylock"] = {"mode": p["mode"], "price": usdc(p["price"]), "to": p["to"], "buyers": p["buyers"], "sold": paid["n"],
                          "period_days": p.get("period", 0) // DAY, "target": usdc(p["target"]) if p.get("target") else None,
                          "raised": usdc(paid["a"]), "network": NETWORK_NAMES.get(network, network)}
        if r.get("parent"):
            chain, cur = [], r["parent"]
            while cur and len(chain) < 20:
                pr = store.one("SELECT id, created_at, parent FROM send_files WHERE id=?", (cur,))
                if pr is None:
                    break
                chain.append({"id": pr["id"][:8], "sealed_at": pr["created_at"]})
                cur = pr["parent"]
            out["chain"] = chain
        return out

    def revealed(r: dict, c: dict, count: int) -> bool:
        """Contributions open together: at the set time, and when enough are in, if the sender asked for that."""
        now = time.time()
        return (not r["open_after"] or now >= r["open_after"]) and count >= c.get("reveal_count", 0)

    def options(d: dict, lim: dict) -> dict:
        """The sender's choices, checked, with their price."""
        try:
            plain, keep, opens = int(d["plain"]), int(d.get("keep") or lim["max_keep"]), int(d.get("max_opens", 1))
            open_after, open_until = int(d.get("open_after") or 0), int(d.get("open_until") or 0)
            holders, need, checkin = int(d.get("holders") or 0), int(d.get("need") or 0), int(d.get("checkin_days") or 0)
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
        if open_until and not max(now, open_after) + 3600 <= open_until <= now + keep:
            raise HTTPException(422, "the closing date must be at least an hour after the opening date and not after the end")
        if holders and not (2 <= holders <= 20 and 2 <= need <= holders):
            raise HTTPException(422, "split custody: 2 to 20 people, and at least 2 keys to open")
        if checkin and not (1 <= checkin <= 90 and checkin * DAY < keep):
            raise HTTPException(422, "check in every 1 to 90 days, and store it longer than one check-in period")
        if checkin and open_after:
            raise HTTPException(422, "choose an opening date or check-in release, not both")
        o = {"plain": plain, "kind": kind, "open_until": open_until, "holders": holders, "need": need if holders else 0,
             "checkin": checkin * DAY, "keep": keep, "opens": opens, "forward": bool(d.get("forward")) or bool(holders),
             "open_after": open_after, "receipt": bool(d.get("receipt")), "reply": bool(d.get("reply")),
             "control": bool(d.get("control")), "fade": bool(d.get("fade")) and lim["all_rules"]}
        o["more"] = more_check(d, bool(d.get("_strict")))
        open_access = bool(o["more"].get("collect") or o["more"].get("pay") or o["more"]["extras"].get("qr") or o["more"].get("recipients")
                           or d.get("recipients"))             # these set who may open; openings are not sold on top
        o["lines"] = [] if lim["all_rules"] else price_lines(
            plain=plain, keep=keep, opens=1 if open_access else opens, forward=o["forward"] and not open_access, open_after=open_after, open_until=open_until,
            receipt=o["receipt"], reply=o["reply"], control=o["control"], holders=holders, checkin=checkin, free_bytes=lim["max_bytes"])
        if not lim["all_rules"]:                           # a send lives exactly one storage period
            o["keep"] = term_price(math.ceil(keep / DAY), plain, prices(), lim["max_bytes"])[0] * DAY
        if not lim["all_rules"]:
            o["lines"] += o["more"]["lines"]
        o["total"] = sum(n for _, n in o["lines"])
        if holders and opens:                              # one opening is the holders together: each of their places releases once
            o["opens"] = opens * holders
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
                         "to": payto, "network": NETWORK_NAMES.get(network, network), "listing_bps": LISTING_BPS, "terms": list(TERMS), "sizes": [lim["max_bytes"], SIZES[1] * MB, SIZES[2] * MB],
                         "grace": GRACE, "plan": [[usdc(prices()[f"plan_{r}_{t}"]) for t in TERMS] for r in range(3)],
                         "prices": {k: usdc(v) for k, v in prices().items()}}}

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
        o = options({**d, "plain": plain, "_strict": True}, lim)
        keep, opens, x = o["keep"], o["opens"], o["more"]
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
        room_hash, seats = None, None
        if o["holders"]:
            room_hash, seats = str(d.get("room_hash", "")), d.get("seat_hashes")
            if (not re.fullmatch(r"[0-9a-f]{64}", room_hash) or not isinstance(seats, list) or len(seats) != o["holders"]
                    or not all(isinstance(x, str) and re.fullmatch(r"[0-9a-f]{64}", x) for x in seats)):
                raise HTTPException(422, "split custody needs room_hash and one seat hash per person")
        die = fade_moment(now, HALF_LIFE, end) if fade else end
        upload = secrets.token_bytes(32)
        try:
            store.x("INSERT INTO send_files(id, state, created_at, expires_at, die_at, half_life, size, parts, max_opens, "
                    "forward, auth_hash, pin_tag, owner_pub, keeper_share, upload_hash, preview, meta, ip, kind, open_after, "
                    "receipt, reply_on, control, price, pay_by, open_until, holders, need, checkin_every, checkin_due, room_hash, seat_hashes) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (fid, "unpaid" if price else "uploading", now, end, die, HALF_LIFE if fade else 0, size, parts, opens,
                     int(o["forward"]), auth_hash, pin_tag, owner, share, sha(upload), preview, meta, ip, o["kind"],
                     o["open_after"], int(o["receipt"]), int(o["reply"]), int(o["control"]), price, now + PAY_WINDOW if price else 0,
                     o["open_until"], o["holders"], o["need"], o["checkin"], now + o["checkin"] if o["checkin"] else 0,
                     room_hash, json.dumps(seats) if seats else None))
        except Exception:  # noqa: BLE001  (duplicate id)
            raise HTTPException(409, "that id is taken")
        store.x("UPDATE send_files SET extras=?, summary=?, recover_hash=?, witness_hash=?, approve_need=?, duress_tag=?, decoy_share=?, "
                "decoy_meta=?, decoy_size=?, collect=?, pay=?, parent=?, versions_left=? WHERE id=?",
                (json.dumps(x["extras"]), x.get("summary"), x.get("recover_hash"), x.get("witness_hash"),
                 x["approvers"][0] if x.get("approvers") else 0, *(x["duress"] if x.get("duress") else (None, None, None, 0)),
                 json.dumps(x["collect"]) if x.get("collect") else None, json.dumps(x["pay"]) if x.get("pay") else None,
                 x.get("parent"), x.get("versions", 0), fid))
        for it in x.get("recipients", []):
            store.x("INSERT INTO send_recipients(file, idx, pin_tag, wrap, after, until, unless) VALUES (?,?,?,?,?,?,?)", (fid, *it))
        for i, h in enumerate(x["approvers"][1] if x.get("approvers") else []):
            store.x("INSERT INTO send_approvals(file, idx, token_hash) VALUES (?,?,?)", (fid, i, h))
        if x["extras"].get("name"):
            store.x("INSERT INTO send_names(name, file) VALUES (?,?)", (x["extras"]["name"], fid))
        open(path(fid), "wb").close()
        os.chmod(path(fid), 0o600)
        P0 = prices()
        return {"id": fid, "upload": b64u(upload), "part": PART, "expires_at": end,
                "renew": [{"days": t, "usdc": usdc(c)} for t in TERMS for c in [term_price(t, plain, P0, lim["max_bytes"])[1]] if c],
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
            h = hashlib.sha256()
            with open(path(fid), "rb") as f:
                for block in iter(lambda: f.read(1 << 20), b""):
                    h.update(block)
            store.x("UPDATE send_files SET seal_hash=? WHERE id=?", (h.hexdigest(), fid))
            event(fid, "sent")
            bump("sent")
            bump("bytes", r["size"])
        return {"got": got, "live": done}

    def is_owner(r: dict, action: str, d: dict) -> bool:
        """The sender: by the sender key, or by the device the send was made on."""
        if d.get("code") and r["recover_hash"] and hmac.compare_digest(sha(unb64u(d.get("code"), 32)), r["recover_hash"]):
            return True
        return bool(d.get("sig")) and verify(r["owner_pub"], action, r["id"], d.get("ts"), d.get("sig"))

    def owner_call(fid: str, action: str, d: dict) -> dict:
        r = row(fid)
        if not is_owner(r, action, d):
            raise HTTPException(403, "only the sender can do this: with the sender key, or from the device it was sent from")
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
                "claims": [{"device": c["device"], "name": c["name"], "code": c["code"], "at": c["at"], "approved": c["approved"]}
                           for c in store.q("SELECT device, name, code, at, approved FROM send_claims WHERE file=? ORDER BY at", (fid,))],
                "locked": r["state"] == "live" and now >= r["expires_at"], "destroy_at": r["expires_at"] + (GRACE if r["paid_at"] else 0),
                "renew": [{"days": t, "usdc": usdc(c)} for t in TERMS
                          for c in [term_price(t, r["size"] - r["parts"] * TAG, prices(), limits()["max_bytes"])[1]] if c],
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
        plain = r["size"] - r["parts"] * TAG
        if days not in TERMS and not lim["all_rules"]:
            raise HTTPException(422, "renew for " + ", ".join(str(t) for t in TERMS) + " days")
        if days < 1 or r["expires_at"] + days * DAY > now + 2 * lim["paid_max_keep"]:
            raise HTTPException(422, "a send can be paid for at most two years ahead")
        total = term_price(days, plain, prices(), lim["max_bytes"])[1]
        if not total and not lim["all_rules"]:
            raise HTTPException(422, "that period is the free one; renew for a longer one")
        if lim["all_rules"]:
            store.x("UPDATE send_files SET expires_at=expires_at+?, die_at=die_at+? WHERE id=?", (days * DAY, days * DAY, fid))
            event(fid, f"extended {days} days", now)
            return {"paid": True, "expires_at": r["expires_at"] + days * DAY, "pay": None}
        if not payto:
            raise HTTPException(402, "paid options are not switched on on this registry yet")
        amount = unique(total)
        store.x("UPDATE send_files SET ext_price=?, ext_keep=?, ext_by=? WHERE id=?", (amount, days * DAY, now + PAY_WINDOW, fid))
        return {"paid": False, "pay": pay_info(amount, now + PAY_WINDOW), "days": days}

    @app.post(api + "/files/{fid}/claim")
    async def claim(fid: str, request: Request):
        """A device asks the sender to be the one that may open this. Both sides see the same short code,
        so the sender can check by phone or in person that the request is from the right person."""
        guard(request)
        r = row(fid)
        d = await body(request)
        check_auth(r, d)
        if not extras(r).get("device"):
            raise HTTPException(404, "this send does not ask for an approved device")
        if r["state"] != "live":
            raise HTTPException(410, "this send has ended" + (f" ({r['reason']})" if r["reason"] else ""))
        device = b64u(unb64u(d.get("device_pub"), 65))
        if not verify(device, "claim", fid, d.get("ts"), d.get("sig")):
            raise HTTPException(403, "this device could not prove its key")
        limiter.check("send-claim", client_ip(request), 30, 3600)
        if store.one("SELECT 1 AS x FROM send_claims WHERE file=? AND device=?", (fid, device)) is None:
            if store.one("SELECT COUNT(*) AS n FROM send_claims WHERE file=?", (fid,))["n"] >= 20:
                raise HTTPException(429, "too many devices have asked; tell the sender")
            code = str(int(sha(unb64u(device, 65) + bytes.fromhex(fid)), 16) % 10000).zfill(4)
            name = re.sub(r"[\x00-\x1f]", " ", str(d.get("name") or "")).strip()[:60] or "No name given"
            store.x("INSERT INTO send_claims(file, device, name, code, at) VALUES (?,?,?,?,?)", (fid, device, name, code, int(time.time())))
            event(fid, f"a device asked to open it (code {code})")
            alarm(fid, f"a device asked to open it (code {code})")
        return claim_of(fid, device)

    @app.post(api + "/files/{fid}/claims")
    async def claims(fid: str, request: Request):
        """The sender approves or refuses a device that asked."""
        guard(request)
        d = await body(request)
        owner_call(fid, "claims", d)
        device = str(d.get("device", ""))
        if store.one("SELECT 1 AS x FROM send_claims WHERE file=? AND device=?", (fid, device)) is None:
            raise HTTPException(404, "no such request")
        store.x("UPDATE send_claims SET approved=? WHERE file=? AND device=?", (1 if d.get("ok") else -1, fid, device))
        event(fid, "the sender " + ("approved" if d.get("ok") else "refused") + " a device")
        return {"ok": True}

    @app.post(api + "/files/{fid}/pause")
    async def pause(fid: str, request: Request):
        """The sender stops it from being opened, or lets it be opened again. Its time keeps running."""
        guard(request)
        d = await body(request)
        r = owner_call(fid, "pause", d)
        if r["state"] != "live":
            raise HTTPException(409, "only a send that is waiting can be paused")
        store.x("UPDATE send_files SET paused=? WHERE id=?", (1 if d.get("on") else 0, fid))
        event(fid, "paused by the sender" if d.get("on") else "resumed by the sender")
        return {"paused": bool(d.get("on"))}

    @app.post(api + "/files/{fid}/edit")
    async def edit(fid: str, request: Request):
        """The sender changes rules of a send that is still waiting. Only within what was set when sending:
        dates can move or be dropped, openings can be lowered, the check-in period and the line shown before
        opening can change. Adding a new priced rule is not an edit."""
        guard(request)
        d = await body(request)
        r = owner_call(fid, "edit", d)
        now = int(time.time())
        if r["state"] != "live":
            raise HTTPException(409, "only a send that is waiting can be changed")
        sets, vals, said = [], [], []
        try:
            if "open_after" in d:
                v = int(d["open_after"] or 0)
                if not r["open_after"]:
                    raise HTTPException(402, "an opening date was not part of this send")
                if v and not now < v < r["expires_at"] - 3600:
                    raise HTTPException(422, "the opening date must be in the future and at least an hour before the end")
                sets.append("open_after=?"); vals.append(v); said.append("opening date " + ("changed" if v else "removed"))
            if "open_until" in d:
                v = int(d["open_until"] or 0)
                if not r["open_until"]:
                    raise HTTPException(402, "a closing date was not part of this send")
                if v and not max(now, int(d.get("open_after", r["open_after"]) or 0)) + 3600 <= v <= r["expires_at"]:
                    raise HTTPException(422, "the closing date must be at least an hour after the opening date and not after the end")
                sets.append("open_until=?"); vals.append(v); said.append("closing date " + ("changed" if v else "removed"))
            if "max_opens" in d:
                v = int(d["max_opens"])
                if not (v > r["opens"] and v >= 1 and (r["max_opens"] == 0 or v <= r["max_opens"])):
                    raise HTTPException(422, "openings can be lowered, not raised, and not below what was already used")
                sets.append("max_opens=?"); vals.append(v); said.append(f"openings set to {v}")
            if "checkin_days" in d:
                v = int(d["checkin_days"])
                if r["checkin_every"] <= 0:
                    raise HTTPException(402, "check-in release is not part of this send, or it was already released")
                if not 1 <= v <= 90:
                    raise HTTPException(422, "check in every 1 to 90 days")
                sets += ["checkin_every=?", "checkin_due=?"]; vals += [v * DAY, now + v * DAY]; said.append(f"check-in every {v} days")
        except (TypeError, ValueError):
            raise HTTPException(422, "dates, openings and days are numbers")
        if d.get("preview"):
            sets.append("preview=?"); vals.append(b64u(unb64u(d["preview"], most=SMALL))); said.append("the line shown before opening changed")
        if not sets:
            raise HTTPException(422, "nothing to change")
        store.x("UPDATE send_files SET " + ", ".join(sets) + " WHERE id=?", (*vals, fid))
        event(fid, "changed by the sender: " + ", ".join(said), now)
        return {"changed": said, **rules(row(fid))}

    @app.post(api + "/files/{fid}/pack")
    async def pack(fid: str, request: Request):
        """The sender's own copy of what they need (link, PINs, keys), sealed under the sender key and kept
        here so the sender key works on any device. The keeper cannot read it."""
        guard(request)
        d = await body(request, most=131072)
        r = owner_call(fid, "pack", d)
        if d.get("pack"):
            store.x("UPDATE send_files SET pack=? WHERE id=?", (b64u(unb64u(d["pack"], most=90000)), fid))
            return {"ok": True}
        if not r["pack"]:
            raise HTTPException(404, "nothing is stored for this sender key")
        return {"pack": r["pack"]}

    @app.post(api + "/files/{fid}/checkin")
    async def checkin(fid: str, request: Request):
        """The sender is still here: hold the send for one more period."""
        guard(request)
        sweep()
        r = owner_call(fid, "checkin", await body(request))
        if r["state"] != "live" or r["checkin_every"] <= 0:
            raise HTTPException(409, "this send is not being held (it was released, opened or ended)")
        due = int(time.time()) + r["checkin_every"]
        store.x("UPDATE send_files SET checkin_due=? WHERE id=?", (due, fid))
        event(fid, "checked in")
        return {"checkin_due": due}

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
        d0 = await body(request)
        check_auth(r, d0)
        if r["state"] in ("dead", "uploading", "unpaid"):
            return {"id": fid, "state": "dead" if r["state"] == "dead" else "uploading", "reason": r["reason"]}
        return {"id": fid, "state": r["state"], "locked": time.time() >= r["expires_at"], "size": r["size"], "parts": r["parts"], "part": PART, "preview": r["preview"],
                "sealed_at": r["created_at"], "claim": claim_of(fid, str(d0.get("device_pub", ""))) if extras(r).get("device") else None, "access": paid_ok(r, str(d0.get("device_pub", "")), int(time.time())) if r["pay"] else True,
                **rules(r), "bound": bool(r["bound_pub"]), "pin_tries_left": PIN_TRIES - r["pin_fails"]}

    def claim_of(fid: str, device: str) -> dict:
        cl = store.one("SELECT code, approved, name FROM send_claims WHERE file=? AND device=?", (fid, device))
        return {"asked": cl is not None, "code": cl["code"] if cl else None, "approved": bool(cl and cl["approved"] == 1),
                "refused": bool(cl and cl["approved"] == -1)}

    def paid_ok(r: dict, device: str, now: int) -> bool:
        p = json.loads(r["pay"])
        if p["mode"] == "crowd":
            return store.one("SELECT COALESCE(SUM(amount),0) AS a FROM send_access WHERE file=?", (r["id"],))["a"] >= p["target"]
        got = store.one("SELECT MAX(until) AS u, COUNT(*) AS n FROM send_access WHERE file=? AND device=?", (r["id"], device))
        return bool(got["n"]) and (p["mode"] == "each" or (got["u"] or 0) > now)

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
        now = int(time.time())
        if now >= r["expires_at"]:
            raise HTTPException(403, "this is locked: its time ended. The sender can still renew it for a few days; after that it is destroyed")
        if r["open_after"] and now < r["open_after"] and not r["collect"]:   # with contributions, that time is when they open
            raise HTTPException(403, "this cannot be opened yet; the sender set a later opening time")
        if r["checkin_every"] > 0:
            raise HTTPException(403, "this is held while the sender keeps checking in")
        if r["paused"]:
            raise HTTPException(403, "the sender has paused this; it cannot be opened until they resume it")
        device = b64u(unb64u(d.get("device_pub"), 65))
        if not verify(device, "open", fid, d.get("ts"), d.get("sig")):
            raise HTTPException(403, "this device could not prove its key")
        if r["approve_need"]:
            have = store.one("SELECT COUNT(*) AS n FROM send_approvals WHERE file=? AND approved_at>0", (fid,))["n"]
            if have < r["approve_need"]:
                raise HTTPException(403, f"waiting for approval: {have} of {r['approve_need']} have approved the release")
        if extras(r).get("device"):
            cl = store.one("SELECT approved, code FROM send_claims WHERE file=? AND device=?", (fid, device))
            if cl is None or cl["approved"] != 1:
                raise HTTPException(403, "the sender must approve this device first" + (f" (your code is {cl['code']})" if cl else ""))
        if r["pay"] and not paid_ok(r, device, now):
            raise HTTPException(402, "this opens after payment")
        recs = [dict(x) for x in store.q("SELECT * FROM send_recipients WHERE file=? ORDER BY idx", (fid,))]
        if not recs and not r["forward"] and r["bound_pub"] and not hmac.compare_digest(device, r["bound_pub"]):
            raise HTTPException(403, "this file was already opened on another device and cannot be passed on")
        proof = str(d.get("pin_proof", ""))
        good = bool(HEX64.match(proof))
        decoy = good and bool(r["duress_tag"]) and hmac.compare_digest(proof, r["duress_tag"])
        who = next((x for x in recs if good and hmac.compare_digest(proof, x["pin_tag"])), None)
        if not decoy and who is None and not (good and not recs and hmac.compare_digest(proof, r["pin_tag"])):
            fails = r["pin_fails"] + 1
            store.x("UPDATE send_files SET pin_fails=? WHERE id=?", (fails, fid))
            if fails >= PIN_TRIES:
                kill(fid, "too many wrong PINs")
                raise HTTPException(410, "too many wrong PINs: the file has been destroyed")
            raise HTTPException(403, f"wrong PIN ({PIN_TRIES - fails} tries left)")
        token = secrets.token_bytes(32)
        opens = r["opens"] + 1
        last = bool(r["max_opens"]) and opens >= r["max_opens"]
        if decoy:                                          # looks like an opening; releases the decoy and tells the sender
            store.x("INSERT INTO send_tokens(token_hash, file, expires_at, kind) VALUES (?,?,?,'decoy')",
                    (sha(token), fid, min(now + DOWNLOAD_WINDOW, r["expires_at"])))
            event(fid, "duress PIN used", now)
            alarm(fid, "duress PIN used", now)
            return {"keeper_share": r["decoy_share"], "token": b64u(token), "meta": r["decoy_meta"], "size": r["decoy_size"],
                    "kind": r["kind"], "reply_on": False, "parts": 1, "part": PART, "opens": opens, "max_opens": r["max_opens"], "last": last}
        if who is not None:
            if who["after"] and now < who["after"]:
                raise HTTPException(403, "this PIN is not valid yet")
            if who["until"] and now >= who["until"]:
                raise HTTPException(403, "the time for this PIN has passed")
            if who["unless"] is not None and any(x["opened_at"] for x in recs[:who["idx"]]):
                raise HTTPException(403, "this was already claimed by the person before you")
            if who["opened_at"] and who["device"] and not hmac.compare_digest(device, who["device"]):
                raise HTTPException(403, "this PIN was already used on another device")
            store.x("UPDATE send_recipients SET opened_at=?, device=? WHERE file=? AND idx=?", (now, device, fid, who["idx"]))
        store.x("INSERT INTO send_tokens(token_hash, file, expires_at) VALUES (?,?,?)",
                (sha(token), fid, min(now + DOWNLOAD_WINDOW, r["expires_at"])))
        store.x("UPDATE send_files SET opens=?, pin_fails=0, bound_pub=COALESCE(bound_pub, ?), state=?, keeper_share=? WHERE id=?",
                (opens, None if r["forward"] or recs else device, "spent" if last else "live", None if last else r["keeper_share"], fid))
        what = "opened" if who is None else f"opened by recipient {who['idx'] + 1}"
        event(fid, what, now)
        bump("opened")
        alarm(fid, what, now)
        return {"keeper_share": r["keeper_share"], "token": b64u(token), "meta": r["meta"], "size": r["size"],
                "kind": r["kind"], "reply_on": bool(r["reply_on"]) and r["reply"] is None,
                "wrap": who["wrap"] if who else None, "who": who["idx"] if who else None,
                "parts": r["parts"], "part": PART, "opens": opens, "max_opens": r["max_opens"], "last": last}

    @app.get(api + "/files/{fid}/parts/{n}")
    def get_part(fid: str, n: int, request: Request):
        r = row(fid)
        token = request.headers.get("x-send-token", "")
        t = store.one("SELECT file, expires_at, kind FROM send_tokens WHERE token_hash=?", (sha(unb64u(token, 32)),))
        if t is None or t["file"] != fid or t["expires_at"] < time.time() or r["state"] == "dead":
            raise HTTPException(403, "this download is no longer allowed")
        decoy = t["kind"] == "decoy"
        if not 0 <= n < (1 if decoy else r["parts"]):
            raise HTTPException(404, "no such part")
        try:
            with open(side(fid, "decoy") if decoy else path(fid), "rb") as f:
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

    # ---- split custody: the opening room ---------------------------------------------------------

    def room_member(fid: str, d: dict) -> tuple[dict, str, int]:
        r = row(fid)
        if not r["holders"] or not r["room_hash"]:
            raise HTTPException(404, "this send has no key holders")
        if not hmac.compare_digest(sha(unb64u(d.get("room_auth"), 32)), r["room_hash"]):
            raise HTTPException(403, "this link does not match the send")
        device = b64u(unb64u(d.get("device_pub"), 65))
        if not verify(device, "room", fid, d.get("ts"), d.get("sig")):
            raise HTTPException(403, "this device could not prove its key")
        if r["paused"]:
            raise HTTPException(403, "the sender has paused this; it cannot be opened until they resume it")
        if r["state"] not in ("live", "spent"):               # after the last opening the holders can still see who is present
            raise HTTPException(410, "this can no longer be opened" + (f" ({r['reason']})" if r["reason"] else ""))
        now = int(time.time())
        here = {x["device"] for x in store.q("SELECT device FROM send_room_seen WHERE file=? AND seen_at>?", (fid, now - ROOM_SEEN))}
        if device not in here and len(here) >= r["holders"]:
            raise HTTPException(429, f"this is already open in {r['holders']} places, the most allowed at once")
        store.x("INSERT INTO send_room_seen(file, device, seen_at) VALUES (?,?,?) ON CONFLICT(file, device) DO UPDATE SET seen_at=excluded.seen_at",
                (fid, device, now))
        if r["room_until"]:
            if now > r["room_until"]:                      # that opening is over: the sealed keys are cleared
                store.x("DELETE FROM send_room WHERE file=?", (fid,))
                store.x("UPDATE send_files SET room_until=0 WHERE id=?", (fid,))
        else:
            # A key counts only while its place is live: a place that left takes its keys with it.
            store.x("DELETE FROM send_room WHERE file=? AND device NOT IN (SELECT device FROM send_room_seen WHERE file=? AND seen_at>?)",
                    (fid, fid, now - ROOM_SEEN))
            first = store.one("SELECT MIN(added_at) AS t FROM send_room WHERE file=?", (fid,))["t"]
            if first and now - first > ROOM_WINDOW:        # the window passed incomplete: the keys are cleared
                store.x("DELETE FROM send_room WHERE file=?", (fid,))
        return r, device, now

    def room_state(r: dict, device: str, now: int) -> dict:
        rows = store.q("SELECT seat, device, ct, added_at FROM send_room WHERE file=?", (r["id"],))
        added = {x["seat"] for x in rows}
        mine = any(x["device"] == device for x in rows)
        released = len(added) >= r["need"]
        first = min((x["added_at"] for x in rows), default=0)
        here = store.one("SELECT COUNT(*) AS n FROM send_room_seen WHERE file=? AND seen_at>?", (r["id"], now - ROOM_SEEN))["n"]
        return {"holders": r["holders"], "need": r["need"], "here": here, "added": sorted(added), "mine": mine,
                "window_ends": first + ROOM_WINDOW if first else 0, "window": ROOM_WINDOW, "released": released,
                "held": r["checkin_every"] > 0, "checkin_due": r["checkin_due"] + RELEASE_DELAY, "open_after": r["open_after"],
                "locked": now >= r["expires_at"],
                # The sealed keys go only to a location that added one, and only when enough are in.
                "keys": {str(x["seat"]): x["ct"] for x in rows} if released and mine else None}

    @app.post(api + "/files/{fid}/room")
    async def room(fid: str, request: Request):
        guard(request)
        sweep()
        r, device, now = room_member(fid, await body(request))
        return room_state(r, device, now)

    @app.post(api + "/files/{fid}/room/key")
    async def room_key(fid: str, request: Request):
        guard(request)
        d = await body(request)
        r, device, now = room_member(fid, d)
        limiter.check("send-room-key", client_ip(request), 120, 3600)
        try:
            seat = int(d["seat"])
        except (KeyError, TypeError, ValueError):
            raise HTTPException(422, "seat is needed")
        if not 1 <= seat <= r["holders"]:
            raise HTTPException(422, "no such key holder")
        ct = unb64u(d.get("ct"), most=64)
        if not hmac.compare_digest(sha(ct), json.loads(r["seat_hashes"])[seat - 1]):
            raise HTTPException(403, "that is not this person's key")
        store.x("INSERT INTO send_room(file, seat, device, ct, added_at) VALUES (?,?,?,?,?) ON CONFLICT(file, seat) DO NOTHING",
                (fid, seat, device, b64u(ct), now))
        if not r["room_until"] and store.one("SELECT COUNT(*) AS n FROM send_room WHERE file=?", (fid,))["n"] >= r["need"]:
            store.x("UPDATE send_files SET room_until=? WHERE id=?", (now + ROOM_HOLD, fid))
            event(fid, "the keys were added together", now)
            alarm(fid, "the keys were added together", now)
        return room_state(r, device, now)


    # ---- the general blocks ----------------------------------------------------------------------

    @app.get(P + "/send/n/{name}")
    def named_page(name: str):
        return page("send-open.html")

    @app.get(api + "/names/{name}")
    def named(name: str):
        r = store.one("SELECT file FROM send_names WHERE name=?", (name.lower(),))
        if r is None:
            raise HTTPException(404, "no send has that name")
        return {"id": r["file"]}

    @app.put(api + "/files/{fid}/decoy")
    async def put_decoy(fid: str, request: Request):
        guard(request)
        r = row(fid)
        if r["state"] == "unpaid":
            raise HTTPException(402, "this send is paid for before it is uploaded")
        if r["state"] != "uploading" or not r["upload_hash"] or not r["duress_tag"]:
            raise HTTPException(409, "no decoy is expected")
        if not hmac.compare_digest(sha(unb64u(request.headers.get("x-send-upload"), 32)), r["upload_hash"]):
            raise HTTPException(403, "wrong upload token")
        data = await request.body()
        if len(data) != r["decoy_size"]:
            raise HTTPException(422, f"the decoy must be {r['decoy_size']} bytes")
        with open(side(fid, "decoy"), "wb") as f:
            f.write(data)
        os.chmod(side(fid, "decoy"), 0o600)
        return {"ok": True}

    def approvals(fid: str, need: int) -> dict:
        rows = store.q("SELECT idx, approved_at FROM send_approvals WHERE file=? ORDER BY idx", (fid,))
        return {"need": need, "of": len(rows), "have": sum(1 for x in rows if x["approved_at"]), "who": [bool(x["approved_at"]) for x in rows]}

    @app.post(api + "/files/{fid}/approve")
    async def approve(fid: str, request: Request):
        """An approver agrees to the release. Approving shows the approver nothing of the content."""
        guard(request)
        r = row(fid)
        d = await body(request)
        try:
            idx = int(d["idx"])
        except (KeyError, TypeError, ValueError):
            raise HTTPException(422, "idx is needed")
        a = store.one("SELECT token_hash, approved_at FROM send_approvals WHERE file=? AND idx=?", (fid, idx))
        if a is None or not hmac.compare_digest(sha(unb64u(d.get("token"), 32)), a["token_hash"]):
            raise HTTPException(403, "this is not an approver's link for this send")
        if r["state"] == "dead":
            raise HTTPException(410, "this send has ended" + (f" ({r['reason']})" if r["reason"] else ""))
        if d.get("approve") and not a["approved_at"]:
            store.x("UPDATE send_approvals SET approved_at=? WHERE file=? AND idx=?", (int(time.time()), fid, idx))
            event(fid, f"approved by approver {idx + 1}")
            alarm(fid, f"approved by approver {idx + 1}")
        return {**approvals(fid, r["approve_need"]), "mine": bool(a["approved_at"]) or bool(d.get("approve")), "state": r["state"],
                "expires_at": r["expires_at"]}

    def build_record(r: dict) -> dict:
        ev = [{"at": e["ts"], "event": e["event"]} for e in store.q("SELECT ts, event FROM send_events WHERE file=? ORDER BY id", (r["id"],))]
        return {"type": "innernet-send-record/1", "registry": settings.origin, "send": r["id"], "sealed_at": r["created_at"],
                "sealed_bytes": r["size"], "seal_sha256": r["seal_hash"], "state": r["state"], "reason": r["reason"],
                "opened": sum(1 for e in ev if e["event"].startswith("opened")), "ends_at": r["expires_at"], "version": r["version"],
                "events": ev, "issued_at": int(time.time())}

    @app.post(api + "/files/{fid}/record")
    async def record(fid: str, request: Request):
        """A signed statement of what happened to this send: when it was sealed, every opening, or that it
        ended unopened. For the sender, a witness, or (if the sender chose) anyone holding the link."""
        guard(request)
        sweep()
        r = row(fid)
        d = await body(request)
        if d.get("sig") or d.get("code"):
            ok = is_owner(r, "record", d)
        elif d.get("token"):
            ok = bool(r["witness_hash"]) and hmac.compare_digest(sha(unb64u(d["token"], 32)), r["witness_hash"])
        else:
            ok = bool(extras(r).get("record")) and hmac.compare_digest(sha(unb64u(d.get("auth"), 32)), r["auth_hash"])
        if not ok:
            raise HTTPException(403, "the record is for the sender, a witness, or link holders if the sender chose so")
        return sign_record(build_record(r))

    @app.post(api + "/files/{fid}/witness")
    async def witness(fid: str, request: Request):
        """A witness sees what happens to a send, and gets the signed record, without holding any key."""
        guard(request)
        sweep()
        r = row(fid)
        d = await body(request)
        if not r["witness_hash"] or not hmac.compare_digest(sha(unb64u(d.get("token"), 32)), r["witness_hash"]):
            raise HTTPException(403, "this is not a witness link for this send")
        return {"state": r["state"], "reason": r["reason"], "sealed_at": r["created_at"], "expires_at": r["expires_at"],
                "opens": r["opens"], "max_opens": r["max_opens"], "holders": r["holders"], "need": r["need"],
                "held": r["checkin_every"] > 0, "open_after": r["open_after"], "open_until": r["open_until"],
                "approvals": approvals(fid, r["approve_need"]) if r["approve_need"] else None,
                "signed": sign_record(build_record(r)) if signer is not None else None}

    @app.post(api + "/files/{fid}/recover")
    async def recover(fid: str, request: Request):
        """Move the sender's control of a send to another device, with the recovery code saved at sending."""
        guard(request)
        limiter.check("send-recover", client_ip(request), 20, 3600)
        r = row(fid)
        d = await body(request)
        new = b64u(unb64u(d.get("owner_pub"), 65))
        if not r["recover_hash"] or not hmac.compare_digest(sha(unb64u(d.get("code"), 32)), r["recover_hash"]):
            raise HTTPException(403, "that recovery code does not belong to this send")
        if not verify(new, "recover", fid, d.get("ts"), d.get("sig")):
            raise HTTPException(403, "this device could not prove its key")
        store.x("UPDATE send_files SET owner_pub=? WHERE id=?", (new, fid))
        event(fid, "control moved to another device")
        return {"ok": True}

    @app.post(api + "/files/{fid}/origin")
    async def origin(fid: str, request: Request):
        """Check that the sender controls the domain they named: it must publish this sender's device key."""
        guard(request)
        r = owner_call(fid, "origin", await body(request))
        dom = extras(r).get("origin")
        if not dom:
            raise HTTPException(409, "no origin was named for this send")
        limiter.check("send-origin", client_ip(request), 30, 3600)
        where = f"https://{dom}/.well-known/innernet-send.txt"
        try:
            text = http_out(where)
        except Exception:  # noqa: BLE001
            raise HTTPException(422, f"could not read {where}")
        if r["owner_pub"] not in text:
            raise HTTPException(422, f"{where} does not contain this device's key")
        store.x("UPDATE send_files SET origin_ok=? WHERE id=?", (int(time.time()), fid))
        event(fid, f"origin confirmed: {dom}")
        return {"origin": dom}

    # ---- others add to it ------------------------------------------------------------------------

    def collect_of(r: dict) -> dict:
        if not r["collect"]:
            raise HTTPException(404, "nothing can be added to this send")
        return json.loads(r["collect"])

    @app.put(api + "/files/{fid}/adds")
    async def add(fid: str, request: Request):
        """Add a sealed contribution, or replace your own, until the opening time."""
        guard(request)
        sweep()
        r = row(fid)
        c = collect_of(r)
        h = request.headers
        if not hmac.compare_digest(sha(unb64u(h.get("x-send-auth"), 32)), r["auth_hash"]):
            raise HTTPException(403, "this link does not match the send")
        device = b64u(unb64u(h.get("x-send-device"), 65))
        if not verify(device, "add", fid, h.get("x-send-ts"), h.get("x-send-sig")):
            raise HTTPException(403, "this device could not prove its key")
        now = int(time.time())
        closes = r["open_after"] or min(r["open_until"] or r["expires_at"], r["expires_at"])
        if r["state"] != "live" or now >= closes:
            raise HTTPException(403, "this is closed: nothing can be added or changed any more")
        data = await request.body()
        if not 17 <= len(data) <= ADD_BYTES:
            raise HTTPException(413, "a contribution is at most 4 MB")
        mine = store.one("SELECT n, changes FROM send_adds WHERE file=? AND device=?", (fid, device))
        count = store.one("SELECT COUNT(*) AS n FROM send_adds WHERE file=?", (fid,))["n"]
        if mine is None and count >= c["seats"]:
            raise HTTPException(409, "all places are taken")
        n = mine["n"] if mine else count
        digest = sha(data)
        with open(side(fid, f"a{n}"), "wb") as f:
            f.write(data)
        os.chmod(side(fid, f"a{n}"), 0o600)
        if mine:
            store.x("UPDATE send_adds SET size=?, hash=?, updated_at=?, changes=changes+1 WHERE file=? AND n=?", (len(data), digest, now, fid, n))
        else:
            store.x("INSERT INTO send_adds(file, n, device, size, hash, first_at, updated_at) VALUES (?,?,?,?,?,?,?)",
                    (fid, n, device, len(data), digest, now, now))
            event(fid, "a contribution was added", now)
        receipt = {"type": "innernet-send-receipt/1", "registry": settings.origin, "send": fid, "entry": n + 1, "sha256": digest,
                   "received_at": now, "changes": (mine["changes"] + 1) if mine else 0}
        return sign_record(receipt) if signer is not None else {"record": receipt}

    def adds_reader(r: dict, c: dict, d: dict) -> tuple[bool, str]:
        """(may read the contributions now, this device)."""
        device = str(d.get("device_pub", ""))
        count = store.one("SELECT COUNT(*) AS n FROM send_adds WHERE file=?", (r["id"],))["n"]
        if d.get("sig") or d.get("code"):
            owner = is_owner(r, "adds", d)
        else:
            owner = False
            check_auth(r, d)
        return revealed(r, c, count) and (owner or c["audience"] == "all"), device

    @app.post(api + "/files/{fid}/adds/list")
    async def adds_list(fid: str, request: Request):
        guard(request)
        sweep()
        r = row(fid)
        c = collect_of(r)
        d = await body(request)
        may, device = adds_reader(r, c, d)
        rows = store.q("SELECT n, device, size, hash, first_at, updated_at, changes FROM send_adds WHERE file=? ORDER BY n", (fid,))
        mine = next((x for x in rows if x["device"] == device), None)
        return {"count": len(rows), "seats": c["seats"], "revealed": revealed(r, c, len(rows)), "may_read": may,
                "form": c.get("form", ""), "audience": c["audience"], "anon": c["anon"], "pub": c.get("pub"),
                "closes_at": r["open_after"] or r["open_until"] or r["expires_at"], "reveal_count": c["reveal_count"],
                "mine": {"entry": mine["n"] + 1, "sha256": mine["hash"], "updated_at": mine["updated_at"], "changes": mine["changes"]} if mine else None,
                "entries": [{"entry": x["n"] + 1, "size": x["size"], "sha256": x["hash"], "received_at": x["updated_at"],
                             "first_at": x["first_at"], "changes": x["changes"]} for x in rows] if may else None}

    @app.post(api + "/files/{fid}/adds/{n}")
    async def adds_get(fid: str, n: int, request: Request):
        guard(request)
        r = row(fid)
        c = collect_of(r)
        may, _ = adds_reader(r, c, await body(request))
        if not may:
            raise HTTPException(403, "the contributions are not open" + ("" if c["audience"] == "all" else " to you"))
        try:
            with open(side(fid, f"a{n - 1}"), "rb") as f:
                data = f.read()
        except FileNotFoundError:
            raise HTTPException(404, "no such contribution")
        return Response(data, media_type="application/octet-stream", headers={"Cache-Control": "no-store"})

    # ---- payment as a lock -----------------------------------------------------------------------

    def buyer(fid: str, d: dict) -> tuple[dict, dict, str]:
        r = row(fid)
        if not r["pay"]:
            raise HTTPException(404, "this send has no payment lock")
        check_auth(r, d)
        device = b64u(unb64u(d.get("device_pub"), 65))
        if not verify(device, "buy", fid, d.get("ts"), d.get("sig")):
            raise HTTPException(403, "this device could not prove its key")
        if r["state"] != "live":
            raise HTTPException(410, "this send has ended" + (f" ({r['reason']})" if r["reason"] else ""))
        return r, json.loads(r["pay"]), device

    @app.post(api + "/files/{fid}/buy")
    async def buy(fid: str, request: Request):
        """A price for this device to open it, paid straight to the sender's own address."""
        guard(request)
        d = await body(request)
        r, p, device = buyer(fid, d)
        if rpc is None or network not in USDC:
            raise HTTPException(503, "payments cannot be checked on this registry")
        limiter.check("send-buy", client_ip(request), 60, 3600)
        now = int(time.time())
        sold = {x["device"] for x in store.q("SELECT DISTINCT device FROM send_access WHERE file=?", (fid,))}
        if device not in sold and len(sold) >= p["buyers"]:
            raise HTTPException(409, "it is sold out")
        base = micro(d.get("amount")) if p["mode"] == "crowd" and d.get("amount") else p["price"]
        if p["mode"] == "crowd" and base < p["price"]:
            raise HTTPException(422, f"the least you can put in is {usdc(p['price'])} USDC")
        store.x("DELETE FROM send_quotes WHERE pay_by<?", (now - PAY_GRACE,))
        amount = unique(base)
        store.x("INSERT INTO send_quotes(amount, file, device, pay_by) VALUES (?,?,?,?)", (amount, fid, device, now + PAY_WINDOW))
        return {"amount": usdc(amount), "micro": amount, "to": p["to"], "network": network, "network_name": NETWORK_NAMES[network],
                "chain_id": CHAIN_IDS[network], "usdc": USDC[network], "pay_by": now + PAY_WINDOW, "explorer": EXPLORER_TX[network]}

    @app.post(api + "/files/{fid}/buy/check")
    async def buy_check(fid: str, request: Request):
        guard(request)
        d = await body(request)
        r, p, device = buyer(fid, d)
        now = int(time.time())
        tx = str(d.get("tx") or "").lower()
        if tx and not TX.match(tx):
            raise HTTPException(422, "tx must be a transaction hash")
        limiter.check("send-pay", client_ip(request), 600, 3600)
        for q in store.q("SELECT amount FROM send_quotes WHERE file=? AND device=? AND pay_by>?", (fid, device, now - PAY_GRACE)):
            found = find_payment(q["amount"], tx or None, p["to"])
            if found is None:
                continue
            try:
                store.x("INSERT INTO send_payments(tx, file, amount, payer, ts, what) VALUES (?,?,?,?,?,?)", (found[0], fid, q["amount"], found[1], now, "buy"))
            except Exception:  # noqa: BLE001
                continue
            store.x("INSERT INTO send_access(file, device, amount, tx, until, at) VALUES (?,?,?,?,?,?)",
                    (fid, device, q["amount"], found[0], now + p["period"] if p["mode"] == "period" else 0, now))
            store.x("DELETE FROM send_quotes WHERE amount=?", (q["amount"],))
            event(fid, f"a reader paid {usdc(q['amount'])} USDC to the sender", now)
        return {"access": paid_ok(r, device, now), **more_rules(r)["paylock"]}

    # ---- a new version on the same link ----------------------------------------------------------

    @app.post(api + "/files/{fid}/version")
    async def version(fid: str, request: Request):
        guard(request)
        d = await body(request)
        r = owner_call(fid, "version", d)
        if r["state"] != "live":
            raise HTTPException(409, "only a send that is waiting can get a new version")
        if r["versions_left"] < 1:
            raise HTTPException(402, "no new versions were bought for this send")
        if store.one("SELECT COUNT(*) AS n FROM send_recipients WHERE file=?", (fid,))["n"] or r["holders"]:
            raise HTTPException(409, "a send with named recipients or key holders cannot get a new version")
        try:
            size, parts = int(d["size"]), int(d["parts"])
        except (KeyError, TypeError, ValueError):
            raise HTTPException(422, "size and parts are needed")
        plain = size - parts * TAG
        if parts < 1 or plain < 1 or parts != math.ceil(plain / PART) or size > max(r["size"], limits()["max_bytes"] + parts * TAG):
            raise HTTPException(422, "a new version is at most as large as the plan that was paid for")
        upload = secrets.token_bytes(32)
        store.x("UPDATE send_files SET next_share=?, next_meta=?, next_size=?, next_parts=?, next_got=0, next_upload=? WHERE id=?",
                (b64u(unb64u(d.get("keeper_share"), 32)), b64u(unb64u(d.get("meta"), most=SMALL)), size, parts, sha(upload), fid))
        open(side(fid, "next"), "wb").close()
        os.chmod(side(fid, "next"), 0o600)
        return {"upload": b64u(upload), "part": PART}

    @app.put(api + "/files/{fid}/vparts/{n}")
    async def put_vpart(fid: str, n: int, request: Request):
        guard(request)
        r = row(fid)
        if r["state"] != "live" or not r["next_upload"]:
            raise HTTPException(409, "no new version is being uploaded")
        if not hmac.compare_digest(sha(unb64u(request.headers.get("x-send-upload"), 32)), r["next_upload"]):
            raise HTTPException(403, "wrong upload token")
        if n != r["next_got"]:
            raise HTTPException(409, f"part {r['next_got']} is next")
        want = PART + TAG if n < r["next_parts"] - 1 else r["next_size"] - (r["next_parts"] - 1) * (PART + TAG)
        data = await request.body()
        if len(data) != want:
            raise HTTPException(422, f"part {n} must be {want} bytes")
        with open(side(fid, "next"), "ab") as f:
            f.write(data)
        if n + 1 < r["next_parts"]:
            store.x("UPDATE send_files SET next_got=? WHERE id=?", (n + 1, fid))
            return {"got": n + 1, "live": False}
        os.replace(side(fid, "next"), path(fid))
        h = hashlib.sha256()
        with open(path(fid), "rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                h.update(block)
        store.x("UPDATE send_files SET keeper_share=next_share, meta=next_meta, size=next_size, parts=next_parts, seal_hash=?, version=version+1, "
                "versions_left=versions_left-1, next_share=NULL, next_meta=NULL, next_upload=NULL, next_size=0, next_parts=0, next_got=0 WHERE id=?",
                (h.hexdigest(), fid))
        store.x("DELETE FROM send_tokens WHERE file=?", (fid,))
        event(fid, f"new version {r['version'] + 1}")
        return {"got": n + 1, "live": True, "version": r["version"] + 1}
