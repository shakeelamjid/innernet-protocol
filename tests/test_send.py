"""INNERNET Send (SEND-1): the keeper's rules. The sealing itself happens in the browser
(static/send-core.js) and is tested with Node at the end of this file."""
import hashlib
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi.testclient import TestClient

from innernet2.registry_service import send
from innernet2.registry_service.app import create_app
from innernet2.registry_service.config import USDC
from tests.test_registry_service import FEE_WALLET, ORIGIN, SEPOLIA, P, FakeChain, settings

H = {"X-Innernet": "1", "Origin": ORIGIN}
API = P + "/send/api"
ROOT = Path(__file__).resolve().parents[1]


class Device:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.pub = send.b64u(self.key.public_key().public_bytes(serialization.Encoding.X962,
                                                                serialization.PublicFormat.UncompressedPoint))

    def sign(self, action, fid, ts=None):
        ts = int(time.time()) if ts is None else ts
        r, s = decode_dss_signature(self.key.sign(send.signed_message(action, fid, ts), ec.ECDSA(hashes.SHA256())))
        return {"ts": ts, "sig": send.b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("INNERNET_SEND_MAX_MB", "9")
    monkeypatch.setenv("INNERNET_SEND_ALL_RULES", "1")       # the whole rule engine (paid capsules, not open yet)
    a = create_app(settings(tmp_path), rpc=FakeChain(), connect=lambda h, p, t: 3.0)
    return TestClient(a, base_url=ORIGIN), a, tmp_path


def make(client, owner, *, plain=10, pin_tag="aa" * 32, auth=b"A" * 32, **rules):
    fid = os.urandom(16).hex()
    parts = max(1, -(-plain // send.PART))
    body = {"id": fid, "size": plain + parts * send.TAG, "parts": parts, "keep": 86400, "max_opens": 1, "forward": False,
            "fade": False, "auth_hash": hashlib.sha256(auth).hexdigest(), "pin_tag": pin_tag, "owner_pub": owner.pub,
            "keeper_share": send.b64u(b"S" * 32), "preview": send.b64u(b"pv"), "meta": send.b64u(b"meta"), **rules}
    r = client.post(API + "/files", json=body, headers=H)
    assert r.status_code == 200, r.text
    sealed = os.urandom(body["size"])
    for n in range(parts):
        chunk = sealed[n * (send.PART + send.TAG):(n + 1) * (send.PART + send.TAG)]
        up = client.put(API + f"/files/{fid}/parts/{n}", content=chunk, headers={**H, "X-Send-Upload": r.json()["upload"]})
        assert up.status_code == 200, up.text
    assert up.json()["live"] is True
    return fid, sealed


def open_(client, fid, device, *, pin_tag="aa" * 32, auth=b"A" * 32):
    return client.post(API + f"/files/{fid}/open", headers=H, json={
        "auth": send.b64u(auth), "pin_proof": pin_tag, "device_pub": device.pub, **device.sign("open", fid)})


def info(client, fid, auth=b"A" * 32):
    return client.post(API + f"/files/{fid}/info", json={"auth": send.b64u(auth)}, headers=H)


def test_a_file_opens_once_then_is_destroyed(app):
    client, a, tmp = app
    owner, rx = Device(), Device()
    fid, sealed = make(client, owner, plain=send.PART + 100)       # two parts
    i = info(client, fid).json()
    assert i["state"] == "live" and i["max_opens"] == 1 and i["parts"] == 2 and i["preview"] == send.b64u(b"pv")
    assert info(client, fid, auth=b"B" * 32).status_code == 403    # without the link: nothing
    assert client.post(API + f"/files/{fid}/info", json={"auth": send.b64u(b"A" * 32)}).status_code == 403   # no header
    r = open_(client, fid, rx)
    assert r.status_code == 200, r.text
    rel = r.json()
    assert rel["keeper_share"] == send.b64u(b"S" * 32) and rel["last"] is True and rel["meta"] == send.b64u(b"meta")
    got = b"".join(client.get(API + f"/files/{fid}/parts/{n}", headers={"X-Send-Token": rel["token"]}).content for n in range(2))
    assert got == sealed
    assert client.get(API + f"/files/{fid}/parts/0", headers={"X-Send-Token": send.b64u(b"x" * 32)}).status_code == 403
    # Used up: the keeper share is gone from the record, a second opening is refused, even with everything right.
    row = a.state.store.one("SELECT state, keeper_share FROM send_files WHERE id=?", (fid,))
    assert row["state"] == "spent" and row["keeper_share"] is None
    assert open_(client, fid, rx).status_code == 410 and info(client, fid).json()["state"] == "spent"
    # After the download window the sealed bytes are deleted too.
    a.state.send_sweep(int(time.time()) + send.DOWNLOAD_WINDOW + 1)
    assert not (tmp / "send" / f"{fid}.bin").exists()
    assert info(client, fid).json() == {"id": fid, "state": "dead", "reason": "opened"}
    st = client.post(API + f"/files/{fid}/status", json=owner.sign("status", fid), headers=H).json()
    assert [e["event"] for e in st["events"]] == ["sent", "opened", "ended: opened"]
    assert client.post(API + f"/files/{fid}/status", json=rx.sign("status", fid), headers=H).status_code == 403


def test_wrong_pins_destroy_the_file_and_the_first_device_keeps_it(app):
    client, a, tmp = app
    owner, rx, other = Device(), Device(), Device()
    fid, _ = make(client, owner, max_opens=3)
    assert open_(client, fid, rx, pin_tag="bb" * 32).status_code == 403
    assert info(client, fid).json()["pin_tries_left"] == send.PIN_TRIES - 1
    assert open_(client, fid, rx).status_code == 200                              # right PIN: tries start again
    assert info(client, fid).json()["pin_tries_left"] == send.PIN_TRIES
    r = open_(client, fid, other)                                                 # not to be passed on
    assert r.status_code == 403 and "another device" in r.text
    assert open_(client, fid, rx).status_code == 200                              # the first device again: 2 of 3
    stale = {"auth": send.b64u(b"A" * 32), "pin_proof": "aa" * 32, "device_pub": rx.pub, **rx.sign("open", fid, int(time.time()) - 900)}
    assert client.post(API + f"/files/{fid}/open", json=stale, headers=H).status_code == 403   # old signature
    for i in range(send.PIN_TRIES):
        r = open_(client, fid, rx, pin_tag="cc" * 32)
    assert r.status_code == 410 and "destroyed" in r.text
    assert info(client, fid).json()["reason"] == "too many wrong PINs" and not (tmp / "send" / f"{fid}.bin").exists()
    # A file that may be passed on opens on any device with link and PIN.
    fid2, _ = make(client, owner, max_opens=0, forward=True)
    assert open_(client, fid2, rx).status_code == 200 and open_(client, fid2, other).status_code == 200
    assert info(client, fid2).json()["state"] == "live"


def test_the_sender_takes_a_file_back_and_time_ends_it(app):
    client, a, tmp = app
    owner, rx = Device(), Device()
    fid, _ = make(client, owner, max_opens=0)
    tok = open_(client, fid, rx).json()["token"]
    assert client.post(API + f"/files/{fid}/revoke", json=rx.sign("revoke", fid), headers=H).status_code == 403
    assert client.post(API + f"/files/{fid}/revoke", json=owner.sign("status", fid), headers=H).status_code == 403
    assert client.post(API + f"/files/{fid}/revoke", json=owner.sign("revoke", fid), headers=H).json()["state"] == "dead"
    assert info(client, fid).json()["reason"] == "taken back by the sender"
    assert open_(client, fid, rx).status_code == 410
    assert client.get(API + f"/files/{fid}/parts/0", headers={"X-Send-Token": tok}).status_code == 403   # a running download stops too
    assert not (tmp / "send" / f"{fid}.bin").exists()
    # Expiry.
    fid2, _ = make(client, owner, max_opens=0)
    a.state.send_sweep(int(time.time()) + 86400 - 5)
    assert info(client, fid2).json()["state"] == "live"
    a.state.send_sweep(int(time.time()) + 86400 + 5)
    assert a.state.store.one("SELECT reason, keeper_share FROM send_files WHERE id=?", (fid2,))["reason"] == "expired"
    # An upload that is never finished is dropped.
    fid3 = os.urandom(16).hex()
    body = {"id": fid3, "size": 10 + send.TAG, "parts": 1, "keep": 86400, "max_opens": 1, "auth_hash": "aa" * 32, "pin_tag": "aa" * 32,
            "owner_pub": owner.pub, "keeper_share": send.b64u(b"S" * 32), "preview": send.b64u(b"p"), "meta": send.b64u(b"m")}
    assert client.post(API + "/files", json=body, headers=H).status_code == 200
    assert client.post(API + "/files", json=body, headers=H).status_code == 409                       # same id twice
    assert info(client, fid3, auth=b"A" * 32).status_code == 403                                      # (its auth differs)
    a.state.send_sweep(int(time.time()) + send.UPLOAD_WINDOW + 5)
    assert a.state.store.one("SELECT state FROM send_files WHERE id=?", (fid3,))["state"] == "dead"


def test_fading_halves_the_chance_each_half_life(app):
    import random
    client, a, tmp = app
    rng = random.Random(7)
    ends = [send.fade_moment(0, 86400, 7 * 86400, rng) for _ in range(20000)]
    alive = lambda t: sum(e > t for e in ends) / len(ends)                       # noqa: E731
    assert abs(alive(86400) - 0.5) < 0.02 and abs(alive(2 * 86400) - 0.25) < 0.02 and alive(7 * 86400) == 0
    owner = Device()
    fid, _ = make(client, owner, fade=True, max_opens=0)
    row = a.state.store.one("SELECT die_at, expires_at, half_life FROM send_files WHERE id=?", (fid,))
    assert row["half_life"] == 86400 and row["die_at"] <= row["expires_at"]
    assert info(client, fid).json()["fade"] is True and "die_at" not in info(client, fid).json()     # nobody is told when
    a.state.send_sweep(row["die_at"] + 1)
    assert a.state.store.one("SELECT reason FROM send_files WHERE id=?", (fid,))["reason"] in ("faded", "expired")


def test_limits_sizes_and_pages(app, monkeypatch):
    client, a, tmp = app
    owner = Device()
    lim = client.get(API + "/limits").json()
    assert lim["max_bytes"] == 9 << 20 and lim["free_keep"] == 7 * 86400 and lim["part"] == send.PART and lim["tier"] == "all"
    base = {"id": os.urandom(16).hex(), "parts": 3, "keep": 86400, "max_opens": 1, "auth_hash": "aa" * 32, "pin_tag": "aa" * 32,
            "owner_pub": owner.pub, "keeper_share": send.b64u(b"S" * 32), "preview": send.b64u(b"p"), "meta": send.b64u(b"m")}
    assert client.post(API + "/files", json={**base, "size": (10 << 20) + 3 * send.TAG}, headers=H).status_code == 413   # too large
    assert client.post(API + "/files", json={**base, "size": 100, "parts": 2}, headers=H).status_code == 422             # sizes disagree
    assert client.post(API + "/files", json={**base, "size": 100, "parts": 1, "keep": 400 * 86400}, headers=H).status_code == 422
    assert client.post(API + "/files", json={**base, "size": 100, "parts": 1, "max_opens": 1001}, headers=H).status_code == 422
    assert client.post(API + "/files", json={**base, "size": 20000, "parts": 1, "kind": "note"}, headers=H).status_code == 413
    assert client.post(API + "/files", json={**base, "size": 100, "parts": 1, "keeper_share": "AAAA"}, headers=H).status_code == 422
    r = client.post(API + "/files", json={**base, "size": 100, "parts": 1}, headers=H)
    assert r.status_code == 200
    up = {**H, "X-Send-Upload": r.json()["upload"]}
    assert client.put(API + f"/files/{base['id']}/parts/0", content=b"x" * 99, headers=up).status_code == 422           # wrong length
    assert client.put(API + f"/files/{base['id']}/parts/0", content=b"x" * 100, headers={**H, "X-Send-Upload": send.b64u(b"n" * 32)}).status_code == 403
    assert client.put(API + f"/files/{base['id']}/parts/1", content=b"x" * 100, headers=up).status_code == 409           # out of order
    assert client.put(API + f"/files/{base['id']}/parts/0", content=b"x" * 100, headers=up).json()["live"] is True
    assert client.put(API + f"/files/{base['id']}/parts/0", content=b"x" * 100, headers=up).status_code == 409           # already complete
    monkeypatch.setenv("INNERNET_SEND_TOTAL_GB", "0")
    assert client.post(API + "/files", json={**base, "id": os.urandom(16).hex(), "size": 100, "parts": 1}, headers=H).status_code == 507
    monkeypatch.setenv("INNERNET_SEND", "0")
    assert client.post(API + "/files", json={**base, "id": os.urandom(16).hex(), "size": 100, "parts": 1}, headers=H).status_code == 503
    for url in ("/send", "/send/o/" + "ab" * 16):
        page = client.get(P + url)
        assert page.status_code == 200 and "send-core.js?v=" in page.text and "Content-Security-Policy" in page.headers


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_browser_sealing_round_trip_in_node():
    script = r"""
const C = require(process.argv[1]);
(async () => {
  const id = C.newId(), secret = C.random(32), share = C.random(32), pin = C.newPin();
  const out = { pin: /^[0-9]{6}$/.test(pin) };
  const key = await C.fileKey(secret, share, pin, id);
  const data = new Uint8Array(require('crypto').randomBytes(C.PART + 77)), parts = C.partCount(data.length);
  const sealed = [];
  for (let n = 0; n < parts; n++) sealed.push(await C.sealPart(key, id, n, parts, data.subarray(n * C.PART, (n + 1) * C.PART)));
  out.sizes = sealed.map(s => s.length);
  const again = await C.fileKey(secret, share, pin, id);
  const plain = [];
  for (let n = 0; n < parts; n++) plain.push(Buffer.from(await C.openPart(again, id, n, parts, sealed[n])));
  out.same = Buffer.compare(Buffer.concat(plain), Buffer.from(data)) === 0;
  const refuses = async (f) => { try { await f(); return false; } catch (e) { return true; } };
  const other = String((Number(pin) + 1) % 1000000).padStart(6, '0');
  out.wrongPin = await refuses(async () => C.openPart(await C.fileKey(secret, share, other, id), id, 0, parts, sealed[0]));
  out.wrongShare = await refuses(async () => C.openPart(await C.fileKey(secret, C.random(32), pin, id), id, 0, parts, sealed[0]));
  out.wrongLink = await refuses(async () => C.openPart(await C.fileKey(C.random(32), share, pin, id), id, 0, parts, sealed[0]));
  out.swapped = await refuses(() => C.openPart(again, id, 0, parts, sealed[1]));
  out.cutShort = await refuses(() => C.openPart(again, id, 0, 1, sealed[0]));
  const keys = await C.linkKeys(secret, id);
  out.preview = (await C.openSmall(keys.preview, id, 'preview', await C.sealSmall(keys.preview, id, 'preview', { from: 'Asma' }))).from;
  out.authHash = keys.authHash; out.auth = C.b64u(keys.auth); out.tag = await C.pinTag(keys, pin);
  const d = await C.newDeviceKey(true);
  out.pub = await C.publicRaw(d); out.id = id; out.signed = await C.signRequest(d, 'open', id);
  console.log(JSON.stringify(out));
})();
"""
    core = ROOT / "innernet2/registry_service/static/send-core.js"
    res = subprocess.run(["node", "-e", script, str(core)], capture_output=True, text=True, timeout=120)
    assert res.returncode == 0, res.stderr
    out = json.loads(res.stdout)
    assert out["pin"] and out["same"] and out["sizes"] == [send.PART + send.TAG, 77 + send.TAG]
    assert out["wrongPin"] and out["wrongShare"] and out["wrongLink"] and out["swapped"] and out["cutShort"]
    assert out["preview"] == "Asma" and len(out["tag"]) == 64
    assert hashlib.sha256(send.unb64u(out["auth"], 32)).hexdigest() == out["authHash"]
    # The keeper accepts the signature a browser makes.
    assert send.verify(out["pub"], "open", out["id"], out["signed"]["ts"], out["signed"]["sig"])
    assert not send.verify(out["pub"], "revoke", out["id"], out["signed"]["ts"], out["signed"]["sig"])


def test_the_operator_can_destroy_a_file_but_not_read_it(app, monkeypatch, capsys):
    from innernet2.registry_service import admin
    client, a, tmp = app
    fid, _ = make(client, Device(), max_opens=0)
    monkeypatch.setenv("INNERNET_REGISTRY_DB", str(tmp / "registry.db"))
    assert admin.main(["send-list"]) == 0 and fid in capsys.readouterr().out
    assert admin.main(["send-remove", fid, "abuse report 14"]) == 0
    assert admin.main(["send-remove", fid, "again"]) == 1
    assert info(client, fid).json()["reason"] == "removed by the operator: abuse report 14"
    assert open_(client, fid, Device()).status_code == 410 and not (tmp / "send" / f"{fid}.bin").exists()


def test_the_free_send_is_one_file_or_note_opened_once_with_no_settings(tmp_path, monkeypatch):
    monkeypatch.delenv("INNERNET_SEND_ALL_RULES", raising=False)
    monkeypatch.delenv("INNERNET_SEND_MAX_MB", raising=False)
    a = create_app(settings(tmp_path), rpc=FakeChain(), connect=lambda h, p, t: 3.0)      # no receiving address on Base
    client = TestClient(a, base_url=ORIGIN)
    lim = client.get(API + "/limits").json()
    assert lim["tier"] == "free" and lim["max_bytes"] == 10 << 20 and lim["free_keep"] == 7 * 86400 and not lim["paid"]["on"]
    owner, rx, other = Device(), Device(), Device()
    base = {"size": 100, "parts": 1, "auth_hash": hashlib.sha256(b"A" * 32).hexdigest(),
            "pin_tag": "aa" * 32, "owner_pub": owner.pub, "keeper_share": send.b64u(b"S" * 32),
            "preview": send.b64u(b"p"), "meta": send.b64u(b"m")}
    new = lambda **kw: client.post(API + "/files", json={**base, "id": os.urandom(16).hex(), **kw}, headers=H)   # noqa: E731
    for paid in ({"max_opens": 3}, {"max_opens": 0}, {"forward": True}, {"keep": 8 * 86400}, {"receipt": True},
                 {"reply": True}, {"control": True}, {"open_after": int(time.time()) + 86400}):
        r = new(**paid)
        assert r.status_code == 402 and "not switched on" in r.text, (paid, r.text)
    assert new(size=(11 << 20) + 3 * send.TAG, parts=3).status_code == 413            # over 10 MB
    r = new(kind="note")
    fid = r.json()["id"]
    assert r.json()["pay"] is None and r.json()["lines"] == []
    assert client.put(API + f"/files/{fid}/parts/0", content=b"x" * 100, headers={**H, "X-Send-Upload": r.json()["upload"]}).json()["live"]
    assert client.post(API + f"/files/{fid}/revoke", json=owner.sign("revoke", fid), headers=H).status_code == 402   # no sender controls
    first = open_(client, fid, rx).json()
    assert first["last"] is True and first["kind"] == "note" and first["reply_on"] is False
    assert open_(client, fid, rx).status_code == 410 and open_(client, fid, other).status_code == 410   # strictly once
    st = client.post(API + f"/files/{fid}/status", json=owner.sign("status", fid), headers=H).json()      # the sender still sees it
    assert st["state"] == "spent" and [(e["event"], bool(e["ts"])) for e in st["events"]] == [("sent", True), ("opened", False)]
    stats = client.get(API + "/stats").json()
    assert stats["sent"] == 1 and stats["opened"] == 1 and stats["bytes"] == 100 and stats["paid"] == 0


class PayChain(FakeChain):
    def __call__(self, url, method, params):
        if method == "eth_getTransactionReceipt":
            logs = [dict(x, address=USDC[SEPOLIA]) for x in self.logs if x["transactionHash"] == params[0]]
            return {"status": "0x1", "logs": logs} if logs else None
        return super().__call__(url, method, params)


def test_everything_added_is_paid_upfront_and_a_send_is_extended_or_destroyed(tmp_path, monkeypatch):
    monkeypatch.delenv("INNERNET_SEND_ALL_RULES", raising=False)
    monkeypatch.setenv("INNERNET_SEND_NETWORK", SEPOLIA)
    chain = PayChain()
    a = create_app(settings(tmp_path), rpc=chain, connect=lambda h, p, t: 3.0)
    client = TestClient(a, base_url=ORIGIN)
    lim = client.get(API + "/limits").json()
    assert lim["tier"] == "paid" and lim["paid"]["on"] and lim["paid"]["to"] == FEE_WALLET
    owner, rx = Device(), Device()
    opts = {"keep": 30 * 86400, "max_opens": 3, "receipt": True, "reply": True, "control": True, "forward": True}
    q = client.post(API + "/quote", json={"plain": 20 << 20, **opts}, headers=H).json()
    # 100 MB tier 0.05 + 30 days 0.05 + 2 more openings 0.02 + passing on 0.05 + receipt 0.03 + reply 0.05 + take back 0.05
    assert q["micro"] == 300_000 and q["total"] == "0.300000" and len(q["lines"]) == 7
    assert client.post(API + "/quote", json={"plain": 100}, headers=H).json()["micro"] == 0
    plain = 84
    body = {"id": os.urandom(16).hex(), "size": plain + send.TAG, "parts": 1, "auth_hash": hashlib.sha256(b"A" * 32).hexdigest(),
            "pin_tag": "aa" * 32, "owner_pub": owner.pub, "keeper_share": send.b64u(b"S" * 32),
            "preview": send.b64u(b"p"), "meta": send.b64u(b"m"), **opts}
    r = client.post(API + "/files", json=body, headers=H).json()
    fid, pay = r["id"], r["pay"]
    assert 250_000 < pay["micro"] < 251_000 and pay["to"] == FEE_WALLET and pay["chain_id"] == 84532      # price + identifying digits
    up = {**H, "X-Send-Upload": r["upload"]}
    assert client.put(API + f"/files/{fid}/parts/0", content=b"x" * 100, headers=up).status_code == 402    # paid before upload
    check = lambda **kw: client.post(API + f"/files/{fid}/pay", json={**owner.sign("pay", fid), **kw}, headers=H)   # noqa: E731
    assert check().json()["paid"] is False
    assert client.post(API + f"/files/{fid}/pay", json=rx.sign("pay", fid), headers=H).status_code == 403   # only the sender
    chain.pay(FEE_WALLET, pay["micro"] - 1, 990)                     # a different amount is not this payment
    assert check().json()["paid"] is False
    chain.pay(FEE_WALLET, pay["micro"], 995)
    paid = check().json()
    assert paid["paid"] is True and paid["state"] == "uploading" and paid["tx"] == chain.logs[-1]["transactionHash"]
    assert check().json()["paid"] is True
    assert client.put(API + f"/files/{fid}/parts/0", content=b"x" * 100, headers=up).json()["live"] is True
    # The paid rules work: opening time is shown, one sealed reply comes back, the sender can take it back.
    rel = open_(client, fid, rx).json()
    assert rel["last"] is False and rel["reply_on"] is True
    tok = {**H, "X-Send-Token": rel["token"]}
    assert client.post(API + f"/files/{fid}/reply", json={"sealed": send.b64u(b"thanks")}, headers=tok).status_code == 200
    assert client.post(API + f"/files/{fid}/reply", json={"sealed": send.b64u(b"again")}, headers=tok).status_code == 409
    st = client.post(API + f"/files/{fid}/status", json=owner.sign("status", fid), headers=H).json()
    assert st["reply"] == send.b64u(b"thanks") and st["paid"] == pay["amount"] and all(e["ts"] for e in st["events"])
    # Extending: priced, paid the same way (here named by its transaction), then the end moves.
    ext = client.post(API + f"/files/{fid}/extend", json={**owner.sign("extend", fid), "days": 30}, headers=H).json()
    assert 50_000 < ext["pay"]["micro"] < 51_000 and check().json()["paid"] is False
    chain.pay(FEE_WALLET, ext["pay"]["micro"], 998)
    done = check(tx=chain.logs[-1]["transactionHash"]).json()
    assert done["paid"] is True and done["expires_at"] == st["expires_at"] + 30 * 86400
    chain.pay(FEE_WALLET, ext["pay"]["micro"], 999)                  # the same transaction is never counted twice
    assert client.post(API + f"/files/{fid}/extend", json={**owner.sign("extend", fid), "days": 400}, headers=H).status_code == 422
    stats = client.get(API + "/stats").json()
    assert stats["paid"] == 2 and stats["paid_usdc"] == send.usdc(pay["micro"] + ext["pay"]["micro"])
    # Unextended, it is destroyed at its end; taking it back works because it was paid for.
    a.state.send_sweep(done["expires_at"] - 10)
    assert info(client, fid).json()["state"] == "live"
    assert client.post(API + f"/files/{fid}/revoke", json=owner.sign("revoke", fid), headers=H).json()["state"] == "dead"
    # An opening date holds the keeper part; an unpaid price lapses.
    later = int(time.time()) + 3 * 86400
    r2 = client.post(API + "/files", json={**body, "id": os.urandom(16).hex(), "open_after": later, "keep": 7 * 86400, "max_opens": 1,
                                           "receipt": False, "reply": False, "control": False, "forward": False}, headers=H).json()
    assert 50_000 < r2["pay"]["micro"] < 51_000
    a.state.send_sweep(int(time.time()) + send.PAY_WINDOW + send.PAY_GRACE + 5)
    gone = client.post(API + f"/files/{r2['id']}/status", json=owner.sign("status", r2["id"]), headers=H).json()
    assert gone["state"] == "dead" and gone["reason"] == "not paid"
