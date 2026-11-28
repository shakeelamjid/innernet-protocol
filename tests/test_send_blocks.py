"""INNERNET Send: the general blocks (who adds, who opens, when, what comes back), keeper side."""
import hashlib
import json
import os
import re
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi.testclient import TestClient

from innernet2.registry_service import send
from innernet2.registry_service.app import create_app
from tests.test_registry_service import FEE_WALLET, ORIGIN, SEPOLIA, FakeChain, settings
from tests.test_send import API, H, Device, PayChain, info, make, open_

h64 = lambda b: hashlib.sha256(b).hexdigest()   # noqa: E731
TAG = "bb" * 32


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("INNERNET_SEND_ALL_RULES", "1")
    a = create_app(settings(tmp_path), rpc=FakeChain(), connect=lambda h, p, t: 3.0)
    a.state.calls = []
    a.state.send_http = lambda url, data=None: (a.state.calls.append((url, data)), a.state.pages.get(url, ""))[1]
    a.state.pages = {}
    return TestClient(a, base_url=ORIGIN), a, tmp_path


def status(client, fid, owner):
    return client.post(API + f"/files/{fid}/status", json=owner.sign("status", fid), headers=H).json()


def checked(signed):
    raw = json.dumps(signed["record"], sort_keys=True, separators=(",", ":")).encode()
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(signed["key"])).verify(send.unb64u(signed["sig"]), raw)
    return signed["record"]


def test_named_recipients_and_passing_on_to_the_next_person(app):
    client, a, tmp = app
    owner, d1, d2, d3 = Device(), Device(), Device(), Device()
    now = int(time.time())
    recs = [{"pin_tag": "11" * 32, "wrap": send.b64u(b"w1" * 24)}, {"pin_tag": "22" * 32, "wrap": send.b64u(b"w2" * 24)}]
    fid, _ = make(client, owner, keep=30 * 86400, max_opens=2, recipients=recs)
    assert info(client, fid).json()["named"] == 2
    assert open_(client, fid, d1, pin_tag="aa" * 32).status_code == 403            # the file-level PIN opens nothing
    one = open_(client, fid, d1, pin_tag="11" * 32).json()
    assert one["wrap"] == recs[0]["wrap"] and one["who"] == 0 and one["last"] is False
    assert open_(client, fid, d3, pin_tag="11" * 32).status_code == 403            # that PIN is bound to its first device
    assert open_(client, fid, d2, pin_tag="22" * 32).json()["last"] is True
    assert [e["event"] for e in status(client, fid, owner)["events"]][-2:] == ["opened by recipient 1", "opened by recipient 2"]
    # Succession: the second PIN works only after the first one's time, and only if the first did not claim.
    chain = [{"pin_tag": "11" * 32, "wrap": send.b64u(b"w1" * 24), "until": now + 5 * 86400},
             {"pin_tag": "22" * 32, "wrap": send.b64u(b"w2" * 24), "after": now + 5 * 86400, "unless": 0}]
    f2, _ = make(client, owner, keep=30 * 86400, max_opens=1, recipients=chain, succession=True)
    assert open_(client, f2, d2, pin_tag="22" * 32).status_code == 403 and "not valid yet" in open_(client, f2, d2, pin_tag="22" * 32).text
    a.state.send_store.x("UPDATE send_recipients SET until=? WHERE file=? AND idx=0", (now - 10, f2))
    a.state.send_store.x("UPDATE send_recipients SET after=? WHERE file=? AND idx=1", (now - 10, f2))
    assert "has passed" in open_(client, f2, d1, pin_tag="11" * 32).text
    assert open_(client, f2, d2, pin_tag="22" * 32).json()["who"] == 1
    f3, _ = make(client, owner, keep=30 * 86400, max_opens=2, recipients=[chain[0], {**chain[1], "after": 0}])
    assert open_(client, f3, d1, pin_tag="11" * 32).status_code == 200
    assert "already claimed" in open_(client, f3, d2, pin_tag="22" * 32).text


def test_approvers_release_without_reading_and_a_witness_gets_the_signed_record(app):
    client, a, tmp = app
    owner, rx = Device(), Device()
    toks, wit = [os.urandom(32) for _ in range(3)], os.urandom(32)
    fid, _ = make(client, owner, keep=30 * 86400, approvers={"need": 2, "hashes": [h64(t) for t in toks]}, witness_hash=h64(wit),
                  extras={"record": True, "alarm_url": "https://hooks.example/x"})
    assert "0 of 2" in open_(client, fid, rx).text
    ap = lambda i, **kw: client.post(API + f"/files/{fid}/approve", json={"idx": i, "token": send.b64u(toks[i]), **kw}, headers=H)   # noqa: E731
    assert client.post(API + f"/files/{fid}/approve", json={"idx": 0, "token": send.b64u(toks[1]), "approve": True}, headers=H).status_code == 403
    assert ap(0).json()["have"] == 0 and ap(0, approve=True).json()["have"] == 1
    assert "keeper_share" not in ap(0).json() and open_(client, fid, rx).status_code == 403
    assert ap(2, approve=True).json()["who"] == [True, False, True]
    assert open_(client, fid, rx).status_code == 200
    w = client.post(API + f"/files/{fid}/witness", json={"token": send.b64u(wit)}, headers=H).json()
    assert w["approvals"]["have"] == 2 and "keeper_share" not in w
    rec = checked(w["signed"])
    assert rec["opened"] == 1 and rec["send"] == fid and len(rec["seal_sha256"]) == 64 and rec["sealed_at"] <= rec["issued_at"]
    assert client.post(API + f"/files/{fid}/witness", json={"token": send.b64u(toks[0])}, headers=H).status_code == 403
    assert checked(client.post(API + f"/files/{fid}/record", json={"auth": send.b64u(b"A" * 32)}, headers=H).json())["opened"] == 1
    assert checked(client.post(API + f"/files/{fid}/record", json=owner.sign("record", fid), headers=H).json())["state"] == "spent"
    assert [c[1]["event"] for c in a.state.calls if c[0] == "https://hooks.example/x"] == ["approved by approver 1", "approved by approver 3", "opened"]
    # Never opened: the record says so.
    f2, _ = make(client, owner, control=True)
    client.post(API + f"/files/{f2}/revoke", json=owner.sign("revoke", f2), headers=H)
    never = checked(client.post(API + f"/files/{f2}/record", json=owner.sign("record", f2), headers=H).json())
    assert never["opened"] == 0 and never["state"] == "dead" and never["reason"] == "taken back by the sender"
    assert client.post(API + f"/files/{f2}/record", json={"auth": send.b64u(b"A" * 32)}, headers=H).status_code == 403


def test_duress_pin_recovery_code_link_name_origin_and_display_rules(app):
    client, a, tmp = app
    owner, rx, new = Device(), Device(), Device()
    code = os.urandom(32)
    fid = os.urandom(16).hex()
    body = {"id": fid, "size": 100 + send.TAG, "parts": 1, "keep": 30 * 86400, "max_opens": 3, "auth_hash": h64(b"A" * 32), "pin_tag": "aa" * 32,
            "owner_pub": owner.pub, "keeper_share": send.b64u(b"S" * 32), "preview": send.b64u(b"p"), "meta": send.b64u(b"m"),
            "summary": send.b64u(b"sealed summary"), "recover_hash": h64(code),
            "duress": {"pin_tag": TAG, "share": send.b64u(b"D" * 32), "meta": send.b64u(b"dm"), "size": 40},
            "extras": {"recovery": True, "view_only": True, "view_secs": 120, "card": "gift", "name": "acme-tender", "origin": "example.com",
                       "alarm_url": "https://hooks.example/y", "qr": True}}
    r = client.post(API + "/files", json=body, headers=H)
    assert r.status_code == 200, r.text
    up = {**H, "X-Send-Upload": r.json()["upload"]}
    assert client.put(API + f"/files/{fid}/decoy", content=b"x" * 39, headers=up).status_code == 422
    assert client.put(API + f"/files/{fid}/decoy", content=b"decoy" * 8, headers=up).status_code == 200
    assert client.put(API + f"/files/{fid}/parts/0", content=b"r" * (100 + send.TAG), headers=up).json()["live"]
    i = info(client, fid).json()
    assert i["extras"] == {"view_only": 1, "view_secs": 120, "card": "gift", "qr": 1, "name": "acme-tender"} and i["summary"] == body["summary"]
    assert i["origin"] is None and i["origin_pending"] == "example.com"
    assert client.get(API + "/names/acme-tender").json() == {"id": fid} and client.get(API + "/names/none").status_code == 404
    assert client.post(API + "/files", json={**body, "id": os.urandom(16).hex()}, headers=H).status_code == 409       # the name is taken
    # The duress PIN looks like an opening, gives the decoy, and tells the sender.
    d = open_(client, fid, rx, pin_tag=TAG).json()
    assert d["keeper_share"] == send.b64u(b"D" * 32) and d["meta"] == send.b64u(b"dm") and d["parts"] == 1 and set(d) == set(open_(client, fid, rx).json()) - {"wrap", "who"}
    assert client.get(API + f"/files/{fid}/parts/0", headers={"X-Send-Token": d["token"]}).content == b"decoy" * 8
    st = status(client, fid, owner)
    assert "duress PIN used" in [e["event"] for e in st["events"]] and ("https://hooks.example/y", "duress PIN used") in [(c[0], c[1]["event"]) for c in a.state.calls]
    # Origin: the domain must publish the sender's device key.
    assert client.post(API + f"/files/{fid}/origin", json=owner.sign("origin", fid), headers=H).status_code == 422
    a.state.pages["https://example.com/.well-known/innernet-send.txt"] = "keys:\n" + owner.pub + "\n"
    assert client.post(API + f"/files/{fid}/origin", json=owner.sign("origin", fid), headers=H).json() == {"origin": "example.com"}
    assert info(client, fid).json()["origin"] == "example.com"
    # Recovery: control moves to another device with the code.
    move = lambda c, dev: client.post(API + f"/files/{fid}/recover", json={"code": send.b64u(c), "owner_pub": dev.pub, **dev.sign("recover", fid)}, headers=H)   # noqa: E731
    assert move(os.urandom(32), new).status_code == 403 and move(code, new).status_code == 200
    assert client.post(API + f"/files/{fid}/status", json=owner.sign("status", fid), headers=H).status_code == 403
    assert status(client, fid, new)["state"] == "live"


def test_others_add_and_replace_until_it_opens_then_all_open_together(app):
    client, a, tmp = app
    owner, b1, b2, b3 = Device(), Device(), Device(), Device()
    now = int(time.time())
    fid, _ = make(client, owner, keep=30 * 86400, max_opens=0, forward=True, open_after=now + 3 * 86400,
                  collect={"audience": "all", "seats": 2, "form": send.b64u(b"form")})
    assert open_(client, fid, b1).status_code == 200                                # the documents themselves open at once
    put = lambda dev, data, f=fid: client.put(API + f"/files/{f}/adds", content=data, headers={   # noqa: E731
        **H, "X-Send-Auth": send.b64u(b"A" * 32), "X-Send-Device": dev.pub, "X-Send-Ts": str(dev.sign("add", f)["ts"]), "X-Send-Sig": dev.sign("add", f)["sig"]})
    lst = lambda dev=None, f=fid, **kw: client.post(API + f"/files/{f}/adds/list", json={"auth": send.b64u(b"A" * 32), "device_pub": dev.pub if dev else "", **kw}, headers=H).json()   # noqa: E731
    r1 = checked(put(b1, b"bid one, sealed....").json())
    assert r1["entry"] == 1 and r1["changes"] == 0 and r1["sha256"] == h64(b"bid one, sealed....")
    assert checked(put(b1, b"bid one, changed...").json())["changes"] == 1      # replaced, not added
    assert put(b2, b"bid two, sealed....").status_code == 200 and put(b3, b"bid three, sealed..").status_code == 409   # two places
    before = lst(b1)
    assert before["count"] == 2 and before["revealed"] is False and before["entries"] is None and before["mine"]["changes"] == 1
    get = lambda n, body: client.post(API + f"/files/{fid}/adds/{n}", json=body, headers=H)   # noqa: E731
    assert get(1, {"auth": send.b64u(b"A" * 32)}).status_code == 403 and get(1, owner.sign("adds", fid)).status_code == 403   # not even the sender
    a.state.send_store.x("UPDATE send_files SET open_after=? WHERE id=?", (now - 5, fid))
    assert put(b1, b"too late, sealed...").status_code == 403                     # closed at the opening time
    after = lst()
    assert after["revealed"] and [e["changes"] for e in after["entries"]] == [1, 0]
    assert get(1, {"auth": send.b64u(b"A" * 32)}).content == b"bid one, changed..." and get(2, {"auth": send.b64u(b"A" * 32)}).content == b"bid two, sealed...."
    # An inbox: only the sender reads, at any time.
    f2, _ = make(client, owner, keep=30 * 86400, max_opens=0, forward=True, collect={"audience": "owner", "seats": 5, "pub": send.b64u(b"\x04" + b"k" * 64)})
    assert put(b1, b"a client's document", f2).status_code == 200
    assert lst(b2, f2)["entries"] is None and lst(b2, f2)["pub"] == send.b64u(b"\x04" + b"k" * 64)
    mine = client.post(API + f"/files/{f2}/adds/list", json=owner.sign("adds", f2), headers=H).json()
    assert mine["may_read"] and client.post(API + f"/files/{f2}/adds/1", json=owner.sign("adds", f2), headers=H).content == b"a client's document"
    # A swap: it opens to both only when both have added.
    f3, _ = make(client, owner, keep=30 * 86400, max_opens=0, forward=True, collect={"audience": "all", "seats": 2, "reveal_count": 2})
    put(b1, b"my half of the swap", f3)
    assert lst(b1, f3)["revealed"] is False
    put(b2, b"the other half.....", f3)
    assert lst(b1, f3)["revealed"] is True and len(lst(b1, f3)["entries"]) == 2


def test_payment_as_a_lock_new_versions_and_the_hand_on_chain(tmp_path, monkeypatch):
    monkeypatch.setenv("INNERNET_SEND_ALL_RULES", "1")
    monkeypatch.setenv("INNERNET_SEND_NETWORK", SEPOLIA)
    chain = PayChain()
    a = create_app(settings(tmp_path), rpc=chain, connect=lambda h, p, t: 3.0)
    client = TestClient(a, base_url=ORIGIN)
    owner, r1, r2 = Device(), Device(), Device()
    seller = "0x" + "5e" * 20
    fid, _ = make(client, owner, keep=30 * 86400, max_opens=0, forward=True, pay={"mode": "each", "price": "2", "to": seller, "buyers": 1},
                  extras={"versions": 1, "chain": True})
    assert open_(client, fid, r1).status_code == 402
    who = lambda dev: {"auth": send.b64u(b"A" * 32), "device_pub": dev.pub, **dev.sign("buy", fid)}   # noqa: E731
    q = client.post(API + f"/files/{fid}/buy", json=who(r1), headers=H).json()
    assert 2_000_000 < q["micro"] < 2_001_000 and q["to"] == seller
    assert client.post(API + f"/files/{fid}/buy/check", json=who(r1), headers=H).json()["access"] is False
    chain.pay(FEE_WALLET, q["micro"], 990)                              # paid to the wrong address: not counted
    assert client.post(API + f"/files/{fid}/buy/check", json=who(r1), headers=H).json()["access"] is False
    chain.pay(seller, q["micro"], 995)
    done = client.post(API + f"/files/{fid}/buy/check", json=who(r1), headers=H).json()
    assert done["access"] is True and done["sold"] == 1 and done["raised"] == send.usdc(q["micro"])
    assert client.post(API + f"/files/{fid}/info", json={"auth": send.b64u(b"A" * 32), "device_pub": r1.pub}, headers=H).json()["access"] is True
    assert client.post(API + f"/files/{fid}/buy", json=who(r2), headers=H).status_code == 409        # sold out
    rel = open_(client, fid, r1).json()
    assert open_(client, fid, r2).status_code == 402
    # Hand-on: whoever opened it can seal it on, and the chain is kept.
    child = os.urandom(16).hex()
    body = {"id": child, "size": 30 + send.TAG, "parts": 1, "keep": 86400, "auth_hash": hashlib.sha256(b"C" * 32).hexdigest(), "pin_tag": "aa" * 32,
            "owner_pub": r1.pub, "keeper_share": send.b64u(b"S" * 32), "preview": send.b64u(b"p"), "meta": send.b64u(b"m"), "parent": fid}
    assert client.post(API + "/files", json={**body, "parent_token": send.b64u(os.urandom(32))}, headers=H).status_code == 403
    made = client.post(API + "/files", json={**body, "parent_token": rel["token"]}, headers=H)
    assert made.status_code == 200
    client.put(API + f"/files/{child}/parts/0", content=b"c" * (30 + send.TAG), headers={**H, "X-Send-Upload": made.json()["upload"]})
    assert [c["id"] for c in info(client, child, auth=b"C" * 32).json()["chain"]] == [fid[:8]]
    # A new version on the same link: new keeper part, new sealed bytes.
    v = client.post(API + f"/files/{fid}/version", json={**owner.sign("version", fid), "size": 26, "parts": 1,
                                                        "keeper_share": send.b64u(b"N" * 32), "meta": send.b64u(b"m2")}, headers=H).json()
    assert client.put(API + f"/files/{fid}/vparts/0", content=b"v" * 26, headers={**H, "X-Send-Upload": v["upload"]}).json()["version"] == 2
    again = open_(client, fid, r1).json()
    assert again["keeper_share"] == send.b64u(b"N" * 32) and again["size"] == 26
    assert client.get(API + f"/files/{fid}/parts/0", headers={"X-Send-Token": again["token"]}).content == b"v" * 26
    assert client.post(API + f"/files/{fid}/version", json={**owner.sign("version", fid), "size": 26, "parts": 1,
                                                            "keeper_share": send.b64u(b"N" * 32), "meta": send.b64u(b"m2")}, headers=H).status_code == 402
    # A crowd lock opens for everyone once the target is reached.
    f2, _ = make(client, owner, keep=30 * 86400, max_opens=0, forward=True, pay={"mode": "crowd", "price": "1", "target": "3", "to": seller, "buyers": 10})
    who2 = lambda dev: {"auth": send.b64u(b"A" * 32), "device_pub": dev.pub, **dev.sign("buy", f2)}   # noqa: E731
    for dev, amt in ((r1, "1"), (r2, "2.5")):
        q2 = client.post(API + f"/files/{f2}/buy", json={**who2(dev), "amount": amt}, headers=H).json()
        chain.pay(seller, q2["micro"], 996)
        state = client.post(API + f"/files/{f2}/buy/check", json=who2(dev), headers=H).json()
    assert state["access"] is True and open_(client, f2, owner).status_code == 200      # open to all, payer or not


def test_every_block_has_a_price(tmp_path, monkeypatch):
    monkeypatch.delenv("INNERNET_SEND_ALL_RULES", raising=False)
    monkeypatch.setenv("INNERNET_SEND_NETWORK", SEPOLIA)
    client = TestClient(create_app(settings(tmp_path), rpc=FakeChain(), connect=lambda h, p, t: 3.0), base_url=ORIGIN)
    q = client.post(API + "/quote", headers=H, json={
        "plain": 100, "keep": 30 * 86400, "recipients": 3, "succession": True, "approvers": {"count": 3, "need": 2}, "duress": True,
        "summary": "x", "collect": {"seats": 4}, "pay": {"mode": "each", "price": "10", "to": "0x" + "5e" * 20, "buyers": 20},
        "extras": {"view_only": 1, "view_secs": 60, "presence": 1, "card": "gift", "alarm_url": "https://x.example/h", "record": 1, "witness": 1,
                   "origin": "example.com", "name": "my-name", "chain": 1, "qr": 1, "recovery": 1, "versions": 2}}).json()
    got = {l["label"]: l["usdc"] for l in q["lines"]}
    assert len(got) == 20 and got["Payment lock, listing fee (5% of what it can take in)"] == "10.000000" and got["4 people can add to it"] == "2.000000"
    assert q["micro"] == sum(round(float(v) * 1e6) for v in got.values())


def test_the_sender_key_controls_a_send_from_any_device(app):
    client, a, tmp = app
    owner, rx = Device(), Device()
    code, now = os.urandom(32), int(time.time())
    key = {"code": send.b64u(code)}                           # what a device that only has the sender key sends
    fid, _ = make(client, owner, keep=30 * 86400, max_opens=5, open_after=now + 86400, open_until=now + 10 * 86400, recover_hash=h64(code))
    post = lambda path, **kw: client.post(API + f"/files/{fid}/{path}", json={**key, **kw}, headers=H)   # noqa: E731
    assert client.post(API + f"/files/{fid}/status", json={"code": send.b64u(os.urandom(32))}, headers=H).status_code == 403
    st = post("status").json()
    assert st["state"] == "live" and st["has_key"] and st["paused"] is False
    # The sender's own pack, sealed by them, readable only with the sender key.
    assert post("pack").status_code == 404 and post("pack", pack=send.b64u(b"sealed pack")).status_code == 200
    assert post("pack").json()["pack"] == send.b64u(b"sealed pack")
    assert client.post(API + f"/files/{fid}/pack", json=rx.sign("pack", fid), headers=H).status_code == 403
    # Check in, change the rules while it is waiting, pause and resume, then delete.
    ed = post("edit", open_after=now + 2 * 86400, open_until=now + 5 * 86400, max_opens=2).json()
    assert ed["open_after"] == now + 2 * 86400 and ed["open_until"] == now + 5 * 86400 and ed["max_opens"] == 2
    assert post("edit", checkin_days=14).status_code == 402
    assert post("edit", max_opens=3).status_code == 422 and post("edit", open_after=now - 5).status_code == 422 and post("edit").status_code == 422
    assert post("edit", open_after=0, preview=send.b64u(b"new line")).json()["open_after"] == 0
    assert post("edit", open_after=now + 86400).status_code == 402          # once dropped, it is not part of the send any more
    assert post("pause", on=True).json() == {"paused": True}
    assert "paused" in open_(client, fid, rx).text and info(client, fid).json()["paused"] is True
    assert post("pause", on=False).json() == {"paused": False} and open_(client, fid, rx).status_code == 200
    assert post("revoke").json()["state"] == "dead"
    assert [e["event"] for e in post("status").json()["events"]][-1] == "ended: taken back by the sender"
    f2, _ = make(client, owner)                                              # every send can be taken back, free
    assert client.post(API + f"/files/{f2}/revoke", json=owner.sign("revoke", f2), headers=H).json()["state"] == "dead"
    f3, _ = make(client, owner, keep=30 * 86400, checkin_days=7, recover_hash=h64(code))
    assert client.post(API + f"/files/{f3}/checkin", json=key, headers=H).json()["checkin_due"] >= now + 7 * 86400 - 5
    assert client.post(API + f"/files/{f3}/edit", json={**key, "checkin_days": 14}, headers=H).json()["checkin_every"] == 14 * 86400


def test_only_a_device_the_sender_approved_can_open_it(app):
    client, a, tmp = app
    owner, right, wrong = Device(), Device(), Device()
    fid, _ = make(client, owner, keep=30 * 86400, max_opens=3, forward=True, extras={"device": True})
    ask = lambda dev, name: client.post(API + f"/files/{fid}/claim", headers=H, json={   # noqa: E731
        "auth": send.b64u(b"A" * 32), "device_pub": dev.pub, "name": name, **dev.sign("claim", fid)})
    assert "must approve this device first" in open_(client, fid, right).text          # link and PIN alone open nothing
    c1, c2 = ask(right, "Bilal").json(), ask(wrong, "Someone else").json()
    assert re.fullmatch(r"\d{4}", c1["code"]) and c1["approved"] is False and ask(right, "x").json()["code"] == c1["code"]
    seen = status(client, fid, owner)["claims"]
    assert sorted((c["name"], c["code"], c["approved"]) for c in seen) == [("Bilal", c1["code"], 0), ("Someone else", c2["code"], 0)]
    decide = lambda dev, ok, who=owner: client.post(API + f"/files/{fid}/claims", json={**who.sign("claims", fid), "device": dev.pub, "ok": ok}, headers=H)   # noqa: E731
    assert decide(right, True, who=wrong).status_code == 403                           # only the sender decides
    assert decide(right, True).status_code == 200 and decide(wrong, False).status_code == 200
    assert client.post(API + f"/files/{fid}/info", json={"auth": send.b64u(b"A" * 32), "device_pub": right.pub}, headers=H).json()["claim"]["approved"] is True
    assert open_(client, fid, right).status_code == 200 and open_(client, fid, wrong).status_code == 403
