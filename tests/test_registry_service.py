"""Registry service (IRM-1 M1 part 2): apply, status, CLI login, passkeys, sessions, chain reads, probes."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import shutil
import socket
import struct
import subprocess
import threading
import time

import pytest

cbor2 = pytest.importorskip("cbor2")
pytest.importorskip("webauthn")

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from innernet2 import irm_registry as reg  # noqa: E402
from innernet2.irm_registry import LOGIN_DOMAIN, sign_descriptor, verify_registry  # noqa: E402
from innernet2.registry_service.terms import current as current_terms  # noqa: E402
from innernet2.mailbox_e2ee import canonical  # noqa: E402
from innernet2.registry_service import admin, chain, probe  # noqa: E402
from innernet2.registry_service.app import create_app  # noqa: E402
from innernet2.registry_service.config import USDC, Settings  # noqa: E402
from innernet2.registry_service.store import Store  # noqa: E402

ORIGIN = "https://innernetcorp.test"
RP = "innernetcorp.test"
SEPOLIA = "eip155:84532"
FEE_WALLET = "0x" + "fe" * 20
P = "/registry"
H = {"X-Innernet": "1"}


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class SoftAuthenticator:
    """Minimal software passkey (ES256, 'none' attestation), enough to drive the real WebAuthn checks."""

    def __init__(self, origin: str = ORIGIN):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(16)
        self.counter = 0
        self.origin = origin
        self.user_handle = b""

    def _cose(self) -> bytes:
        nums = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})

    def create(self, options: dict) -> dict:
        self.user_handle = unb64u(options["user"]["id"])
        rp_hash = hashlib.sha256(options["rp"]["id"].encode()).digest()
        self.counter += 1
        auth = (rp_hash + bytes([0x45]) + struct.pack(">I", self.counter) + bytes(16)
                + struct.pack(">H", len(self.cred_id)) + self.cred_id + self._cose())
        client = json.dumps({"type": "webauthn.create", "challenge": options["challenge"], "origin": self.origin,
                             "crossOrigin": False}).encode()
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth})
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(client), "attestationObject": b64u(att)},
                "clientExtensionResults": {}}

    def get(self, options: dict, rp_id: str = RP) -> dict:
        self.counter += 1
        auth = hashlib.sha256(rp_id.encode()).digest() + bytes([0x05]) + struct.pack(">I", self.counter)
        client = json.dumps({"type": "webauthn.get", "challenge": options["challenge"], "origin": self.origin,
                             "crossOrigin": False}).encode()
        sig = self.key.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(client), "authenticatorData": b64u(auth),
                             "signature": b64u(sig), "userHandle": b64u(self.user_handle)},
                "clientExtensionResults": {}}


class FakeChain:
    def __init__(self):
        self.head = 1000
        self.logs: list[dict] = []
        self.code = "0x6080"
        self.splits: dict[str, str] = {}          # receiver -> split (lower-case)

    def __call__(self, url, method, params):
        if method == "eth_blockNumber":
            return hex(self.head)
        if method == "eth_getCode":
            return self.code
        if method == "eth_getBlockByNumber":
            return {"timestamp": hex(int(time.time()) - 3600)}
        if method == "eth_call":
            to, data = params[0]["to"].lower(), params[0]["data"]
            sel, arg = data[2:10], data[10:]
            word = lambda v: "0x" + format(v, "064x")  # noqa: E731
            if sel == chain.SEL_SPLIT_OF:
                return word(int(self.splits.get("0x" + arg[-40:], "0x0"), 16))
            if sel == chain.SEL_IS_SPLIT:
                return word(1 if ("0x" + arg[-40:]) in self.splits.values() else 0)
            if sel == chain.SEL_FEE_RECIPIENT:
                return word(int(FEE_WALLET, 16))
            if sel == chain.SEL_FEE_BPS:
                return word(250)
            raise AssertionError(sel)
        if method == "eth_getLogs":
            f = params[0]
            lo, hi = int(f["fromBlock"], 16), int(f["toBlock"], 16)
            assert f["address"] == USDC[SEPOLIA] and f["topics"][0] == chain.TRANSFER_TOPIC
            return [x for x in self.logs if lo <= int(x["blockNumber"], 16) <= hi
                    and x["topics"][2] == f["topics"][2]]
        raise AssertionError(method)

    def pay(self, payto: str, amount: int, block: int):
        self.logs.append({"blockNumber": hex(block), "transactionHash": "0x" + os.urandom(32).hex(),
                          "logIndex": "0x0", "data": hex(amount),
                          "topics": [chain.TRANSFER_TOPIC, "0x" + "0" * 24 + "11" * 20, "0x" + "0" * 24 + payto[2:].lower()]})


def settings(tmp_path, **kw) -> Settings:
    key = tmp_path / "registry.key"
    if not key.exists():
        key.write_text(Ed25519PrivateKey.generate().private_bytes_raw().hex())
    s = Settings(db_path=str(tmp_path / "registry.db"), key_file=str(key), fee_payto={SEPOLIA: FEE_WALLET},
                 rpc={SEPOLIA: "http://rpc.invalid"}, origin=ORIGIN, rp_id=RP, login_host=RP, workers=False,
                 trust_proxy=False)
    for k, v in kw.items():
        setattr(s, k, v)
    return s


def provider_record(key: Ed25519PrivateKey, payto: str = "0x" + "ab" * 20, network: str = SEPOLIA,
                    host: str = "node1.example.test", port: int = 9443) -> dict:
    pid = key.public_key().public_bytes_raw().hex()
    entry = {"id": pid, "name": "lahore-box-1", "region": "asia-south", "endpoints": [{"host": host, "port": port}],
             "services": ["STO-1", "CMP-1"], "payto": {network: payto},
             "prices": {"STO-1": {"asset": "USDC", "unit": "GiB-day", "amount": "0.0010"},
                        "CMP-1": {"asset": "USDC", "unit": "CPU-hour", "amount": "0.0200"}},
             "limits": {"STO-1": {"max_storage_gib": 200}, "CMP-1": {"max_cpus": 4, "max_memory_mib": 2048}},
             "terms": current_terms("provider")["sha256"]}
    return sign_descriptor(entry, key)


def login_record(key: Ed25519PrivateKey, challenge: str, expires: int, host: str = RP) -> dict:
    payload = {"version": "REG-1-LOGIN", "provider": key.public_key().public_bytes_raw().hex(),
               "challenge": challenge, "registry": host, "expires_at": expires}
    return {"payload": payload, "signature": key.sign(LOGIN_DOMAIN + canonical(payload)).hex()}


@pytest.fixture
def env(tmp_path):
    fake = FakeChain()
    s = settings(tmp_path)
    app = create_app(s, rpc=fake, connect=lambda h, p, t: 3.0)
    client = TestClient(app, base_url=ORIGIN)
    return client, app.state.store, fake, s


def enroll(client, key) -> SoftAuthenticator:
    pid = key.public_key().public_bytes_raw().hex()
    ch = client.get(P + "/v1/login/challenge", params={"provider": pid}).json()
    r = client.post(P + "/v1/login", json=login_record(key, ch["challenge"], ch["expires_at"]))
    assert r.status_code == 200, r.text
    token = r.json()["url"].split("#t=")[1]
    assert r.json()["url"].startswith(ORIGIN + "/registry/enroll#t=")
    auth = SoftAuthenticator()
    opt = client.post(P + "/api/enroll/options", json={"token": token}, headers=H).json()
    v = client.post(P + "/api/enroll/verify", json={"flow": opt["flow"], "credential": auth.create(opt["options"]),
                                                    "name": "Laptop"}, headers=H)
    assert v.status_code == 200, v.text
    # The one-time link cannot be used twice.
    again = client.post(P + "/api/enroll/options", json={"token": token}, headers=H)
    assert again.status_code == 401
    return auth


def test_apply_and_status(env):
    client, store, fake, _ = env
    key = Ed25519PrivateKey.generate()
    r = client.post(P + "/v1/apply", json=provider_record(key))
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "testing"
    st = client.get(P + f"/v1/providers/{r.json()['provider']}/status").json()
    assert st["state"] == "testing" and st["health"]["uptime_7d"] == "n/a"
    assert st["earnings"] == {"asset": "USDC", "gross_30d": "0.00", "fee_30d": "0.00", "net_30d": "0.00"}
    assert client.get(P + "/v1/providers/" + "00" * 32 + "/status").status_code == 404


def test_apply_rejections(env):
    client, store, fake, _ = env
    key = Ed25519PrivateKey.generate()
    rec = provider_record(key)
    rec["payload"]["provider"]["prices"]["STO-1"]["amount"] = "0.0001"
    assert client.post(P + "/v1/apply", json=rec).status_code == 422           # signature no longer matches
    # The provider must have agreed to the current provider terms (their SHA-256 is signed into the listing).
    entry = dict(provider_record(key)["payload"]["provider"])
    for terms_value in (None, "00" * 32):
        e = {k: v for k, v in entry.items() if k != "terms"} if terms_value is None else dict(entry, terms=terms_value)
        r = client.post(P + "/v1/apply", json=sign_descriptor(e, key))
        assert r.status_code == 422 and "provider terms" in r.json()["detail"]
    t = client.get(P + "/v1/terms").json()
    assert set(t) == {"provider", "client"} and t["provider"]["sha256"] == current_terms("provider")["sha256"]
    assert "Acceptable use" in t["client"]["text"] and client.get(P + "/terms").status_code == 200
    assert client.get(P + "/v1/config").json()["terms"]["client"]["sha256"] == t["client"]["sha256"]
    mainnet = provider_record(key, network="eip155:8453")
    r = client.post(P + "/v1/apply", json=mainnet)
    assert r.status_code == 422 and "not accepted yet" in r.json()["detail"]
    fake.code = "0x"
    r = client.post(P + "/v1/apply", json=provider_record(key))
    assert r.status_code == 422 and "not a contract" in r.json()["detail"]
    fake.code = "0x6080"
    assert client.post(P + "/v1/apply", json=provider_record(key)).status_code == 200
    other = provider_record(Ed25519PrivateKey.generate())                        # same payout contract
    r = client.post(P + "/v1/apply", json=other)
    assert r.status_code == 422 and "already used" in r.json()["detail"]
    assert client.post(P + "/v1/apply", content=b"not json").status_code == 400


def test_cli_login_passkey_dashboard_and_access(env):
    client, store, fake, _ = env
    key = Ed25519PrivateKey.generate()
    pid = key.public_key().public_bytes_raw().hex()
    client.post(P + "/v1/apply", json=provider_record(key))

    # Login record signed for another registry, or replayed, is refused.
    ch = client.get(P + "/v1/login/challenge", params={"provider": pid}).json()
    assert client.post(P + "/v1/login", json=login_record(key, ch["challenge"], ch["expires_at"], host="evil.test")).status_code == 422
    stranger = Ed25519PrivateKey.generate()
    assert client.post(P + "/v1/login", json=login_record(stranger, ch["challenge"], ch["expires_at"])).status_code == 401

    auth = enroll(client, key)
    me = client.get(P + "/api/me")
    assert me.status_code == 200
    d = me.json()
    assert d["provider"]["id"] == pid and d["fee_bps"] == 250
    assert [k["name"] for k in d["passkeys"]] == ["Laptop"]
    assert set(d["activity"]) == {"STO-1", "CMP-1"}
    assert len(d["daily"]) == 30
    assert {a["event"] for a in d["audit"]} >= {"applied", "cli-login", "passkey-added"}

    # Last passkey cannot be removed.
    cred = d["passkeys"][0]["id"]
    assert client.post(P + f"/api/passkeys/{cred}/delete", json={}, headers=H).status_code == 409
    assert client.post(P + f"/api/passkeys/{cred}/rename", json={"name": "Work laptop"}, headers=H).status_code == 200

    # CSRF: custom header and same origin are required.
    assert client.post(P + f"/api/passkeys/{cred}/rename", json={"name": "x"}).status_code == 403
    assert client.post(P + f"/api/passkeys/{cred}/rename", json={"name": "x"},
                       headers={**H, "Origin": "https://evil.test"}).status_code == 403

    # Log out, then log back in with the passkey alone.
    assert client.post(P + "/api/logout", json={}, headers=H).status_code == 200
    assert client.get(P + "/api/me").status_code == 401
    opt = client.post(P + "/api/login/options", json={}, headers=H).json()
    ok = client.post(P + "/api/login/verify", json={"flow": opt["flow"], "credential": auth.get(opt["options"])}, headers=H)
    assert ok.status_code == 200, ok.text
    assert client.get(P + "/api/me").json()["passkeys"][0]["name"] == "Work laptop"

    # A flow id is single use; a passkey for another site is refused.
    replay = client.post(P + "/api/login/verify", json={"flow": opt["flow"], "credential": auth.get(opt["options"])}, headers=H)
    assert replay.status_code == 400
    opt = client.post(P + "/api/login/options", json={}, headers=H).json()
    bad = client.post(P + "/api/login/verify", json={"flow": opt["flow"], "credential": auth.get(opt["options"], rp_id="evil.test")}, headers=H)
    assert bad.status_code == 401

    # Second device: add a passkey from the session, then sign the other session out.
    other = TestClient(client.app, base_url=ORIGIN)
    opt = other.post(P + "/api/login/options", json={}, headers=H).json()
    assert other.post(P + "/api/login/verify", json={"flow": opt["flow"], "credential": auth.get(opt["options"])}, headers=H).status_code == 200
    sessions = client.get(P + "/api/me").json()["sessions"]
    target = [s for s in sessions if not s["current"]][0]["id"]
    assert client.post(P + f"/api/sessions/{target}/revoke", json={}, headers=H).status_code == 200
    assert other.get(P + "/api/me").status_code == 401
    phone = SoftAuthenticator()
    opt = client.post(P + "/api/enroll/options", json={}, headers=H).json()
    assert len(opt["options"]["excludeCredentials"]) == 1
    assert client.post(P + "/api/enroll/verify", json={"flow": opt["flow"], "credential": phone.create(opt["options"]),
                                                       "name": "Phone"}, headers=H).status_code == 200
    assert client.post(P + f"/api/passkeys/{cred}/delete", json={}, headers=H).status_code == 200


def test_enroll_rejects_wrong_origin(env):
    client, store, fake, _ = env
    key = Ed25519PrivateKey.generate()
    pid = key.public_key().public_bytes_raw().hex()
    client.post(P + "/v1/apply", json=provider_record(key))
    ch = client.get(P + "/v1/login/challenge", params={"provider": pid}).json()
    token = client.post(P + "/v1/login", json=login_record(key, ch["challenge"], ch["expires_at"])).json()["url"].split("#t=")[1]
    phish = SoftAuthenticator(origin="https://innernetcorp-login.test")
    opt = client.post(P + "/api/enroll/options", json={"token": token}, headers=H).json()
    r = client.post(P + "/api/enroll/verify", json={"flow": opt["flow"], "credential": phish.create(opt["options"])}, headers=H)
    assert r.status_code == 400
    assert client.get(P + "/api/me").status_code == 401


def test_payments_earnings_and_splits(env):
    client, store, fake, s = env
    key = Ed25519PrivateKey.generate()
    payto = "0x" + "ab" * 20
    client.post(P + "/v1/apply", json=provider_record(key, payto=payto))
    assert chain.scan_once(store, s, fake) == 0            # first sight: start at the current head
    fake.pay(payto, 2_500_000, 1003)                       # 2.50 USDC
    fake.pay(payto, 1_000_001, 1004)
    fake.pay("0x" + "cd" * 20, 9_000_000, 1004)           # someone else's contract
    fake.head = 1010
    assert chain.scan_once(store, s, fake) == 2
    assert chain.scan_once(store, s, fake) == 0            # idempotent
    st = client.get(P + f"/v1/providers/{key.public_key().public_bytes_raw().hex()}/status").json()
    assert st["earnings"]["gross_30d"] == "3.50"
    e = chain.earnings(store, key.public_key().public_bytes_raw().hex(), s.fee_bps, since=0)
    assert e["gross"] == 3_500_001 and e["fee"] == 62_500 + 25_001 and e["net"] == e["gross"] - e["fee"]
    assert chain.split(1_000_001, 250) == (975_000, 25_001)
    assert chain.split(1_000_001, 100) == (990_000, 10_001)
    enroll(client, key)
    d = client.get(P + "/api/me").json()
    assert len(d["splits"]) == 2 and d["splits"][0]["explorer"].startswith("https://sepolia.basescan.org/tx/0x")
    assert d["earnings"]["30d"]["net"] == chain.usdc(e["net"])


def test_probe_suspends_unreachable_provider(env, tmp_path):
    client, store, fake, _ = env
    key = Ed25519PrivateKey.generate()
    pid = client.post(P + "/v1/apply", json=provider_record(key)).json()["provider"]
    os.environ["INNERNET_REGISTRY_DB"] = store_path = str(tmp_path / "registry.db")
    try:
        assert admin.main(["approve", pid]) == 0
    finally:
        os.environ.pop("INNERNET_REGISTRY_DB")
    assert store_path
    now = int(time.time())

    def down(host, port, timeout):
        raise OSError("refused")
    for i in range(probe.MIN_PROBES):
        probe.probe_once(store, down, now=now - i)
    p = store.provider(pid)
    assert p["state"] == "suspended" and "95%" in p["reason"]


def test_signed_registry_document(env, tmp_path):
    client, store, fake, s = env
    key = Ed25519PrivateKey.generate()
    pid = client.post(P + "/v1/apply", json=provider_record(key)).json()["provider"]
    doc = client.get(P + "/v1/registry.json").json()
    assert doc["payload"]["providers"] == []                # testing providers are not published
    store.x("UPDATE providers SET state='listed', listed_at=? WHERE id=?", (int(time.time()), pid))
    store.x("INSERT INTO probes(provider, ts, ok) VALUES (?,?,1)", (pid, int(time.time())))
    client2 = TestClient(create_app(s, store=store, rpc=fake), base_url=ORIGIN)   # fresh cache
    doc = client2.get(P + "/v1/registry.json").json()
    reg_pub = bytes.fromhex(doc["registry_key"])
    payload = verify_registry(doc, [reg_pub])
    assert [p["id"] for p in payload["providers"]] == [pid]
    assert payload["fee_bps"] == 250 and payload["fee_payto"] == {SEPOLIA: FEE_WALLET}
    assert payload["providers"][0]["reputation"]["uptime_7d"] == "1.0000"


def test_pages_and_headers(env):
    client, *_ = env
    for path in ("/dashboard", "/enroll", "/payout", "/providers/" + "ab" * 32):
        r = client.get(P + path)
        assert r.status_code == 200 and "text/html" in r.headers["content-type"]
        assert "script-src 'self'" in r.headers["content-security-policy"]
        assert r.headers["x-frame-options"] == "DENY"
        assert "style=" not in r.text and "<script>" not in r.text      # nothing inline under the strict CSP
    assert client.get(P + "/static/registry.css").status_code == 200
    # Pages pin each script to its content hash, so browsers never mix an old script with a new server.
    import hashlib, re
    from pathlib import Path
    html = client.get(P + "/claim").text
    v = re.search(r'static/claim\.js\?v=([0-9a-f]{12})"', html).group(1)
    assert v == hashlib.sha256((Path(__file__).parents[1] / "innernet2/registry_service/static/claim.js").read_bytes()).hexdigest()[:12]
    assert "immutable" in client.get(P + "/static/claim.js?v=" + v).headers["cache-control"]
    assert client.get(P + "/static/claim.js").headers["cache-control"] == "no-cache"
    assert client.get(P + "/static/dashboard.html").status_code == 404
    assert client.get(P + "/static/..%2Fapp.py").status_code == 404


# ---- end to end with the real Go CLI --------------------------------------

GO = shutil.which("go")


@pytest.mark.skipif(GO is None, reason="Go toolchain not installed")
def test_go_cli_against_live_registry(tmp_path):
    import uvicorn

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    fake = FakeChain()
    s = settings(tmp_path, login_host=f"127.0.0.1:{port}")
    app = create_app(s, rpc=fake, connect=lambda h, p, t: 2.0)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    try:
        binary = tmp_path / "innernet-provider"
        subprocess.run([GO, "build", "-o", str(binary), "."], cwd=os.path.join(os.path.dirname(__file__), "..", "provider"),
                       env={**os.environ, "CGO_ENABLED": "0"}, check=True, capture_output=True)
        home = tmp_path / "home"
        cli_env = {**os.environ, "INNERNET_HOME": str(home), "INNERNET_REGISTRY": f"http://127.0.0.1:{port}/registry/v1"}

        def cli(*args):
            r = subprocess.run([str(binary), *args], env=cli_env, capture_output=True, text=True, stdin=subprocess.DEVNULL)
            assert r.returncode == 0, r.stderr
            return r.stdout
        cli("init", "--yes", "--name", "go-box", "--region", "eu-central", "--host", "node.example.test",
            "--storage-gib", "50", "--compute", "--accept-terms")
        cli("wallet", "set", "0x" + "9a" * 20)
        assert "Application received" in cli("apply")
        out = cli("status")
        assert "Checking (not listed yet)" in out and "0.00 USDC to you (0.00 paid, 0.00 fee)" in out
        assert json.loads(cli("status", "--json"))["registry"]["state"] == "testing"
        out = cli("login")
        link = out.strip().splitlines()[-1]
        assert link.startswith(ORIGIN + "/registry/enroll#t=")
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def test_works_when_proxy_strips_prefix(env):
    client, *_ = env
    assert client.get("/healthz").json() == {"ok": True}
    assert client.get("/registry/healthz").json() == {"ok": True}
    assert client.get("/dashboard").status_code == 200


def test_public_config_and_payout_assets(env):
    client, *_ = env
    cfg = client.get(P + "/v1/config").json()
    assert cfg["fee_bps"] == 250
    net = cfg["networks"][0]
    assert net["caip2"] == SEPOLIA and net["chain_id"] == 84532 and net["usdc"] == USDC[SEPOLIA]
    assert net["fee_wallet"] == FEE_WALLET and net["factory"] is None
    assert net["explorer_address"] == "https://sepolia.basescan.org/address/"
    art = client.get(P + "/static/split-factory.json")
    assert art.status_code == 200 and art.headers["content-type"].startswith("application/json")


def test_payout_page_matches_compiled_contracts():
    """Selectors hard-coded in payout.js and chain.py, and the factory bytecode served to the
    operator, must match contracts/build/contracts.json exactly."""
    import re
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    art = json.loads((root / "contracts/build/contracts.json").read_text())
    split_ids = art["contracts"]["INNERnetSplit"]["methodIdentifiers"]
    fac_ids = art["contracts"]["INNERnetSplitFactory"]["methodIdentifiers"]
    js = (root / "innernet2/registry_service/static/payout.js").read_text()
    sel = dict(re.findall(r"(\w+): '([0-9a-f]{8})'", js.split("const SEL = {")[1].split("};")[0]))
    assert sel == {"splitOf": fac_ids["splitOf(address)"], "create": fac_ids["create(address)"],
                   "preview": split_ids["preview(address)"], "release": split_ids["release(address)"],
                   "isSplit": fac_ids["isSplit(address)"]}
    assert chain.SEL_IS_SPLIT == fac_ids["isSplit(address)"]
    assert chain.SEL_FEE_RECIPIENT == split_ids["feeRecipient()"]
    assert chain.SEL_FEE_BPS == split_ids["feeBps()"]
    assert chain.SEL_SPLIT_OF == fac_ids["splitOf(address)"]
    served = json.loads((root / "innernet2/registry_service/static/split-factory.json").read_text())
    assert served["bytecode"] == art["contracts"]["INNERnetSplitFactory"]["bytecode"]


def test_contract_artifact_is_reproducible(tmp_path):
    """Recompile with solc 0.8.28 when node and solc are available, and compare byte for byte."""
    import shutil as sh
    from pathlib import Path
    root = Path(__file__).resolve().parents[1] / "contracts"
    node = sh.which("node")
    if node is None or not (root / "node_modules" / "solc").exists():
        pytest.skip("node + solc 0.8.28 not installed (cd contracts && npm ci)")
    work = tmp_path / "c"
    (work / "test").mkdir(parents=True)
    (work / "build").mkdir()
    for name in ("INNERnetSplit.sol", "build.js", "test/MockTokens.sol"):
        sh.copy(root / name, work / name)
    (work / "node_modules").symlink_to((root / "node_modules").resolve())
    subprocess.run([node, str(work / "build.js"), str(work)], check=True, capture_output=True)
    assert (work / "build/contracts.json").read_text() == (root / "build/contracts.json").read_text()



# ---- web and terminal setup (innernet-provider start) -------------------------

from innernet2.irm_registry import CONNECT_DOMAIN, verify_connect  # noqa: E402
from innernet2.registry_service.app import nonce_check, norm_code  # noqa: E402


def connect_record(key, detected, now=None, nonce="ab" * 16):
    payload = {"version": "REG-1-CONNECT", "provider": key.public_key().public_bytes_raw().hex(), "detected": detected,
               "nonce": nonce, "issued_at": int(time.time()) if now is None else now}
    return {"payload": payload, "signature": key.sign(CONNECT_DOMAIN + canonical(payload)).hex()}


def intent_record(key, action, target=None):
    import secrets
    p = {"version": "REG-1-INTENT", "provider": key.public_key().public_bytes_raw().hex(), "action": action,
         "nonce": secrets.token_hex(16), "issued_at": int(time.time())}
    if target is not None:
        p["target"] = target
    return {"payload": p, "signature": key.sign(reg.INTENT_DOMAIN + canonical(p)).hex()}


def test_connect_record_rules():
    key = Ed25519PrivateKey.generate()
    det = {"name": "box", "host": "1.2.3.4", "port": 9443, "cpus": 4, "reachable": True}
    pid, d = verify_connect(connect_record(key, det))
    assert pid == key.public_key().public_bytes_raw() and d == det
    from innernet2.bulk_v080 import BulkError
    with pytest.raises(BulkError, match="stale"):
        verify_connect(connect_record(key, det, now=int(time.time()) - 3600))
    with pytest.raises(BulkError):
        verify_connect(connect_record(key, dict(det, password="x")))
    rec = connect_record(key, det)
    rec["payload"]["detected"]["host"] = "6.6.6.6"
    with pytest.raises(BulkError, match="signature"):
        verify_connect(rec)
    assert norm_code("k7qm 4xpa") == "K7QM-4XPA" and norm_code("short") == ""


def test_whoami_reachability_and_split(tmp_path):
    fake = FakeChain()
    calls = []
    s = settings(tmp_path, split_factory={SEPOLIA: "0x" + "fa" * 20})
    app = create_app(s, rpc=fake, reach=lambda host, port, nonce: calls.append((host, port)) or True)
    c = TestClient(app, base_url=ORIGIN)
    ip = c.get(P + "/v1/whoami").json()["ip"]
    r = c.post(P + "/v1/reachability", json={"port": 9443, "nonce": "cd" * 16}).json()
    assert r["reachable"] and calls == [(ip, 9443)]                  # dials the caller only
    assert c.post(P + "/v1/reachability", json={"port": 9443, "nonce": "zz"}).status_code == 400
    wallet = "0x" + "77" * 20
    assert c.get(P + "/v1/split", params={"receiver": wallet}).json()["split"] is None
    fake.splits[wallet] = "0x" + "5b" * 20
    out = c.get(P + "/v1/split", params={"receiver": wallet}).json()
    assert out["split"] == "0x" + "5b" * 20 and out["ready"]


def test_nonce_check_talks_to_a_real_listener():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    nonce = "ef" * 16

    def serve():
        conn, _ = srv.accept()
        conn.sendall(nonce.encode())
        conn.close()
    threading.Thread(target=serve, daemon=True).start()
    assert nonce_check("127.0.0.1", port, nonce)
    srv.close()
    assert not nonce_check("127.0.0.1", port, nonce, timeout=0.5)


def test_claim_and_setup_api(env):
    client, store, fake, s = env
    key = Ed25519PrivateKey.generate()
    pid = key.public_key().public_bytes_raw().hex()
    det = {"name": "box", "region": "asia-south", "host": "203.0.113.7", "port": 9443, "storage_free_gib": 500,
           "cpus": 8, "memory_mib": 16384, "os": "linux", "arch": "amd64", "reachable": True, "version": "0.2.0"}
    started = client.post(P + "/v1/connect", json=connect_record(key, det)).json()
    assert started["url"] == f"{ORIGIN}/registry/claim#code={started['code']}"
    poll = {"X-Poll-Token": started["poll"]}
    assert client.get(P + "/v1/connect/status", headers=poll).json() == {"status": "waiting"}
    assert client.post(P + "/api/claim/options", json={"code": "AAAA-AAAA"}, headers=H).status_code == 404
    auth = SoftAuthenticator()
    opt = client.post(P + "/api/claim/options", json={"code": started["code"].lower().replace("-", " ")}, headers=H).json()
    v = client.post(P + "/api/claim/verify", json={"flow": opt["flow"], "credential": auth.create(opt["options"]), "name": "Mac"}, headers=H)
    assert v.status_code == 200
    assert client.post(P + "/api/claim/options", json={"code": started["code"]}, headers=H).json()["resume"] is True
    assert client.get(P + "/v1/connect/status", headers=poll).json()["status"] == "claimed"
    assert client.get(P + "/api/me").status_code == 409                      # not applied yet -> setup page
    setup = client.get(P + "/api/setup").json()
    assert setup["detected"]["host"] == "203.0.113.7" and setup["fee_bps"] == 250
    offer = {"name": "box", "region": "asia-south", "host": "203.0.113.7", "port": 9443, "storage_gib": 100,
             "relay_gib": 0, "compute": True, "cpus": 4, "memory_mib": 2048,
             "prices": {"STO-1": "0.0012", "CMP-1": "0.02"}, "network": SEPOLIA, "payout": "0x" + "ab" * 20,
             "terms": current_terms("provider")["sha256"]}
    bad = dict(offer, name="Bad Name!")
    assert client.post(P + "/api/setup", json=bad, headers=H).status_code == 422
    assert client.post(P + "/api/setup", json=dict(offer, storage_gib=0, compute=False), headers=H).status_code == 422
    fake.code = "0x"
    assert client.post(P + "/api/setup", json=offer, headers=H).status_code == 422   # payout is not a contract
    fake.code = "0x6080"
    r = client.post(P + "/api/setup", json=offer, headers=H)
    assert r.status_code == 200
    # Nothing reaches the machine until the passkey confirms this exact setup.
    assert client.get(P + "/v1/connect/status", headers=poll).json() == {"status": "signing"}
    signed = json.loads(store.one("SELECT signed FROM claims WHERE provider=? AND status='signing'", (pid,))["signed"])
    assert unb64u(r.json()["options"]["challenge"]) == reg.setup_challenge(signed)
    assert signed["provider"] == pid and signed["offer"]["prices"]["STO-1"] == "0.0012" and "backup" not in signed
    other = SoftAuthenticator()                                   # a passkey of no machine
    assert client.post(P + "/api/setup/confirm", json={"flow": r.json()["flow"], "credential": other.get(r.json()["options"])},
                       headers=H).status_code == 401
    r = client.post(P + "/api/setup", json=offer, headers=H).json()  # the flow was used up: apply again
    forged = dict(r["options"], challenge=b64u(b"x" * 32))
    assert client.post(P + "/api/setup/confirm", json={"flow": r["flow"], "credential": auth.get(forged)},
                       headers=H).status_code == 401              # signed something else
    r = client.post(P + "/api/setup", json=offer, headers=H).json()
    assert client.post(P + "/api/setup/confirm", json={"flow": r["flow"], "credential": auth.get(r["options"])},
                       headers=H).status_code == 200
    st = client.get(P + "/v1/connect/status", headers=poll).json()
    assert st["status"] == "submitted" and st["offer"]["prices"]["STO-1"] == "0.0012"
    assert reg.setup_challenge(st["setup"]) == unb64u(json.loads(unb64u(st["auth"]["client_data"]))["challenge"])
    assert st["auth"]["cred_id"] == b64u(auth.cred_id)
    steps = {"steps": [{"id": "check", "label": "Passkey", "state": "ok", "text": "confirmed"}]}
    assert client.post(P + "/v1/connect/progress", json=steps, headers=poll).json() == {"ok": True}
    prog = client.get(P + "/api/setup/progress").json()
    assert prog["status"] == "submitted" and prog["steps"][0]["state"] == "ok" and prog["listing"] is None
    assert client.post(P + "/v1/connect/progress", json={"steps": [{"state": "bogus"}]}, headers=poll).status_code == 422
    assert client.post(P + "/v1/connect/finish", json=steps, headers=poll).json() == {"ok": True}
    assert client.get(P + "/v1/connect/status", headers=poll).json()["status"] == "done"
    assert client.get(P + "/api/setup/progress").json()["status"] == "done"
    assert pid in {a["provider"] for a in [dict(r) for r in store.q("SELECT provider FROM audit")]}


def seal_to(machine_key: str, text: str) -> dict:
    """What the setup page does in the browser: P-256 ECDH, HKDF-SHA256, AES-256-GCM."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import serialization as ser
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), unb64u(machine_key))
    eph = ec.generate_private_key(ec.SECP256R1())
    shared = eph.exchange(ec.ECDH(), pub)
    key = HKDF(hashes.SHA256(), 32, salt=None, info=b"INNERnet/REG-1/setup-seal").derive(shared)
    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, text.encode(), b"INNERnet backup passphrase")
    epk = eph.public_key().public_bytes(ser.Encoding.X962, ser.PublicFormat.UncompressedPoint)
    return {"epk": b64u(epk), "iv": b64u(iv), "ct": b64u(ct)}


def confirm_setup(web, auth, offer: dict) -> None:
    r = web.post(P + "/api/setup", json=offer, headers=H)
    assert r.status_code == 200, r.text
    c = web.post(P + "/api/setup/confirm", json={"flow": r.json()["flow"], "credential": auth.get(r.json()["options"])},
                 headers=H)
    assert c.status_code == 200, c.text


def test_setup_checks_vpn_reach_backup_and_service_changes(env):
    client, store, fake, s = env
    key = Ed25519PrivateKey.generate()
    pid = key.public_key().public_bytes_raw().hex()
    seal = b64u(ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
    det = {"name": "box", "region": "asia-south", "host": "203.0.113.7", "port": 9443, "storage_free_gib": 500,
           "cpus": 8, "memory_mib": 16384, "os": "darwin", "arch": "arm64", "reachable": True, "version": "0.6.2",
           "path": "tunnel", "seal_key": seal}
    assert client.post(P + "/v1/connect", json=connect_record(key, dict(det, seal_key="nope"))).status_code == 422
    started = client.post(P + "/v1/connect", json=connect_record(key, det)).json()
    poll = {"X-Poll-Token": started["poll"]}
    auth = SoftAuthenticator()
    opt = client.post(P + "/api/claim/options", json={"code": started["code"]}, headers=H).json()
    assert client.post(P + "/api/claim/verify", json={"flow": opt["flow"], "credential": auth.create(opt["options"])},
                       headers=H).status_code == 200
    setup = client.get(P + "/api/setup").json()
    assert setup["can_seal"] is True and setup["mode"] == "terminal" and setup["waiting_for_machine"] is False
    offer = {"name": "box", "region": "asia-south", "host": "203.0.113.7", "port": 9443, "storage_gib": 10,
             "relay_gib": 50, "vpn": True, "vpn_consent": True, "network": SEPOLIA, "payout": "0x" + "ab" * 20,
             "terms": current_terms("provider")["sha256"]}
    r = client.post(P + "/api/setup", json=offer, headers=H)
    assert r.status_code == 422 and "tunnel" in r.text                    # VPN needs direct or relay reach
    offer["vpn"] = False
    assert client.post(P + "/api/setup", json=dict(offer, backup={"epk": seal, "iv": "AA", "ct": "AA"}),
                       headers=H).status_code == 422
    backup = seal_to(seal, "correct horse battery staple")
    confirm_setup(client, auth, dict(offer, backup=backup, service=True))
    st = client.get(P + "/v1/connect/status", headers=poll).json()
    assert st["setup"]["backup"] == dict(backup, to=seal) and st["setup"]["service"] is True
    assert client.post(P + "/v1/connect/finish", headers=poll).status_code == 200
    # Machine listed; the owner opens the setup page again with no terminal: the service joins it.
    store.x("INSERT INTO providers(id, record, state, reason, applied_at, updated_at) VALUES (?,?,?,?,?,?)",
            (pid, json.dumps(provider_record(key)), "listed", "", int(time.time()), int(time.time())))
    assert client.get(P + f"/v1/providers/{pid}/setup-pending").json() == {"pending": False}
    page = client.get(P + "/api/setup").json()
    assert page["waiting_for_machine"] is True and page["mode"] == "service"
    assert client.get(P + "/api/me").status_code == 200                   # the dashboard still works meanwhile
    assert client.get(P + f"/v1/providers/{pid}/setup-pending").json() == {"pending": True}
    fetched = client.post(P + f"/v1/providers/{pid}/intent", json=intent_record(key, "setup-fetch")).json()
    assert client.get(P + f"/v1/providers/{pid}/setup-pending").json() == {"pending": False}
    spoll = {"X-Poll-Token": fetched["poll"]}
    stranger = Ed25519PrivateKey.generate()
    assert client.post(P + "/v1/connect/attach", json=connect_record(stranger, det), headers=spoll).status_code == 422
    assert client.post(P + "/v1/connect/attach", json=connect_record(key, dict(det, path="relay")),
                       headers=spoll).status_code == 200
    page = client.get(P + "/api/setup").json()
    assert page["waiting_for_machine"] is False and page["mode"] == "service" and page["detected"]["path"] == "relay"
    confirm_setup(client, auth, dict(offer, vpn=True))                    # through a relay VPN exit is allowed
    st = client.get(P + "/v1/connect/status", headers=spoll).json()
    assert st["status"] == "submitted" and st["setup"]["offer"]["vpn"] is True


def live_registry(tmp_path, **kw):
    import uvicorn
    port = free_tcp_port()
    fake = FakeChain()
    s = settings(tmp_path, login_host=f"127.0.0.1:{port}", cookie_secure=False, **kw)
    app = create_app(s, rpc=fake, connect=lambda h, p, t: 2.0)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    return server, th, port, fake, app.state.store


def free_tcp_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.mark.skipif(GO is None, reason="Go toolchain not installed")
def test_go_start_web_setup_end_to_end(tmp_path):
    import httpx
    server, th, port, fake, store = live_registry(tmp_path)
    try:
        binary = tmp_path / "innernet-provider"
        subprocess.run([GO, "build", "-o", str(binary), "."], cwd=os.path.join(os.path.dirname(__file__), "..", "provider"),
                       env={**os.environ, "CGO_ENABLED": "0"}, check=True, capture_output=True)
        offer_port = free_tcp_port()
        env = {**os.environ, "INNERNET_HOME": str(tmp_path / "home"), "INNERNET_POLL_MS": "100", "INNERNET_NO_SERVICE": "1", "INNERNET_NO_PORTMAP": "1",
               "INNERNET_REGISTRY": f"http://127.0.0.1:{port}/registry/v1", "TZ": "Asia/Karachi"}
        proc = subprocess.Popen([str(binary), "start", "--mode", "web", "--no-browser", "--port", str(offer_port)],
                                env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        code, lines = None, []
        while code is None:
            line = proc.stdout.readline()
            assert line, "".join(lines)
            lines.append(line)
            if line.strip().startswith(("Code:", "Machine code:")):
                code = line.split(":", 1)[1].strip()
        out = "".join(lines)
        assert "Internet address" in out and "127.0.0.1" in out and "reachable from the internet" in out   # real dial-back
        assert "[1/9]" in out and "Machine key" in out and "\x1b[" not in out        # steps; no colour codes in a pipe
        web = httpx.Client(base_url=f"http://127.0.0.1:{port}", headers=H)
        auth = SoftAuthenticator()
        assert len(code) == 19                                          # the permanent machine code
        opt = web.post(P + "/api/claim/options", json={"code": code}).json()
        assert web.post(P + "/api/claim/verify", json={"flow": opt["flow"], "credential": auth.create(opt["options"]),
                                                       "pair": opt.get("pair", False)}).status_code == 200
        det = web.get(P + "/api/setup").json()["detected"]
        assert det["reachable"] is True and det["host"] == "127.0.0.1" and det["region"] == "asia-south" and det["cpus"] >= 1
        assert det["class"] in ("server", "desktop", "laptop") and det["tz"] == "Asia/Karachi"
        payout = "0x" + "c3" * 20
        offer = {"name": det["name"], "region": det["region"], "host": "node.example.test", "port": offer_port,
                 "storage_gib": 10, "relay_gib": 0, "compute": False, "cpus": 1, "memory_mib": 512,
                 "prices": {"STO-1": "0.0015"}, "network": SEPOLIA, "payout": payout,
                 "terms": current_terms("provider")["sha256"]}
        assert web.get(P + "/api/setup").json()["can_seal"] is True
        # Everything on the website: offer, backup passphrase (sealed to the machine), passkey. The terminal asks nothing.
        confirm_setup(web, auth, dict(offer, backup=seal_to(det["seal_key"], "a long backup passphrase"), service=False))
        rest, _ = proc.communicate(timeout=60)
        assert proc.returncode == 0, out + rest
        assert "Setup finished" in rest and "sent to the registry" in rest and "(y/n)" not in rest
        home = tmp_path / "home"
        pid = json.loads((home / "descriptor.json").read_text())["payload"]["provider"]["id"]
        p = store.provider(pid)
        assert p["state"] == "testing" and p["entry"]["prices"]["STO-1"]["amount"] == "0.0015"
        assert p["entry"]["endpoints"] == [{"host": "node.example.test", "port": offer_port}]
        backup = json.loads((tmp_path / "provider-backup.json").read_text())
        assert backup and "a long backup passphrase" not in json.dumps(backup)
        assert json.loads((home / "passkeys.json").read_text()) == {b64u(auth.cred_id): b64u(auth._cose())}
        prog = web.get(P + "/api/setup/progress").json()
        assert prog["status"] == "done" and prog["listing"]["state"] == "testing"
        assert [s["id"] for s in prog["steps"]] == ["check", "sign", "backup", "service", "registry"]
        assert [s["state"] for s in prog["steps"]][:3] == ["ok", "ok", "ok"]
        assert web.get(P + "/api/me").status_code == 200                        # dashboard works now
        # Running start again on a set-up machine shows where it stands and exits; it does not start over.
        again = subprocess.run([str(binary), "start"], env=env, capture_output=True, text=True, timeout=60)
        assert again.returncode == 0 and "already set up" in again.stdout and "Machine code" not in again.stdout
    finally:
        server.should_exit = True
        th.join(timeout=5)


@pytest.mark.skipif(GO is None, reason="Go toolchain not installed")
def test_go_closed_port_waits_for_the_owner_to_choose(tmp_path):
    """No silent fallback: a closed port is shown on the website; the owner tests again (or connects out)."""
    import httpx
    server, th, port, fake, store = live_registry(tmp_path)
    blocker = socket.socket()
    try:
        binary = tmp_path / "innernet-provider"
        subprocess.run([GO, "build", "-o", str(binary), "."], cwd=os.path.join(os.path.dirname(__file__), "..", "provider"),
                       env={**os.environ, "CGO_ENABLED": "0"}, check=True, capture_output=True)
        offer_port = free_tcp_port()
        blocker.bind(("0.0.0.0", offer_port))
        blocker.listen(1)                                            # another program holds the port: not reachable
        env = {**os.environ, "INNERNET_HOME": str(tmp_path / "home"), "INNERNET_POLL_MS": "100", "INNERNET_NO_SERVICE": "1",
               "INNERNET_NO_PORTMAP": "1", "INNERNET_NO_FIREWALL": "1", "INNERNET_NO_UPDATE": "1",
               "INNERNET_REGISTRY": f"http://127.0.0.1:{port}/registry/v1"}
        proc = subprocess.Popen([str(binary), "start", "--no-browser", "--port", str(offer_port)], env=env,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        code, out = None, ""
        while code is None:
            line = proc.stdout.readline()
            assert line, out
            out += line
            if line.strip().startswith("Machine code:"):
                code = line.split(":", 1)[1].strip()
        assert "Trying an INNERnet relay" not in out and "HTTPS tunnel" not in out    # nothing chosen for the owner
        web = httpx.Client(base_url=f"http://127.0.0.1:{port}", headers=H)
        auth = SoftAuthenticator()
        opt = web.post(P + "/api/claim/options", json={"code": code}).json()
        assert web.post(P + "/api/claim/verify", json={"flow": opt["flow"], "credential": auth.create(opt["options"]),
                                                       "pair": opt.get("pair", False)}).status_code == 200
        page = web.get(P + "/api/setup").json()
        det = page["detected"]
        assert det["reachable"] is False and "path" not in det and "in use" in det["reach_note"]
        offer = {"name": det["name"], "region": det["region"], "host": "127.0.0.1", "port": offer_port, "storage_gib": 5,
                 "network": SEPOLIA, "payout": "0x" + "c3" * 20, "terms": current_terms("provider")["sha256"]}
        r = web.post(P + "/api/setup", json=offer)
        assert r.status_code == 422 and "cannot reach" in r.text                    # Apply waits for a choice
        assert web.post(P + "/api/setup/reach", json={"action": "bogus"}).status_code == 422
        blocker.close()                                                              # the owner opened the port
        assert web.post(P + "/api/setup/reach", json={"action": "retest"}).json() == {"ok": True}
        for _ in range(100):
            page = web.get(P + "/api/setup").json()
            if not page["request"]:
                break
            time.sleep(0.1)
        assert page["request"] is None and page["detected"]["reachable"] is True and page["detected"]["path"] == "direct"
        confirm_setup(web, auth, offer)
        rest, _ = proc.communicate(timeout=60)
        assert proc.returncode == 0 and "Setup finished" in rest, out + rest
        assert "reachable from the internet" in rest
    finally:
        blocker.close()
        server.should_exit = True
        th.join(timeout=5)

@pytest.mark.skipif(GO is None, reason="Go toolchain not installed")
def test_go_serve_applies_a_change_made_on_the_website(tmp_path):
    """No terminal: the owner changes the offer on the website and the background service applies it."""
    import httpx
    server, th, port, fake, store = live_registry(tmp_path)
    serve = None
    try:
        binary = tmp_path / "innernet-provider"
        subprocess.run([GO, "build", "-o", str(binary), "."], cwd=os.path.join(os.path.dirname(__file__), "..", "provider"),
                       env={**os.environ, "CGO_ENABLED": "0"}, check=True, capture_output=True)
        offer_port = free_tcp_port()
        env = {**os.environ, "INNERNET_HOME": str(tmp_path / "home"), "INNERNET_POLL_MS": "100", "INNERNET_NO_SERVICE": "1",
               "INNERNET_NO_PORTMAP": "1", "INNERNET_NO_UPDATE": "1", "INNERNET_PRESENCE_SEC": "1",
               "INNERNET_REGISTRY": f"http://127.0.0.1:{port}/registry/v1"}
        proc = subprocess.Popen([str(binary), "start", "--no-browser", "--port", str(offer_port)],
                                env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        code = None
        while code is None:
            line = proc.stdout.readline()
            assert line
            if line.strip().startswith("Machine code:"):
                code = line.split(":", 1)[1].strip()
        web = httpx.Client(base_url=f"http://127.0.0.1:{port}", headers=H)
        auth = SoftAuthenticator()
        opt = web.post(P + "/api/claim/options", json={"code": code}).json()
        assert web.post(P + "/api/claim/verify", json={"flow": opt["flow"], "credential": auth.create(opt["options"]),
                                                       "pair": opt.get("pair", False)}).status_code == 200
        det = web.get(P + "/api/setup").json()["detected"]
        offer = {"name": det["name"], "region": det["region"], "host": "127.0.0.1", "port": offer_port,
                 "storage_gib": 10, "network": SEPOLIA, "payout": "0x" + "c3" * 20,
                 "terms": current_terms("provider")["sha256"]}
        confirm_setup(web, auth, offer)
        proc.communicate(timeout=60)
        assert proc.returncode == 0
        serve = subprocess.Popen([str(binary), "serve"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        page = web.get(P + "/api/setup").json()
        assert page["mode"] == "service"
        for _ in range(100):
            if not page["waiting_for_machine"]:
                break
            time.sleep(0.1)
            page = web.get(P + "/api/setup").json()
        assert not page["waiting_for_machine"], "the background service did not join"
        assert page["can_seal"] is True
        confirm_setup(web, auth, dict(offer, storage_gib=25, prices={"STO-1": "0.0020"},
                                      backup=seal_to(page["detected"]["seal_key"], "another long passphrase")))
        pid = page["provider"]
        for _ in range(100):
            prog = web.get(P + "/api/setup/progress").json()
            if prog["status"] == "done" and prog["listing"]:
                break
            time.sleep(0.1)
        assert prog["status"] == "done" and [s_["state"] for s_ in prog["steps"]][:3] == ["ok", "ok", "ok"], prog
        e = store.provider(pid)["entry"]
        assert e["limits"]["STO-1"]["max_storage_gib"] == 25 and e["prices"]["STO-1"]["amount"] == "0.0020"
        assert (tmp_path / "provider-backup.json").exists()
        # The service restarted with the new settings and keeps answering.
        for _ in range(100):
            try:
                if httpx.get(f"http://127.0.0.1:{offer_port}/sto/v1/info", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.1)
        assert serve.poll() is None
    finally:
        if serve is not None:
            serve.kill()
        server.should_exit = True
        th.join(timeout=5)


@pytest.mark.skipif(GO is None, reason="Go toolchain not installed")
def test_go_start_terminal_for_agents(tmp_path):
    server, th, port, fake, store = live_registry(tmp_path, split_factory={SEPOLIA: "0x" + "fa" * 20})
    try:
        binary = tmp_path / "innernet-provider"
        subprocess.run([GO, "build", "-o", str(binary), "."], cwd=os.path.join(os.path.dirname(__file__), "..", "provider"),
                       env={**os.environ, "CGO_ENABLED": "0"}, check=True, capture_output=True)
        wallet, split = "0x" + "44" * 20, "0x" + "5c" * 20
        fake.splits[wallet] = split
        env = {**os.environ, "INNERNET_HOME": str(tmp_path / "agent"), "INNERNET_POLL_MS": "100", "INNERNET_NO_SERVICE": "1", "INNERNET_NO_PORTMAP": "1",
               "INNERNET_REGISTRY": f"http://127.0.0.1:{port}/registry/v1"}
        r = subprocess.run([str(binary), "start", "--yes", "--wallet", wallet, "--port", str(free_tcp_port())],
                           env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)
        assert r.returncode == 0, r.stdout + r.stderr
        assert "Payout contract: " + split in r.stdout and "Application received" in r.stdout
        pid = json.loads((tmp_path / "agent" / "descriptor.json").read_text())["payload"]["provider"]["id"]
        assert store.provider(pid)["entry"]["payto"] == {SEPOLIA: split}
        again = subprocess.run([str(binary), "start", "--yes", "--port", str(free_tcp_port())], env=env,
                               capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)
        assert again.returncode == 0                                   # set-up machine re-applies, wallet kept
        if sys.platform.startswith("linux"):                           # background service file, dry run
            svc_env = {k: v for k, v in env.items() if k != "INNERNET_NO_SERVICE"}
            dry = subprocess.run([str(binary), "service", "install", "--dry-run"], env=svc_env, capture_output=True,
                                 text=True, stdin=subprocess.DEVNULL, timeout=30)
            assert dry.returncode == 0, dry.stderr
            assert f"ExecStart={binary} serve" in dry.stdout and f"INNERNET_HOME={tmp_path / 'agent'}" in dry.stdout
            assert "Restart=always" in dry.stdout
        fresh = dict(env, INNERNET_HOME=str(tmp_path / "fresh"))
        no = subprocess.run([str(binary), "start", "--yes", "--port", "9"], env=fresh, capture_output=True, text=True,
                            stdin=subprocess.DEVNULL, timeout=60)
        assert no.returncode != 0 and "--wallet" in no.stderr
    finally:
        server.should_exit = True
        th.join(timeout=5)


@pytest.mark.skipif(GO is None, reason="Go toolchain not installed")
def test_go_serve_presence_intents_status_and_states(tmp_path):
    """serve checks in with a signed presence; the registry verifies the address by fetching the
    provider's signed info; pause/resume/leave/reinstate work from the terminal and the web; status
    shows it all; states move on with time (gone, trial, listed again)."""
    import httpx
    from innernet2.registry_service import presence, probe as probe_mod
    server, th, port, fake, store = live_registry(tmp_path, split_factory={SEPOLIA: "0x" + "fa" * 20})
    procs = []
    try:
        binary = tmp_path / "innernet-provider"
        subprocess.run([GO, "build", "-o", str(binary), "."], cwd=os.path.join(os.path.dirname(__file__), "..", "provider"),
                       env={**os.environ, "CGO_ENABLED": "0"}, check=True, capture_output=True)
        wallet, split = "0x" + "45" * 20, "0x" + "5d" * 20
        fake.splits[wallet] = split
        sport = free_tcp_port()
        env = {**os.environ, "INNERNET_HOME": str(tmp_path / "p"), "INNERNET_POLL_MS": "100", "INNERNET_NO_SERVICE": "1",
               "INNERNET_NO_PORTMAP": "1", "INNERNET_NO_FIREWALL": "1", "INNERNET_PRESENCE_SEC": "1",
               "INNERNET_REGISTRY": f"http://127.0.0.1:{port}/registry/v1", "TZ": "Asia/Karachi"}
        run = lambda *a: subprocess.run([str(binary), *a], env=env, capture_output=True, text=True,  # noqa: E731
                                        stdin=subprocess.DEVNULL, timeout=60)
        r = run("start", "--yes", "--wallet", wallet, "--port", str(sport))
        assert r.returncode == 0, r.stdout + r.stderr
        pid = json.loads((tmp_path / "p" / "descriptor.json").read_text())["payload"]["provider"]["id"]
        entry = store.provider(pid)["entry"]
        assert entry["class"] in ("server", "desktop", "laptop")
        procs.append(subprocess.Popen([str(binary), "serve"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        api = httpx.Client(base_url=f"http://127.0.0.1:{port}/registry/v1")
        live = None
        for _ in range(80):
            got = api.get(f"/presence/{pid}")
            if got.status_code == 200 and got.json()["reachable"]:
                live = got.json()
                break
            time.sleep(0.1)
        assert live and live["online"] and live["record"]["payload"]["endpoint"] == {"host": "127.0.0.1", "port": sport}
        assert reg_verify_presence(live["record"])["path"] == "direct"          # clients check the signature themselves
        # a forged record (wrong key) or an address that is not the sender's is refused
        bad = json.loads(json.dumps(live["record"]))
        bad["payload"]["seq"] += 10**6
        assert api.post("/presence", json=bad).status_code == 422
        # the running service answers the registry's reachability test (port in use by serve)
        assert nonce_check("127.0.0.1", sport, "ab" * 16)
        # intents from the terminal
        r = run("pause")
        assert r.returncode == 0 and "Paused" in r.stdout, r.stdout + r.stderr
        assert store.provider(pid)["state"] == "paused"
        assert "listed" not in [p["state"] for p in store.providers("listed") if p["id"] == pid]
        assert run("resume").returncode == 0 and store.provider(pid)["state"] == "testing"
        assert run("leave").returncode == 0 and store.provider(pid)["state"] == "leaving"
        assert run("resume").returncode == 0 and store.provider(pid)["state"] == "testing"
        r = run("reinstate")
        assert r.returncode != 0 and "nothing to reinstate" in r.stderr
        # status: plain and JSON
        r = run("status", "--json")
        st = json.loads(r.stdout)
        assert st["service_answering"] and st["presence"]["reachable"] and st["registry"]["state"] == "testing"
        r = run("status")
        assert "running on port" in r.stdout and "last check-in" in r.stdout and "\x1b[" not in r.stdout
        # usage and market for the dashboard
        u = presence.usage(store, pid)
        assert u["now"]["storage_limit_bytes"] > 0 and "stored_bytes" in u["now"]
        store.x("UPDATE providers SET state='listed', listed_at=? WHERE id=?", (int(time.time()), pid))
        m = api.get("/market").json()["services"]["STO-1"]
        assert m["providers"] == 1 and m["median"] == entry["prices"]["STO-1"]["amount"].rstrip("0").rstrip(".")
        # time passes: nothing heard for 8 days -> gone; reinstate -> trial; a clean trial lists it again
        procs[0].kill()
        procs[0].wait()
        later = int(time.time()) + 8 * 86400
        store.x("UPDATE providers SET last_seen=?, checked_at=? WHERE id=?", (later - 8 * 86400, later - 8 * 86400, pid))
        store.x("DELETE FROM probes WHERE provider=?", (pid,))
        presence.advance_states(store, probe_mod.uptime, later)
        assert store.provider(pid)["state"] == "gone"
        assert run("reinstate").returncode == 0 and store.provider(pid)["state"] == "testing"
        trial = store.provider(pid)["trial_since"]
        for i in range(24):
            store.x("INSERT INTO probes(provider, ts, ok, latency_ms) VALUES (?,?,?,?)", (pid, trial + 3600 * i + 1, 1, 5))
        presence.advance_states(store, probe_mod.uptime, trial + 86400 + 10)
        assert store.provider(pid)["state"] == "listed"
        audit = [r["event"] for r in store.q("SELECT event FROM audit WHERE provider=? ORDER BY id", (pid,))]
        for ev in ("pause", "resume", "leave", "gone", "reinstate", "listed"):
            assert ev in audit
    finally:
        for p in procs:
            p.kill()
        server.should_exit = True
        th.join(timeout=5)


def test_presence_and_intent_records_are_checked():
    from innernet2.bulk_v080 import BulkError
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as K
    from innernet2 import irm_registry as r
    key = K.generate()
    pid = key.public_key().public_bytes_raw().hex()
    now = int(time.time())
    p = {"version": "REG-1-PRESENCE", "provider": pid, "endpoint": {"host": "203.0.113.9", "port": 9443}, "path": "router",
         "seq": now * 1000, "issued_at": now, "software": "innernet-provider/0.3.0", "stats": {"stored_bytes": 5}}
    rec = {"payload": p, "signature": key.sign(r.PRESENCE_DOMAIN + r.canonical(p)).hex()}
    assert r.verify_presence(rec)["path"] == "router"
    for change in ({"path": "teleport"}, {"issued_at": now - 3600}, {"stats": {"secret": 1}}):
        q = dict(p, **change)
        with pytest.raises(BulkError):
            r.verify_presence({"payload": q, "signature": key.sign(r.PRESENCE_DOMAIN + r.canonical(q)).hex()})
    with pytest.raises(BulkError):                                      # signed with the intent domain
        r.verify_presence({"payload": p, "signature": key.sign(r.INTENT_DOMAIN + r.canonical(p)).hex()})
    i = {"version": "REG-1-INTENT", "provider": pid, "action": "pause", "nonce": "ab" * 16, "issued_at": now}
    assert r.verify_intent({"payload": i, "signature": key.sign(r.INTENT_DOMAIN + r.canonical(i)).hex()})[1] == "pause"
    j = dict(i, action="delete-everything")
    with pytest.raises(BulkError):
        r.verify_intent({"payload": j, "signature": key.sign(r.INTENT_DOMAIN + r.canonical(j)).hex()})
    # hours: Wednesday 21:46 in Karachi is inside "wed 20:00-24:00", Thursday noon is not
    e = {"availability": {"tz": "Asia/Karachi", "weekly": [[2, 1200, 1440]]}}
    assert r.in_hours(e, 1795624000) and not r.in_hours(e, 1795624000 + 14 * 3600)
    assert r.in_hours({}, 0) and r.available_minutes(e) == 240
    with pytest.raises(BulkError):
        r.validate_availability({"tz": "Asia/Karachi", "weekly": [[2, 1300, 1200]]})


def reg_verify_presence(record):
    from innernet2 import irm_registry as r
    return r.verify_presence(record)


def test_claim_again_with_the_passkey_this_device_already_has(env):
    """Setting the same machine up a second time from the same device: the browser refuses a second
    passkey (InvalidStateError), so the page signs in with the existing one and the claim still works."""
    client, store, fake, s = env
    key = Ed25519PrivateKey.generate()
    det = {"name": "mac", "region": "asia-south", "host": "203.0.113.8", "port": 9443, "os": "darwin", "arch": "arm64"}
    auth = SoftAuthenticator()
    first = client.post(P + "/v1/connect", json=connect_record(key, det)).json()
    opt = client.post(P + "/api/claim/options", json={"code": first["code"]}, headers=H).json()
    assert "login_flow" not in opt                                            # no passkeys yet: only enrolment
    assert client.post(P + "/api/claim/verify", json={"flow": opt["flow"], "credential": auth.create(opt["options"]),
                                                      "name": "Mac"}, headers=H).status_code == 200
    client.cookies.clear()
    store.x("UPDATE claims SET status='done'")                               # that setup was finished
    second = client.post(P + "/v1/connect", json=connect_record(key, det)).json()
    assert second["resumed"] is False
    opt = client.post(P + "/api/claim/options", json={"code": second["code"]}, headers=H).json()
    assert opt["login_flow"] and opt["login_options"]["allowCredentials"]
    stranger = SoftAuthenticator()                                            # a passkey of another machine is refused
    stranger.create(client.post(P + "/api/claim/options", json={"code": second["code"]}, headers=H).json()["options"])
    assert client.post(P + "/api/claim/verify", json={"login": True, "flow": opt["login_flow"],
                                                      "credential": stranger.get(opt["login_options"])},
                       headers=H).status_code == 401
    opt = client.post(P + "/api/claim/options", json={"code": second["code"]}, headers=H).json()
    v = client.post(P + "/api/claim/verify", json={"login": True, "flow": opt["login_flow"],
                                                   "credential": auth.get(opt["login_options"])}, headers=H)
    assert v.status_code == 200 and v.json()["existing"] is True
    assert client.get(P + "/v1/connect/status", headers={"X-Poll-Token": second["poll"]}).json()["status"] == "claimed"
    assert client.get(P + "/api/setup").status_code == 200                   # signed in: the setup page works
    assert store.one("SELECT COUNT(*) AS n FROM passkeys")["n"] == 1          # no second passkey was made


@pytest.mark.skipif(GO is None, reason="Go toolchain not installed")
def test_go_passkeys_list_and_remove_with_the_machine_key(tmp_path):
    """Lost passkey: the machine key lists and removes passkeys; removal logs out every web session.
    start shows the passkeys that already exist."""
    server, th, port, fake, store = live_registry(tmp_path, split_factory={SEPOLIA: "0x" + "fa" * 20})
    try:
        binary = tmp_path / "innernet-provider"
        subprocess.run([GO, "build", "-o", str(binary), "."], cwd=os.path.join(os.path.dirname(__file__), "..", "provider"),
                       env={**os.environ, "CGO_ENABLED": "0"}, check=True, capture_output=True)
        wallet = "0x" + "46" * 20
        fake.splits[wallet] = "0x" + "5e" * 20
        env = {**os.environ, "INNERNET_HOME": str(tmp_path / "p"), "INNERNET_POLL_MS": "100", "INNERNET_NO_SERVICE": "1",
               "INNERNET_NO_PORTMAP": "1", "INNERNET_NO_FIREWALL": "1",
               "INNERNET_REGISTRY": f"http://127.0.0.1:{port}/registry/v1"}
        run = lambda *a: subprocess.run([str(binary), *a], env=env, capture_output=True, text=True,  # noqa: E731
                                        stdin=subprocess.DEVNULL, timeout=60)
        assert run("start", "--yes", "--wallet", wallet, "--port", str(free_tcp_port())).returncode == 0
        pid = json.loads((tmp_path / "p" / "descriptor.json").read_text())["payload"]["provider"]["id"]
        assert "No passkeys yet" in run("passkeys").stdout
        now = int(time.time())
        for name in ("Mac", "Phone"):
            store.x("INSERT INTO passkeys(cred_id, provider, public_key, sign_count, name, created_at) VALUES (?,?,?,?,?,?)",
                    (name.lower() + "-id", pid, b"k", 0, name, now))
        store.x("INSERT INTO sessions(token_hash, id, provider, created_at, expires_at) VALUES ('h','s1',?,?,?)",
                (pid, now, now + 3600))
        out = run("passkeys").stdout
        assert "Mac" in out and "Phone" in out and "added" in out
        r = run("passkeys", "remove", "Phone")
        assert r.returncode == 0 and 'Removed passkey "Phone"' in r.stdout, r.stdout + r.stderr
        assert [x["name"] for x in store.q("SELECT name FROM passkeys WHERE provider=?", (pid,))] == ["Mac"]
        assert store.one("SELECT revoked FROM sessions WHERE id='s1'")["revoked"] == 1
        r = run("passkeys", "remove", "Tablet")
        assert r.returncode != 0 and "no passkey" in r.stderr
        # start (website mode) shows the passkey that already exists
        proc = subprocess.Popen([str(binary), "start", "--mode", "web", "--no-browser", "--port", str(free_tcp_port())],
                                env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        seen = ""
        for _ in range(60):
            line = proc.stdout.readline()
            seen += line
            if "Passkeys for this machine" in line or not line:
                break
        proc.kill()
        assert "Passkeys for this machine: Mac (" in seen, seen
    finally:
        server.should_exit = True
        th.join(timeout=5)


def test_setup_resumes_after_closing_the_terminal_or_the_tab(env):
    """Closing the browser tab: the same code signs you in again with your passkey. Closing the terminal:
    `start` again continues the claimed setup (new code, still signed in, draft kept)."""
    client, store, fake, s = env
    key = Ed25519PrivateKey.generate()
    det = {"name": "mac", "region": "asia-south", "host": "203.0.113.9", "port": 9443, "os": "darwin", "arch": "arm64"}
    auth = SoftAuthenticator()
    first = client.post(P + "/v1/connect", json=connect_record(key, det)).json()
    assert first["resumed"] is False
    opt = client.post(P + "/api/claim/options", json={"code": first["code"]}, headers=H).json()
    assert client.post(P + "/api/claim/verify", json={"flow": opt["flow"], "credential": auth.create(opt["options"]),
                                                      "name": "Mac"}, headers=H).status_code == 200
    # tab closed, cookie gone: the same code works again, by passkey
    client.cookies.clear()
    again = client.post(P + "/api/claim/options", json={"code": first["code"]}, headers=H).json()
    assert again["resume"] is True and "options" not in again
    v = client.post(P + "/api/claim/verify", json={"login": True, "flow": again["login_flow"],
                                                   "credential": auth.get(again["login_options"])}, headers=H)
    assert v.status_code == 200 and client.get(P + "/api/setup").status_code == 200
    # terminal closed: start again continues (already claimed, no code needed in the open tab)
    second = client.post(P + "/v1/connect", json=connect_record(key, det)).json()
    assert second["resumed"] is True and second["setup_url"].endswith("/registry/setup")
    assert client.get(P + "/v1/connect/status", headers={"X-Poll-Token": second["poll"]}).json()["status"] == "claimed"
    assert client.get(P + "/v1/connect/status", headers={"X-Poll-Token": first["poll"]}).json()["status"] == "superseded"
    assert client.get(P + "/api/setup").status_code == 200                  # the open tab keeps working
    assert client.post(P + "/api/claim/options", json={"code": first["code"]}, headers=H).status_code == 410


def test_claim_code_stays_alive_while_the_terminal_waits_and_says_why_it_fails(env):
    client, store, fake, s = env
    key = Ed25519PrivateKey.generate()
    det = {"name": "box", "region": "asia-south", "host": "203.0.113.7", "port": 9443, "storage_free_gib": 50,
           "cpus": 4, "memory_mib": 8192, "os": "darwin", "arch": "arm64", "reachable": True, "version": "0.5.1"}
    first = client.post(P + "/v1/connect", json=connect_record(key, det)).json()
    poll = {"X-Poll-Token": first["poll"]}
    # 40 minutes pass while the terminal keeps polling: the code is still good.
    store.x("UPDATE claims SET expires_at=?, created_at=? WHERE poll_hash IS NOT NULL",
            (int(time.time()) + 60, int(time.time()) - 40 * 60))
    assert client.get(P + "/v1/connect/status", headers=poll).json()["status"] == "waiting"
    exp = store.one("SELECT expires_at FROM claims")["expires_at"]
    assert exp > int(time.time()) + 25 * 60
    r = client.post(P + "/api/claim/options", json={"code": first["code"]}, headers=H)
    assert r.status_code == 200
    # Running start again makes a new code; the old one says so plainly.
    second = client.post(P + "/v1/connect", json=connect_record(key, det, nonce="cd" * 16)).json()
    r = client.post(P + "/api/claim/options", json={"code": first["code"]}, headers=H)
    assert r.status_code == 410 and "newer code" in r.json()["detail"]
    r = client.post(P + "/api/claim/options", json={"code": "ZZZZ-ZZZZ"}, headers=H)
    assert r.status_code == 404 and "No machine has this code" in r.json()["detail"]
    # The terminal stopped polling long ago: expired, with the reason.
    store.x("UPDATE claims SET expires_at=? WHERE status='waiting'", (int(time.time()) - 5,))
    r = client.post(P + "/api/claim/options", json={"code": second["code"]}, headers=H)
    assert r.status_code == 410 and "stopped waiting" in r.json()["detail"]


def test_machine_code_is_permanent_until_rekey(env):
    import hashlib
    import secrets
    import innernet2.irm_registry as r
    client, store, fake, s = env
    key = Ed25519PrivateKey.generate()
    pid = key.public_key().public_bytes_raw().hex()

    def intent(action, target=None, nonce=None):
        p = {"version": "REG-1-INTENT", "provider": pid, "action": action, "nonce": nonce or secrets.token_hex(16),
             "issued_at": int(time.time())}
        if target:
            p["target"] = target
        return client.post(P + f"/v1/providers/{pid}/intent", json={"payload": p, "signature": key.sign(r.INTENT_DOMAIN + r.canonical(p)).hex()})

    code = "ABCD-EFGH-JKLM-NPQR"
    assert intent("pairing-set", hashlib.sha256(code.encode()).hexdigest()).status_code == 200
    other = Ed25519PrivateKey.generate()                  # someone else cannot set this machine's code
    p = {"version": "REG-1-INTENT", "provider": pid, "action": "pairing-set", "nonce": "cd" * 16,
         "issued_at": int(time.time()), "target": "00" * 32}
    bad = client.post(P + f"/v1/providers/{pid}/intent", json={"payload": p, "signature": other.sign(r.INTENT_DOMAIN + r.canonical(p)).hex()})
    assert bad.status_code == 422

    # Machine not running start: the code adds a passkey and opens the dashboard (no setup page).
    auth = SoftAuthenticator()
    opt = client.post(P + "/api/claim/options", json={"code": code.lower().replace("-", "")}, headers=H).json()
    assert opt["pair"] is True and opt["setup"] is False
    v = client.post(P + "/api/claim/verify", json={"flow": opt["flow"], "credential": auth.create(opt["options"]),
                                                     "name": "Phone", "pair": True}, headers=H)
    assert v.status_code == 200
    assert store.one("SELECT name FROM passkeys WHERE provider=?", (pid,))["name"] == "Phone"
    # Days later the same code still works, now while the machine waits for setup.
    det = {"name": "box", "region": "asia-south", "host": "203.0.113.7", "port": 9443, "storage_free_gib": 50,
           "cpus": 4, "memory_mib": 8192, "os": "darwin", "arch": "arm64", "reachable": True, "version": "0.5.2"}
    client.post(P + "/v1/connect", json=connect_record(key, det))
    client.cookies.clear()
    opt = client.post(P + "/api/claim/options", json={"code": code}, headers=H).json()
    assert opt["pair"] is True and opt["setup"] is True and "login_flow" in opt      # the passkey exists: confirm it
    v = client.post(P + "/api/claim/verify", json={"login": True, "flow": opt["login_flow"],
                                                     "credential": auth.get(opt["login_options"])}, headers=H)
    assert v.status_code == 200 and client.get(P + "/api/setup").json()["detected"]["host"] == "203.0.113.7"
    # Rekey: the old code stops working at once.
    assert intent("pairing-set", hashlib.sha256(b"WXYZ-WXYZ-WXYZ-WXYZ").hexdigest()).status_code == 200
    r2 = client.post(P + "/api/claim/options", json={"code": code}, headers=H)
    assert r2.status_code == 404 and "rekey" in r2.json()["detail"]


def test_download_routes_forward_to_release_files(env):
    client, store, fake, s = env
    r = client.get(P + "/dl/provider-v0.6.0/innernet-provider-darwin-arm64", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].endswith("/releases/download/provider-v0.6.0/innernet-provider-darwin-arm64")
    assert client.get(P + "/dl/provider-v0.6.0/evil.sh", follow_redirects=False).status_code == 404
    r = client.get(P + "/install.sh", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].endswith("/provider/install.sh")
    assert client.get(P + "/claim").status_code == 200 and client.get(P + "/terms").status_code == 200


def test_super_admin_page(env):
    client, store, fake, s = env
    from innernet2.registry_service.admin_web import new_login_link
    assert client.get(P + "/admin").status_code == 200
    assert client.get(P + "/api/admin/overview").status_code == 401
    assert client.post(P + "/api/admin/login/options", json={}, headers=H).status_code == 404   # no admin yet
    assert client.post(P + "/api/admin/enroll/options", json={"token": "nope"}, headers=H).status_code == 401
    link = new_login_link(store, ORIGIN, P)
    token = link.split("#token=")[1]
    admin = SoftAuthenticator()
    o = client.post(P + "/api/admin/enroll/options", json={"token": token}, headers=H).json()
    assert client.post(P + "/api/admin/enroll/verify", json={"flow": o["flow"], "credential": admin.create(o["options"])},
                       headers=H).status_code == 200
    assert client.post(P + "/api/admin/enroll/options", json={"token": token}, headers=H).status_code == 401  # used once
    # Two machines; the first holds a payout contract the second wants.
    k1, k2 = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    payto = "0x" + "ab" * 20
    assert client.post(P + "/v1/apply", json=provider_record(k1, payto=payto)).status_code == 200
    assert client.post(P + "/v1/apply", json=provider_record(k2, payto=payto)).status_code == 422
    p1 = k1.public_key().public_bytes_raw().hex()
    store.x("INSERT INTO passkeys(cred_id, provider, public_key, sign_count, name, created_at) VALUES ('pk1',?,?,0,'Mac',1)",
            (p1, b"k"))
    ov = client.get(P + "/api/admin/overview").json()
    m = [x for x in ov["machines"] if x["id"] == p1][0]
    assert m["payto"][SEPOLIA] == payto and m["passkeys"][0]["name"] == "Mac" and ov["admins"][0]["name"]
    assert client.post(P + f"/api/admin/machines/{p1}/state", json={"state": "suspended"}, headers=H).status_code == 422
    assert client.post(P + f"/api/admin/machines/{p1}/state", json={"state": "suspended", "reason": "test"},
                       headers=H).status_code == 200
    assert store.provider(p1)["state"] == "suspended"
    assert client.post(P + f"/api/admin/machines/{p1}/state", json={"state": "listed"}, headers=H).status_code == 200
    assert client.post(P + "/api/admin/passkeys/pk1/delete", headers=H).status_code == 200
    assert store.one("SELECT 1 FROM passkeys WHERE cred_id='pk1'") is None
    assert client.post(P + f"/api/admin/machines/{p1}/delete", json={"confirm": "wrong"}, headers=H).status_code == 422
    assert client.post(P + f"/api/admin/machines/{p1}/delete", json={"confirm": p1[:8]}, headers=H).status_code == 200
    assert store.provider(p1) is None
    assert client.post(P + "/v1/apply", json=provider_record(k2, payto=payto)).status_code == 200   # payout free again
    assert client.post(P + f"/api/admin/admins/{b64u(admin.cred_id)}/delete", headers=H).status_code == 409  # last one
    events = {a["event"] for a in client.get(P + "/api/admin/overview").json()["audit"]}
    assert {"admin-passkey-added", "admin-suspended", "admin-deleted", "admin-passkey-deleted"} <= events
    # A provider session is not an admin session, and the admin can sign in again later.
    assert client.post(P + "/api/admin/logout", headers=H).status_code == 200
    assert client.get(P + "/api/admin/overview").status_code == 401
    o = client.post(P + "/api/admin/login/options", json={}, headers=H).json()
    assert client.post(P + "/api/admin/login/verify", json={"flow": o["flow"], "credential": admin.get(o["options"])},
                       headers=H).status_code == 200
    assert client.get(P + "/api/admin/overview").status_code == 200


def test_leaving_machine_frees_its_payout_contract(env):
    client, store, fake, s = env
    k1, k2 = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    payto = "0x" + "ad" * 20
    assert client.post(P + "/v1/apply", json=provider_record(k1, payto=payto)).status_code == 200
    r = client.post(P + "/v1/apply", json=provider_record(k2, payto=payto))
    assert r.status_code == 422 and "press Leave" in r.text
    p1 = k1.public_key().public_bytes_raw().hex()
    assert client.post(P + f"/v1/providers/{p1}/intent", json=intent_record(k1, "leave")).status_code == 200
    assert client.post(P + "/v1/apply", json=provider_record(k2, payto=payto)).status_code == 200


def test_admin_password_sign_in(env, monkeypatch):
    client, store, fake, s = env
    assert client.get(P + "/api/admin/config").json() == {"password": False, "passkey": False}
    monkeypatch.setenv("INNERNET_ADMIN_USER", "shakeel")
    monkeypatch.setenv("INNERNET_ADMIN_PASSWORD", "short")
    assert client.post(P + "/api/admin/login/password", json={"user": "shakeel", "password": "short"},
                       headers=H).status_code == 404                     # under 16 characters: password sign-in off
    monkeypatch.setenv("INNERNET_ADMIN_PASSWORD", "a-long-admin-password-123")
    assert client.get(P + "/api/admin/config").json()["password"] is True
    assert client.post(P + "/api/admin/login/password", json={"user": "shakeel", "password": "wrong-password-xxxxx"},
                       headers=H).status_code == 401
    assert client.post(P + "/api/admin/login/password", json={"user": "shakeel", "password": "a-long-admin-password-123"},
                       ).status_code == 403                               # browser header required
    r = client.post(P + "/api/admin/login/password", json={"user": "shakeel", "password": "a-long-admin-password-123"},
                    headers=H)
    assert r.status_code == 200 and client.get(P + "/api/admin/overview").status_code == 200
    # Signed in with the password, an admin passkey can be added from the page.
    o = client.post(P + "/api/admin/enroll/options", json={}, headers=H).json()
    admin = SoftAuthenticator()
    assert client.post(P + "/api/admin/enroll/verify", json={"flow": o["flow"], "credential": admin.create(o["options"])},
                       headers=H).status_code == 200
    assert client.get(P + "/api/admin/config").json() == {"password": True, "passkey": True}
    for _ in range(8):
        client.post(P + "/api/admin/login/password", json={"user": "x", "password": "y"}, headers=H)
    assert client.post(P + "/api/admin/login/password", json={"user": "shakeel", "password": "a-long-admin-password-123"},
                       headers=H).status_code == 429                      # too many tries from this address

