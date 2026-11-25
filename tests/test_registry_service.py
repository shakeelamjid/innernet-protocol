"""Registry service (IRM-1 M1 part 2): apply, status, CLI login, passkeys, sessions, chain reads, probes."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import socket
import struct
import subprocess
import threading
import time

import pytest

cbor2 = pytest.importorskip("cbor2")
pytest.importorskip("webauthn")

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from innernet2.irm_registry import LOGIN_DOMAIN, sign_descriptor, verify_registry  # noqa: E402
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

    def __call__(self, url, method, params):
        if method == "eth_blockNumber":
            return hex(self.head)
        if method == "eth_getCode":
            return self.code
        if method == "eth_getBlockByNumber":
            return {"timestamp": hex(int(time.time()) - 3600)}
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
                        "CMP-1": {"asset": "USDC", "unit": "Ginstr", "amount": "0.0100"}},
             "limits": {"STO-1": {"max_storage_gib": 200}, "CMP-1": {"max_cpus": 4, "max_memory_mib": 2048}}}
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
    assert d["provider"]["id"] == pid and d["fee_bps"] == 100
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
    e = chain.earnings(store, key.public_key().public_bytes_raw().hex(), 100, since=0)
    assert e["gross"] == 3_500_001 and e["fee"] == 25_000 + 10_001 and e["net"] == e["gross"] - e["fee"]
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
    assert payload["fee_bps"] == 100 and payload["fee_payto"] == {SEPOLIA: FEE_WALLET}
    assert payload["providers"][0]["reputation"]["uptime_7d"] == "1.0000"


def test_pages_and_headers(env):
    client, *_ = env
    for path in ("/dashboard", "/enroll", "/providers/" + "ab" * 32):
        r = client.get(P + path)
        assert r.status_code == 200 and "text/html" in r.headers["content-type"]
        assert "script-src 'self'" in r.headers["content-security-policy"]
        assert r.headers["x-frame-options"] == "DENY"
        assert "style=" not in r.text and "<script>" not in r.text      # nothing inline under the strict CSP
    assert client.get(P + "/static/registry.css").status_code == 200
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
            "--storage-gib", "50", "--compute")
        cli("wallet", "set", "0x" + "9a" * 20)
        assert "Application received" in cli("apply")
        out = cli("status")
        assert "Status: testing" in out and "Earnings (30 days): 0.00 USDC paid" in out
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
