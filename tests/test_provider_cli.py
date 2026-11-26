"""Cross-checks between the Go provider CLI and the Python reference (IRM-1 draft)."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from innernet2.bulk_v080 import BulkError
from innernet2.irm_registry import LOGIN_DOMAIN, make_login_challenge, verify_descriptor, verify_login

ROOT = Path(__file__).resolve().parents[1]
PROVIDER = ROOT / "provider"
GO = shutil.which("go")
pytestmark = pytest.mark.skipif(GO is None, reason="Go toolchain not installed")
PASS = "correct horse battery staple"
PAYOUT = "0x" + "ab" * 20


@pytest.fixture(scope="module")
def binary(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("bin") / "innernet-provider"
    env = {**os.environ, "CGO_ENABLED": "0"}
    subprocess.run([GO, "test", "./..."], cwd=PROVIDER, env=env, check=True, capture_output=True)
    subprocess.run([GO, "build", "-o", str(out), "."], cwd=PROVIDER, env=env, check=True, capture_output=True)
    return out


def run(binary: Path, home: Path, *args: str, ok: bool = True) -> subprocess.CompletedProcess:
    env = {**os.environ, "INNERNET_HOME": str(home), "INNERNET_BACKUP_PASSPHRASE": PASS,
           "INNERNET_REGISTRY": "http://127.0.0.1:9"}
    proc = subprocess.run([str(binary), *args], env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL)
    if ok:
        assert proc.returncode == 0, proc.stderr
    else:
        assert proc.returncode != 0
    return proc


def setup(binary: Path, home: Path) -> None:
    run(binary, home, "init", "--yes", "--network", "base-sepolia", "--name", "lahore-box-1", "--region", "asia-south",
        "--host", "node1.example.test", "--port", "9443", "--storage-gib", "200", "--relay-gib", "500",
        "--compute", "--cpus", "4", "--memory-mib", "2048", "--price-storage", "0.0008")


def test_descriptor_from_go_verifies_in_python(binary, tmp_path):
    setup(binary, tmp_path)
    run(binary, tmp_path, "apply", "--dry-run", ok=False)  # payout contract missing
    run(binary, tmp_path, "wallet", "set", PAYOUT)
    run(binary, tmp_path, "apply", "--dry-run")
    record = json.loads((tmp_path / "descriptor.json").read_text())
    entry = verify_descriptor(record)
    assert entry["services"] == ["STO-1", "RLY-1", "CMP-1"]
    assert entry["payto"] == {"eip155:84532": PAYOUT}
    assert entry["prices"]["STO-1"] == {"asset": "USDC", "unit": "GiB-day", "amount": "0.0008"}
    assert entry["limits"]["CMP-1"] == {"max_cpus": 4, "max_memory_mib": 2048}
    record["payload"]["provider"]["prices"]["STO-1"]["amount"] = "0.0001"
    with pytest.raises(BulkError):
        verify_descriptor(record)


def test_files_and_permissions(binary, tmp_path):
    setup(binary, tmp_path)
    seed = bytes.fromhex((tmp_path / "identity.key").read_text().strip())
    details = (tmp_path / "PROVIDER-DETAILS.txt").read_text()
    assert seed.hex() not in details
    pid = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw().hex()
    assert pid in details and "safe to share" in details
    if os.name == "posix":
        assert (tmp_path / "identity.key").stat().st_mode & 0o777 == 0o600
        assert tmp_path.stat().st_mode & 0o777 == 0o700
        os.chmod(tmp_path / "identity.key", 0o644)
        assert "readable by other users" in run(binary, tmp_path, "show", ok=True).stdout + \
            run(binary, tmp_path, "apply", "--dry-run", ok=False).stderr
    run(binary, tmp_path, "init", "--yes", "--network", "base-sepolia", "--name", "x", "--region", "r", "--host", "h", "--storage-gib", "1",
        ok=False)  # already set up


def test_backup_opens_in_python_and_restores(binary, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    setup(binary, a)
    seed = bytes.fromhex((a / "identity.key").read_text().strip())
    backup = tmp_path / "backup.json"
    run(binary, a, "backup", str(backup))
    doc = json.loads(backup.read_text())
    assert doc["kdf"] == "pbkdf2-hmac-sha256" and doc["iterations"] >= 600000
    key = hashlib.pbkdf2_hmac("sha256", PASS.encode(), bytes.fromhex(doc["salt"]), doc["iterations"], 32)
    aad = (doc["version"] + "\x00" + doc["provider_id"]).encode()
    assert AESGCM(key).decrypt(bytes.fromhex(doc["nonce"]), bytes.fromhex(doc["ciphertext"]), aad) == seed
    assert PASS not in backup.read_text()
    run(binary, b, "restore", str(backup))
    assert (b / "identity.key").read_text().strip() == seed.hex()
    run(binary, b, "restore", str(backup), ok=False)  # refuses to overwrite


def test_login_record_from_go_verifies_in_python(binary, tmp_path):
    setup(binary, tmp_path)
    ch = make_login_challenge(now=1_764_000_000)
    out = run(binary, tmp_path, "login", "--sign-challenge", ch["challenge"],
              "--registry-host", "innernetcorp.com", "--expires", str(ch["expires_at"])).stdout
    record = json.loads(out)
    pid = verify_login(record, expected_challenge=ch["challenge"], registry_host="innernetcorp.com",
                       now=1_764_000_100)
    assert pid.hex() == record["payload"]["provider"]
    for kwargs in ({"expected_challenge": "00" * 32, "registry_host": "innernetcorp.com", "now": 1_764_000_100},
                   {"expected_challenge": ch["challenge"], "registry_host": "evil.example", "now": 1_764_000_100},
                   {"expected_challenge": ch["challenge"], "registry_host": "innernetcorp.com", "now": 1_764_001_000}):
        with pytest.raises(BulkError):
            verify_login(record, **kwargs)
    assert LOGIN_DOMAIN.startswith(b"INNERnet/REG-1/")


def test_apply_reports_unreachable_registry(binary, tmp_path):
    setup(binary, tmp_path)
    run(binary, tmp_path, "wallet", "set", PAYOUT)
    err = run(binary, tmp_path, "apply", ok=False).stderr
    assert "signed form is saved" in err
