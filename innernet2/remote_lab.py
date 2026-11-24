"""INNERnet RC5: Mac-to-Contabo research-lab client over private SSH tunnels.

The server keeps its nine lab endpoints bound to host loopback. Only synthetic
information may be used with this unaudited pilot. No cloud credentials, x402,
or customer uploads are involved.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import statistics
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import re
import secrets
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx

from .audit import audit_registry
from .network import MeshClient, MAX_CHUNK
from .version import RELEASE_VERSION
from .baseline import one_node_baseline
from .observability import capacity_report, topology_report, load_registry
from .local_retention import local_trial_cleanup
from .immediate_probe import ImmediateProbeError, probe_local_immediate_delivery
from .remote_transit import RemoteTransitError, probe_remote_transit

LAB_COUNT = 9
MAX_TRIAL_BYTES = 100_000_000
REMOTE_BASE = 19400
LOCAL_BASE = 29400
CONTAINER_RE = re.compile(r"^lab-[a-z0-9]+-\d{8}T\d{6}$")
SSH_TARGET_RE = re.compile(r"^(?:[a-zA-Z_][a-zA-Z0-9_.-]*@)?(?:[a-zA-Z0-9][a-zA-Z0-9.-]*|\[[0-9a-fA-F:]+\])$")


class RemoteLabError(RuntimeError):
    """A safe-to-display remote lab operation failed."""


def safe_ssh_target(target: str) -> str:
    if not SSH_TARGET_RE.fullmatch(target) or target.startswith("-"):
        raise ValueError("SSH target must be a hostname/IP or user@hostname, without shell options")
    return target


def ssh_command(target: str, arguments: list[str], *, timeout: float = 90,
                control_path: str | None = None) -> bytes:
    """Run an exact remote argv via SSH with no interpolated shell metacharacters.

    Do not print stdout: one caller retrieves private upload tokens through SSH.
    """
    safe_ssh_target(target)
    if not arguments or not all(isinstance(arg, str) for arg in arguments):
        raise ValueError("invalid remote command")
    remote_cmd = " ".join(shlex.quote(arg) for arg in arguments)
    command = ["ssh", "-T", "-o", "ClearAllForwardings=yes", "-o", "ConnectTimeout=12"]
    if control_path is not None:
        # Reuse the authenticated tunnel's private control socket. Do not fall
        # back to an interactive password or a separate connection mid-test.
        socket = Path(control_path)
        if socket.name != ".innernet-ssh.sock" or socket.parent.is_symlink():
            raise ValueError("invalid SSH control socket path")
        command += ["-o", "ControlMaster=auto", "-o", f"ControlPath={socket}",
                    "-o", "BatchMode=yes"]
    command += [target, remote_cmd]
    try:
        proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              check=False, timeout=timeout)
    except FileNotFoundError as exc:
        raise RemoteLabError("OpenSSH client is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise RemoteLabError("SSH request timed out; check the Contabo SSH connection") from exc
    if proc.returncode:
        # Avoid echoing stderr in case remote tools put an unexpected credential in it.
        raise RemoteLabError(f"SSH request failed (exit {proc.returncode}); check SSH access and lab container")
    return proc.stdout


def discover_lab_container(target: str) -> str:
    listing = ssh_command(target, ["docker", "ps", "--format", "{{.Names}}"])
    names = listing.decode("utf-8").splitlines()
    candidates = [name for name in names if CONTAINER_RE.fullmatch(name)]
    if len(candidates) != 1:
        raise RemoteLabError(f"expected one running lab container; found {len(candidates)}. "
                             "Pass --container with the exact lab container name if needed")
    return candidates[0]


def validate_lab_bundle(peers: Any, writers: Any) -> None:
    if (not isinstance(peers, dict) or not isinstance(peers.get("nodes"), list)
            or len(peers["nodes"]) != LAB_COUNT or not isinstance(writers, dict)
            or not isinstance(writers.get("tokens"), dict)):
        raise RemoteLabError("server returned malformed lab configuration")
    expected_ids = {f"node-{i:02d}" for i in range(1, LAB_COUNT + 1)}
    seen_ids = set()
    keys = set()
    for i, peer in enumerate(peers["nodes"], start=1):
        expected_id = f"node-{i:02d}"
        if (not isinstance(peer, dict) or peer.get("id") != expected_id
                or peer.get("url") != f"http://127.0.0.1:{REMOTE_BASE + i}"
                or peer.get("failure_domain") != f"simulated-group-{'abc'[(i - 1)//3]}"):
            raise RemoteLabError(f"server returned an unexpected {expected_id} entry")
        pub = peer.get("public_key")
        if not isinstance(pub, str) or not re.fullmatch(r"[0-9a-f]{64}", pub):
            raise RemoteLabError("invalid lab node signing key")
        seen_ids.add(expected_id)
        keys.add(pub)
    if seen_ids != expected_ids or len(keys) != LAB_COUNT or set(writers["tokens"]) != expected_ids:
        raise RemoteLabError("incomplete or duplicate lab identities or upload tokens")
    if not all(isinstance(v, str) and 24 <= len(v) <= 256 for v in writers["tokens"].values()):
        raise RemoteLabError("unexpected lab upload credential format")


def local_configuration(peers: dict, writers: dict, local_base: int = LOCAL_BASE) -> tuple[dict, dict]:
    if not 1024 <= local_base <= 64000 - LAB_COUNT:
        raise ValueError("local port base is out of range")
    validate_lab_bundle(peers, writers)
    local_peers = {"nodes": []}
    for i, peer in enumerate(peers["nodes"], start=1):
        local_peers["nodes"].append({**peer, "url": f"http://127.0.0.1:{local_base + i}"})
    local_writers = {
        "tokens": dict(writers["tokens"]),
        "endpoints": {f"node-{i:02d}": f"http://127.0.0.1:{local_base + i}"
                      for i in range(1, LAB_COUNT + 1)},
    }
    return local_peers, local_writers


def ensure_private_directory(path: Path) -> Path:
    path = path.expanduser().absolute()
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise RemoteLabError("lab working directory must be a real directory")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.stat().st_uid != os.getuid():
        raise RemoteLabError("lab working directory is owned by another user")
    path.chmod(0o700)
    return path


def secure_write(path: Path, contents: bytes, *, replace: bool = False) -> None:
    """Use atomic, mode-0600 files; never follow a destination symlink."""
    if path.is_symlink():
        raise RemoteLabError("refusing to write through symlink")
    if path.exists() and not replace:
        raise FileExistsError(f"refusing to overwrite existing private file: {path}")
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "wb") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.lexists(tmp):
            os.unlink(tmp)


def read_config(folder: Path) -> dict:
    path = folder / "config.json"
    if path.is_symlink() or not path.exists() or path.stat().st_mode & 0o077:
        raise RemoteLabError("missing or unsafe local config; run prepare first")
    config = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(config, dict) or not CONTAINER_RE.fullmatch(config.get("container", "")):
        raise RemoteLabError("invalid local configuration")
    safe_ssh_target(config.get("ssh", ""))
    return config


def prepare(ssh_target: str, folder: Path, container: str | None = None,
            local_base: int = LOCAL_BASE) -> dict:
    target = safe_ssh_target(ssh_target)
    container = container or discover_lab_container(target)
    if not CONTAINER_RE.fullmatch(container):
        raise ValueError("container name must identify a Coolify INNERnet lab container")
    # Refuse an accidentally public lab port mapping. None may bind 0.0.0.0.
    port_output = ssh_command(target, ["docker", "port", container]).decode("utf-8")
    mapped = {}
    for line in port_output.splitlines():
        match = re.fullmatch(r"(1940[1-9])/tcp -> (127\.0\.0\.1):(1940[1-9])", line.strip())
        if match and match.group(1) == match.group(3):
            mapped[int(match.group(1))] = True
    if set(mapped) != set(range(19401, 19410)) or len(port_output.splitlines()) != LAB_COUNT:
        raise RemoteLabError("lab ports do not all bind strictly to Contabo 127.0.0.1; "
                             "stop and review Compose before importing upload tokens")
    # Remote lab data is read only; production node1 storage is never accessed.
    raw_peers = ssh_command(target, ["docker", "exec", container, "cat",
                                     "/var/lib/innernet-lab/mesh/peers.json"])
    raw_writers = ssh_command(target, ["docker", "exec", container, "cat",
                                       "/var/lib/innernet-lab/mesh/writers.json"])
    try:
        peers, writers = json.loads(raw_peers), json.loads(raw_writers)
    except (ValueError, UnicodeDecodeError) as exc:
        raise RemoteLabError("invalid JSON received from remote lab") from exc
    local_peers, local_writers = local_configuration(peers, writers, local_base)
    folder = ensure_private_directory(folder)
    existing = folder / "peers.json"
    if existing.exists():
        if existing.is_symlink():
            raise RemoteLabError("refusing existing symlink registry")
        old = json.loads(existing.read_text(encoding="utf-8"))
        pinned_old = {p["id"]: p["public_key"] for p in old["nodes"]}
        pinned_new = {p["id"]: p["public_key"] for p in local_peers["nodes"]}
        if pinned_old != pinned_new:
            raise RemoteLabError("node signing keys changed since first preparation; "
                                 "stop and investigate before trusting new keys")
    config = {"ssh": target, "container": container, "local_base": local_base,
              "caution": "ONE Contabo VPS; simulated failure domains, not independent hosts"}
    secure_write(folder / "peers.json", (json.dumps(local_peers, indent=2) + "\n").encode(), replace=True)
    secure_write(folder / "writers.json", (json.dumps(local_writers, indent=2) + "\n").encode(), replace=True)
    secure_write(folder / "config.json", (json.dumps(config, indent=2) + "\n").encode(), replace=True)
    return {"prepared": True, "nodes": LAB_COUNT, "container": container,
            "local_port_range": f"{local_base+1}-{local_base+LAB_COUNT}",
            "private_config_directory": str(folder),
            "note": "upload tokens saved locally as private files; never commit or share"}


def tunnel_args(config: dict, folder: Path | None = None) -> list[str]:
    base = config["local_base"]
    if type(base) is not int or not 1024 <= base <= 64000-LAB_COUNT:
        raise RemoteLabError("invalid local port base")
    args = ["ssh", "-N", "-T", "-o", "ExitOnForwardFailure=yes", "-o",
            "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3"]
    if folder is not None:
        secure_folder = ensure_private_directory(folder)
        socket = secure_folder / ".innernet-ssh.sock"
        if socket.is_symlink():
            raise RemoteLabError("refusing SSH control socket symlink")
        args += ["-o", "ControlMaster=yes", "-o", f"ControlPath={socket}",
                 "-o", "StreamLocalBindUnlink=yes", "-o", "ControlPersist=no"]
    for i in range(1, LAB_COUNT+1):
        args.extend(["-L", f"127.0.0.1:{base+i}:127.0.0.1:{REMOTE_BASE+i}"])
    args.append(config["ssh"])
    return args


def audit_local(folder: Path) -> dict:
    peers = json.loads((folder / "peers.json").read_text(encoding="utf-8"))
    with httpx.Client(timeout=httpx.Timeout(3.5, connect=1.5), follow_redirects=False, trust_env=False) as client:
        result = audit_registry(peers, client)
    if result["failed"]:
        bad = [entry["node_id"] for entry in result["nodes"] if not entry["ok"]]
        raise RemoteLabError(f"peer audit failed for: {', '.join(str(v) for v in bad)}; "
                             "verify SSH tunnel is running and lab nodes are online")
    return {"nodes_audited": result["passed"], "signatures_verified": result["passed"],
            "note": "public offers do not prove retention or independent providers"}


def fault_set(config: dict, state: str) -> None:
    if state not in {"up", "down"}:
        raise ValueError("invalid fault state")
    command = ["docker", "exec", config["container"], "python", "-m",
               "deploy.lab_control", state, "group-a"]
    try:
        ssh_command(config["ssh"], command, timeout=35,
                    control_path=config.get("_control_socket"))
    except RemoteLabError:
        if state != "up" or not config.get("_control_socket"):
            raise
        # Fail-safe: if the multiplexed tunnel dies while nodes are down,
        # allow ordinary SSH authentication to attempt restoring the lab.
        ssh_command(config["ssh"], command, timeout=45)


def wait_for_audit(folder: Path, expected: int, seconds: float = 18) -> None:
    peers = json.loads((folder / "peers.json").read_text(encoding="utf-8"))["nodes"]
    deadline = time.monotonic()+seconds
    last_count = 0
    with httpx.Client(timeout=0.8, follow_redirects=False, trust_env=False) as client:
        while time.monotonic() < deadline:
            def healthy(peer):
                try:
                    resp = client.get(peer["url"] + "/.well-known/innernet-node")
                    return int(resp.status_code == 200 and resp.json().get("public_key") == peer["public_key"])
                except (httpx.HTTPError, ValueError):
                    return 0
            with ThreadPoolExecutor(max_workers=LAB_COUNT) as pool:
                last_count = sum(pool.map(healthy, peers))
            if last_count == expected:
                return
            time.sleep(0.4)
    raise RemoteLabError(f"expected {expected} reachable nodes, observed {last_count}")


def run_trial(folder: Path, *, simulate_group_a_failure: bool = False,
              data_size: int = 180_000, workers: int = 6,
              profile: bool = False, chunk_bytes: int = MAX_CHUNK,
              preverified_audit: dict | None = None,
              synthetic_payload: bytes | None = None) -> dict:
    if type(chunk_bytes) is not int or not 4096 <= chunk_bytes <= MAX_CHUNK or chunk_bytes % 4096:
        raise ValueError("chunk_bytes must be a 4096-byte multiple between 4096 and 1048576")
    if not 1 <= data_size <= MAX_TRIAL_BYTES:
        raise ValueError("synthetic test file must be between 1 and 100,000,000 bytes")
    if type(workers) is not int or not 1 <= workers <= 9:
        raise ValueError("workers must be between 1 and 9")
    started_at = time.monotonic()
    config = read_config(folder)
    audit_result = audit_local(folder) if preverified_audit is None else preverified_audit
    if audit_result.get("nodes_audited") != LAB_COUNT or audit_result.get("signatures_verified") != LAB_COUNT:
        raise RemoteLabError("full signed lab audit required before trial")
    if simulate_group_a_failure:
        config["_control_socket"] = str(folder.expanduser().absolute() / ".innernet-ssh.sock")
    trial_id = secrets.token_hex(6)
    trials = ensure_private_directory(folder / "trials")
    trial = ensure_private_directory(trials / trial_id)
    source = trial / "synthetic-input.bin"
    # No real personal or business data in unaudited research release.
    if synthetic_payload is not None and (not isinstance(synthetic_payload, bytes)
                                          or len(synthetic_payload) != data_size):
        raise ValueError("synthetic payload must exactly match the requested trial size")
    original = synthetic_payload if synthetic_payload is not None else secrets.token_bytes(data_size)
    secure_write(source, original)
    digest = hashlib.sha256(original).hexdigest()
    peers, writers = folder / "peers.json", folder / "writers.json"
    if writers.is_symlink() or writers.stat().st_mode & 0o077:
        raise RemoteLabError("private upload token file has unsafe permissions")
    # A shared *header-free* HTTP connection pool cuts new TCP/SSH-forward
    # handshakes between write and read phases. The reader MeshClient itself
    # never receives writer tokens; per-write headers are request-scoped.
    transport = httpx.Client(timeout=12.0, follow_redirects=False, trust_env=False)
    publisher = MeshClient(peers, writers, max_workers=workers, profile=profile,
                           http=transport)
    upload_started = time.monotonic()
    def persist_capabilities(reader: str, admin: str) -> None:
        secure_write(trial / "admin.secret", (admin + "\n").encode())
        secure_write(trial / "read.secret", (reader + "\n").encode())

    try:
        result = publisher.upload_file(source, k=4, n=6,
                                       chunk_bytes=chunk_bytes, survive_one_domain=True,
                                       capability_version=3, persist_capabilities=persist_capabilities)
    except BaseException:
        transport.close()
        raise
    upload_profile = publisher.timing_report() if profile else None
    upload_ms = round((time.monotonic() - upload_started) * 1000)
    secret = result.pop("capability")
    result.pop("admin_capability")
    reader = MeshClient(peers, max_workers=workers, profile=profile,
                        http=transport)
    outage_ok = False
    restored = False
    returned_online = None
    try:
        read_started = time.monotonic()
        reader.restore_file(secret, trial / "recovered-normal.bin")
        normal_read_ms = round((time.monotonic() - read_started) * 1000)
        normal_read_profile = reader.timing_report() if profile else None
        restored = hashlib.sha256((trial / "recovered-normal.bin").read_bytes()).hexdigest() == digest
        if not restored:
            raise RemoteLabError("ordinary recovery failed integrity comparison")
        if simulate_group_a_failure:
            # Restoration is in finally, including if reconstruction fails.
            try:
                fault_set(config, "down")
                wait_for_audit(folder, 6)
                outage_started = time.monotonic()
                reader.restore_file(secret, trial / "recovered-with-outage.bin")
                outage_read_ms = round((time.monotonic() - outage_started) * 1000)
                outage_ok = hashlib.sha256((trial / "recovered-with-outage.bin").read_bytes()).hexdigest() == digest
                if not outage_ok:
                    raise RemoteLabError("recovery with three nodes offline failed integrity comparison")
            finally:
                fault_set(config, "up")
                wait_for_audit(folder, 9)
                returned_online = 9
    finally:
        reader.http.close()
    report = {"result": "PASS", "trial_id": trial_id, "mac_generated_bytes": data_size,
              "original_sha256": digest, "signed_peers_audited": audit_result["nodes_audited"],
              "concurrent_workers": workers, "chunk_bytes": chunk_bytes,
              "remote_upload": True, "ordinary_recovery": restored,
              "three_remote_processes_offline_recovery": outage_ok if simulate_group_a_failure else "not-tested",
              "nodes_online_after": returned_online if simulate_group_a_failure else "not-tested",
              "read_client_had_upload_tokens": False,
              "data_shards": result["data_shards"], "metadata_shards": result["metadata_shards"],
              "upload_ms": upload_ms, "ordinary_read_ms": normal_read_ms,
              "upload_mib_s": round(data_size / 1048576 / max(upload_ms / 1000, 0.001), 3),
              "ordinary_read_mib_s": round(data_size / 1048576 / max(normal_read_ms / 1000, 0.001), 3),
              "outage_read_ms": outage_read_ms if simulate_group_a_failure else "not-tested",
              "total_test_ms": round((time.monotonic() - started_at) * 1000),
              "private_read_capability_file": str(trial / "read.secret"),
              "private_admin_capability_file": str(trial / "admin.secret"),
              "caution": "SSH-protected test between Mac and ONE Contabo VPS; no independent storage failure domains"}
    if profile:
        report["profiling"] = {"upload": upload_profile, "normal_read": normal_read_profile,
                               "caution": "Aggregated network request time across parallel workers is not wall time."}
    secure_write(trial / "report.json", (json.dumps(report, indent=2) + "\n").encode())
    return report


def refresh_container_reference(folder: Path) -> dict:
    """Refresh a recreated Coolify container without reimporting credentials.

    Caller must first pass signed live-node audit. Verify every lab service
    remains loopback bound before updating the local container reference.
    """
    config = read_config(folder)
    control_path = str(folder.expanduser().absolute() / ".innernet-ssh.sock")
    listing = ssh_command(config["ssh"], ["docker", "ps", "--format", "{{.Names}}"],
                          control_path=control_path)
    candidates = [name for name in listing.decode().splitlines() if CONTAINER_RE.fullmatch(name)]
    if len(candidates) != 1:
        raise RemoteLabError("expected exactly one running INNERnet lab container")
    current = candidates[0]
    ports = ssh_command(config["ssh"], ["docker", "port", current], control_path=control_path)
    expected = {f"{REMOTE_BASE+i}/tcp -> 127.0.0.1:{REMOTE_BASE+i}"
                for i in range(1, LAB_COUNT + 1)}
    if set(ports.decode().splitlines()) != expected:
        raise RemoteLabError("current INNERnet lab container has unexpected published ports")
    changed = current != config["container"]
    if changed:
        config["container"] = current
        secure_write(folder / "config.json", (json.dumps(config, indent=2) + "\n").encode(), replace=True)
    return {"container_refreshed": changed, "container_present": True}


def _private_capability(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise RemoteLabError("read capability file missing or has unsafe permissions (must be 0600)")
    if path.stat().st_size > 256:
        raise RemoteLabError("invalid read capability file length")
    return path.read_text(encoding="ascii").strip()


def upload_local_file(folder: Path, source: Path, *, acknowledge: bool = False,
                      workers: int = 6) -> dict:
    """Explicit experimental upload; leaves ciphertext on remote lab after command exits."""
    if not acknowledge:
        raise RemoteLabError("confirm research risk with --acknowledge-persistent-storage")
    source = source.expanduser().absolute()
    if source.is_symlink() or not source.is_file() or not 1 <= source.stat().st_size <= MAX_TRIAL_BYTES:
        raise RemoteLabError("input must be a regular, non-symlink file of 1 to 100,000,000 bytes")
    if type(workers) is not int or not 1 <= workers <= 9:
        raise ValueError("workers must be between 1 and 9")
    read_config(folder)
    audit_local(folder)
    writers = folder / "writers.json"
    if writers.is_symlink() or writers.stat().st_mode & 0o077:
        raise RemoteLabError("upload token file has unsafe permissions")
    trial = ensure_private_directory(ensure_private_directory(folder / "trials") / secrets.token_hex(6))
    started = time.monotonic()
    publisher = MeshClient(folder / "peers.json", writers, max_workers=workers,
                           http=httpx.Client(timeout=12.0, follow_redirects=False, trust_env=False))
    # Persist freshly minted secrets before fragment PUTs; never reuse them.
    def persist_capabilities(reader: str, admin: str) -> None:
        secure_write(trial / "admin.secret", (admin + "\n").encode("ascii"))
        secure_write(trial / "read.secret", (reader + "\n").encode("ascii"))

    try:
        stats = publisher.upload_file(source, k=4, n=6,
                                      chunk_bytes=MAX_CHUNK, survive_one_domain=True,
                                      capability_version=3, persist_capabilities=persist_capabilities)
    finally:
        publisher.http.close()
    capability = stats.pop("capability")
    keyfile = trial / "read.secret"
    stats.pop("admin_capability")
    with source.open("rb") as verify_stream:
        sha256 = hashlib.file_digest(verify_stream, "sha256").hexdigest()
    result = {"status": "STORED", "source_bytes": stats["bytes"],
              "source_sha256": sha256,
              "data_shards": stats["data_shards"], "metadata_shards": stats["metadata_shards"],
              "read_capability_file": str(keyfile),
              "admin_capability_file": str(trial / "admin.secret"), "upload_ms": round((time.monotonic()-started)*1000),
              "note": "No automatic retention guarantee or remote deletion; key must remain private."}
    secure_write(trial / "report.json", (json.dumps(result, indent=2) + "\n").encode())
    return result


def restore_local_file(folder: Path, secret_path: Path, destination: Path,
                       *, workers: int = 6) -> dict:
    read_config(folder)
    audit_local(folder)
    secret_path = secret_path.expanduser().absolute()
    secret = _private_capability(secret_path)
    destination = destination.expanduser().absolute()
    if destination.exists() or destination.is_symlink():
        raise RemoteLabError("refusing to overwrite an existing destination file")
    if not destination.parent.is_dir():
        raise RemoteLabError("destination parent directory does not exist")
    reader = MeshClient(folder / "peers.json", max_workers=workers,
                        http=httpx.Client(timeout=12.0, follow_redirects=False, trust_env=False))
    try:
        result = reader.restore_file(secret, destination)
    finally:
        reader.http.close()
    destination.chmod(0o600)
    return {"result": "PASS", "restored_to": str(destination), **result,
            "note": "Restored plaintext is now on the local device."}


def repair_local_file(folder: Path, secret_path: Path, *, acknowledge: bool = False,
                      workers: int = 6, admin_file: Path | None = None) -> dict:
    """Repair missing fragments on the SAME lab nodes after they return."""
    if not acknowledge:
        raise RemoteLabError("repair needs --acknowledge-storage-writes")
    read_config(folder)
    audit_local(folder)
    writers = folder / "writers.json"
    if writers.is_symlink() or not writers.is_file() or writers.stat().st_mode & 0o077:
        raise RemoteLabError("upload token file has unsafe permissions")
    cap = _private_capability(secret_path.expanduser().absolute())
    from .crypto import parse_read_capability
    _, _, v3 = parse_read_capability(cap)
    admin = None
    if v3:
        admin_path = admin_file if admin_file is not None else secret_path.parent / "admin.secret"
        if not admin_path.is_file():
            raise RemoteLabError("v3 repair requires a separate --admin-file (0600)")
        admin = _private_capability(admin_path.expanduser().absolute())
    publisher = MeshClient(folder / "peers.json", writers, max_workers=workers,
                           http=httpx.Client(timeout=12.0, follow_redirects=False, trust_env=False))
    try:
        result = publisher.repair_file(cap, admin_capability=admin)
    finally:
        publisher.http.close()
    return {"status": "PASS", **result,
            "caution": "Same-node repair only. Operator rights and available K-of-N shares are required."}


def bench_sizes(value: str) -> list[int]:
    try:
        sizes = [int(t.strip()) for t in value.split(",")]
    except ValueError as exc:
        raise ValueError("--sizes must be comma-separated byte counts") from exc
    if not 1 <= len(sizes) <= 3 or any(not 1 <= size <= MAX_TRIAL_BYTES for size in sizes):
        raise ValueError("supply 1 to 3 sizes, each 1 through 100,000,000 bytes")
    return sizes


def bench_remote(folder: Path, sizes: list[int], *, workers: int = 6,
                 profile: bool = False, chunk_bytes: int = MAX_CHUNK) -> dict:
    trials = [run_trial(folder, data_size=size, workers=workers,
                        profile=profile, chunk_bytes=chunk_bytes) for size in sizes]
    return {"status": "PASS", "workers": workers, "chunk_bytes": chunk_bytes,
            "results": [{key: trial[key] for key in (
                "trial_id", "mac_generated_bytes", "upload_ms", "ordinary_read_ms",
                "upload_mib_s", "ordinary_read_mib_s")}
                | ({"profiling": trial["profiling"]} if profile else {})
                for trial in trials],
            "caution": "Each run leaves encrypted test fragments on one Contabo VPS; not direct HTTPS baseline."}


def _private_writers(folder: Path) -> Path:
    path = folder / "writers.json"
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise RemoteLabError("missing or unsafe private upload token file; run prepare first")
    return path


def capacity_local(folder: Path, *, warn_at: float = 0.85) -> dict:
    """Read-only, fully signed per-node quota monitoring (not VPS filesystem free)."""
    read_config(folder)
    peers = load_registry(folder / "peers.json")
    with httpx.Client(timeout=httpx.Timeout(4.0, connect=2.0),
                      follow_redirects=False, trust_env=False) as http:
        report = capacity_report(peers, http, warn_at=warn_at)
    report["topology"] = topology_report(peers)
    return report


def baseline_remote(folder: Path, source: Path, *, node_id: str = "node-09") -> dict:
    """Direct one-node HTTP through the SAME SSH tunnel using only synthetic data."""
    read_config(folder)
    _private_writers(folder)
    source = source.expanduser().absolute()
    if source.is_symlink() or not source.is_file() or not 1 <= source.stat().st_size <= MAX_TRIAL_BYTES:
        raise RemoteLabError("baseline source must be a regular synthetic file <= 100 MB")
    http = httpx.Client(timeout=12.0, follow_redirects=False, trust_env=False,
                        limits=httpx.Limits(max_connections=24, max_keepalive_connections=18,
                                            keepalive_expiry=30))
    try:
        mesh = MeshClient(folder / "peers.json", _private_writers(folder), http=http, max_workers=1)
        return one_node_baseline(mesh, source, node_id=node_id)
    finally:
        http.close()


def compare_remote(folder: Path, sizes: list[int], *, workers: int = 6,
                   acknowledge: bool = False, node_id: str = "node-09",
                   profile: bool = False, chunk_bytes: int = MAX_CHUNK) -> dict:
    """One same-file side-by-side lab comparison; both sides persist fragments."""
    if not acknowledge:
        raise RemoteLabError("compare writes persistent test bytes; pass --acknowledge-persistent-storage")
    capacity = capacity_local(folder)
    if capacity["failed"]:
        raise RemoteLabError("cannot benchmark: one or more signed node capacity offers failed")
    available = {n["node_id"]: n["advertised_available_bytes"] for n in capacity["nodes"]}
    if node_id not in available:
        raise RemoteLabError("unrecognized baseline node")
    if any(size > available[node_id] - 4 * 1024 * 1024 for size in sizes):
        raise RemoteLabError("baseline node reports insufficient quota headroom for this benchmark")
    results = []
    for size in sizes:
        mesh = run_trial(folder, data_size=size, workers=workers,
                         profile=profile, chunk_bytes=chunk_bytes)
        raw = Path(mesh["private_read_capability_file"]).parent / "synthetic-input.bin"
        direct = baseline_remote(folder, raw, node_id=node_id)
        results.append({"bytes": size, "mesh_upload_ms": mesh["upload_ms"],
                        "mesh_read_ms": mesh["ordinary_read_ms"],
                        "single_node_upload_ms": direct["upload_ms"],
                        "single_node_read_ms": direct["download_ms"],
                        "baseline_sha256_verified": direct["sha256_verified"],
                        "trial_id": mesh["trial_id"],
                        **({"profiling": mesh["profiling"]} if profile else {})})
    return {"status": "PASS", "workers": workers, "chunk_bytes": chunk_bytes,
            "baseline_node": node_id,
            "results": results,
            "caution": "Same SSH tunnel and payload, NOT direct HTTPS. The one-node baseline "
                       "provides no encryption-at-rest or recovery. Each run leaves fragments on Contabo."}


def wait_for_tunnel_ready(folder: Path, tunnel: subprocess.Popen, *, seconds: float = 45) -> None:
    """Wait for SSH authentication + ControlMaster socket, then all 9 nodes.

    A newly forked SSH process can be waiting on password entry or setting up
    forwards even after it prints its prompt. Do not mistake that as a dead lab.
    The connection must be authenticated before starting an HTTP readiness audit.
    """
    config = read_config(folder)
    control = folder.expanduser().absolute() / ".innernet-ssh.sock"
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        status = tunnel.poll()
        if status is not None:
            raise RemoteLabError(f"SSH tunnel exited before readiness (exit {status}); "
                                 "check SSH authentication, forwarded ports and server connectivity")
        if control.is_symlink():
            raise RemoteLabError("refusing unsafe SSH control socket symlink")
        if control.exists():
            try:
                result = subprocess.run(
                    ["ssh", "-S", str(control), "-O", "check", "-o", "BatchMode=yes", config["ssh"]],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, check=False, timeout=2)
                if result.returncode == 0:
                    remaining = deadline - time.monotonic()
                    wait_for_audit(folder, LAB_COUNT, seconds=max(0.5, remaining))
                    return
            except (OSError, subprocess.TimeoutExpired):
                pass
        time.sleep(0.3)
    raise RemoteLabError("SSH control connection was not ready; check password prompt and existing tunnels")


@contextmanager
def qualification_tunnel(folder: Path):
    """Start one temporary authenticated SSH tunnel, or reuse a v0.3.6 master.

    No credentials are stored. An old non-multiplexed tunnel must be stopped
    first instead of silently binding to its ports or bypassing the pinned lab.
    """
    config = read_config(folder)
    sockpath = folder.expanduser().absolute() / ".innernet-ssh.sock"
    if sockpath.is_symlink():
        raise RemoteLabError("unsafe SSH control socket symlink")
    reusable = False
    if sockpath.exists():
        try:
            check = subprocess.run(["ssh", "-S", str(sockpath), "-O", "check", config["ssh"]],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, check=False, timeout=4)
            reusable = check.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            reusable = False
    tunnel = None
    if not reusable:
        base = config["local_base"]
        with socket.socket() as probe:
            probe.settimeout(0.2)
            if probe.connect_ex(("127.0.0.1", base + 1)) == 0:
                raise RemoteLabError("port already occupied by an older tunnel. Stop Terminal 2 (Ctrl+C) "
                                     "before running the one-command qualification")
        print("Starting private SSH tunnel for one-command qualification; "
              "enter VPS password when prompted.", file=sys.stderr, flush=True)
        tunnel = subprocess.Popen(tunnel_args(config, folder))
        try:
            wait_for_tunnel_ready(folder, tunnel, seconds=45)
        except BaseException:
            tunnel.terminate()
            try:
                tunnel.wait(timeout=5)
            except subprocess.TimeoutExpired:
                tunnel.kill()
                tunnel.wait()
            raise
    try:
        yield
    finally:
        if tunnel is not None:
            tunnel.terminate()
            try:
                tunnel.wait(timeout=5)
            except subprocess.TimeoutExpired:
                tunnel.kill()
                tunnel.wait()



def percentile_ms(values: list[int], rank: float = 0.95) -> int:
    """Nearest-rank percentile; no interpolation, with explicit sample count."""
    if not values or not 0 < rank <= 1:
        raise ValueError("percentile requires nonempty samples and valid rank")
    return sorted(values)[max(0, math.ceil(rank * len(values)) - 1)]


def repeat_verified_reads(folder: Path, trial: dict, *, workers: int, count: int) -> dict:
    """Read an already-uploaded synthetic object; never issue remote writes.

    Uses the same authenticated read-only client for all repeated restores, so
    short-lived signed discovery-cache hits are measurable. All restored files
    are checked for integrity and removed from the private trial directory.
    """
    if type(count) is not int or not 1 <= count <= 9:
        raise ValueError("read repeat count must be 1 through 9")
    trial_folder = Path(trial["private_read_capability_file"]).parent
    capability = _private_capability(trial_folder / "read.secret")
    source = trial_folder / "synthetic-input.bin"
    if source.is_symlink() or not source.is_file():
        raise RemoteLabError("missing synthetic source for repeated read verification")
    expected_size = source.stat().st_size
    with source.open("rb") as handle:
        expected_digest = hashlib.file_digest(handle, "sha256").digest()
    timings = []
    with httpx.Client(timeout=12.0, follow_redirects=False, trust_env=False) as http:
        reader = MeshClient(folder / "peers.json", max_workers=workers, http=http, profile=True)
        for _ in range(count):
            restored = trial_folder / f".repeat-check-{secrets.token_hex(6)}.bin"
            try:
                started = time.monotonic()
                info = reader.restore_file(capability, restored)
                elapsed_ms = round(1000 * (time.monotonic() - started))
                with restored.open("rb") as stream:
                    observed = hashlib.file_digest(stream, "sha256").digest()
                if info["bytes"] != expected_size or observed != expected_digest:
                    raise RemoteLabError("repeated synthetic read failed SHA-256 verification")
                timings.append(elapsed_ms)
            finally:
                restored.unlink(missing_ok=True)
        stages = reader.timing_report()["stages"]
    warm = timings[1:]
    return {"samples": count, "read_ms": timings,
            "first_read_ms": timings[0], "warm_samples": len(warm),
            "warm_p50_ms": round(statistics.median(warm), 1) if warm else "not-measured",
            "warm_p95_ms": percentile_ms(warm) if len(warm) >= 5 else "insufficient_samples",
            "p50_ms": round(statistics.median(timings), 1),
            "p95_ms": percentile_ms(timings) if count >= 5 else "insufficient_samples",
            "signed_discovery_cache_hits": stages.get("network.discovery_cache_hit", {}).get("calls", 0),
            "verified_sha256": True}


def small_message_probe(folder: Path, *, workers: int, probes: int,
                        verified_audit: dict, synthetic_payload: bytes | None = None) -> dict:
    """One tiny synthetic object, then independent read-only latency samples.

    Measures *store-and-retrieve latency*, not packet RTT or VPN performance.
    The tiny encrypted fragments remain remotely stored in the lab.
    """
    if type(probes) is not int or not 0 <= probes <= 9:
        raise ValueError("latency probes must be between 0 and 9")
    if not probes:
        return {"tested": False}
    trial = run_trial(folder, data_size=256, workers=workers, profile=False,
                      simulate_group_a_failure=False, preverified_audit=verified_audit,
                      synthetic_payload=synthetic_payload)
    repeated = repeat_verified_reads(folder, trial, workers=workers, count=probes)
    tiny_source = Path(trial["private_read_capability_file"]).parent / "synthetic-input.bin"
    direct = baseline_remote(folder, tiny_source, node_id="node-09")
    if not direct.get("sha256_verified"):
        raise RemoteLabError("tiny single-node baseline failed SHA-256 verification")
    return {"tested": True, "payload_bytes": 256,
            "message_sha256": trial["original_sha256"],
            "upload_ms": trial["upload_ms"],
            "store_then_first_restore_ms": trial["upload_ms"] + trial["ordinary_read_ms"],
            "durability": "test fragments accepted; independent retention not verified",
            "single_node_baseline_ms": {"upload": direct["upload_ms"], "read": direct["download_ms"]},
            "first_restore_ms": trial["ordinary_read_ms"],
            "repeated_restores": repeated,
            "kind": "encrypted distributed storage read latency, not VPN/packet RTT",
            "caution": "Same SSH tunnel and one VPS; cached discovery may be stale up to 10 seconds"}


def qualify_lab(folder: Path, sizes: list[int], *, workers: int = 6,
                repeats: int = 1, outage: bool = True, profile: bool = True,
                acknowledge: bool = False, baseline_node: str = "node-09",
                read_repeats: int = 1, latency_probes: int = 0,
                immediate_probes: int = 0, remote_probes: int = 0) -> dict:
    """Single bounded acceptance test: one audit, comparison, optional outage.

    No secrets, plaintext paths or capability strings in the report. One
    synthetic transfer per sample, not a separate outage upload and baseline
    upload. The first sample alone performs the group-a outage simulation.
    """
    if not acknowledge:
        raise RemoteLabError("qualification stores lab fragments; pass --acknowledge-persistent-storage")
    if type(repeats) is not int or not 1 <= repeats <= 5:
        raise ValueError("repeats must be between 1 and 5")
    if type(workers) is not int or not 1 <= workers <= 9:
        raise ValueError("workers must be between 1 and 9")
    if len(sizes) * repeats > 10:
        raise ValueError("qualification limited to 10 synthetic trials")
    if type(read_repeats) is not int or not 1 <= read_repeats <= 9:
        raise ValueError("read_repeats must be 1 through 9")
    if type(latency_probes) is not int or not 0 <= latency_probes <= 9:
        raise ValueError("latency_probes must be 0 through 9")
    if type(immediate_probes) is not int or not 0 <= immediate_probes <= 25:
        raise ValueError("immediate_probes must be 0 through 25")
    if type(remote_probes) is not int or not 0 <= remote_probes <= 32:
        raise ValueError("remote_probes must be 0 through 32")
    signed = audit_local(folder)  # only once; all nine signing keys verified
    capacity = capacity_local(folder)
    if capacity.get("failed"):
        raise RemoteLabError("signed node capacity preflight failed")
    available = {node["node_id"]: node["advertised_available_bytes"]
                 for node in capacity["nodes"]}
    if baseline_node not in available:
        raise RemoteLabError("baseline node missing from signed capacity report")
    # Conservative accounting: repeated test fragments persist on the lab.
    # Do not consume a node's advertised quota close to its limit.
    required_headroom = sum(sizes) * repeats * 2 + 4 * 1024 * 1024
    if latency_probes:
        required_headroom += 1024 * 1024  # one additional 256-byte synthetic object
    if any(free < required_headroom for free in available.values()):
        raise RemoteLabError("insufficient signed per-node quota headroom for all qualification trials")
    ref = refresh_container_reference(folder) if (outage or remote_probes) else {"container_refreshed": False}
    # Actual Mac-to-Contabo immediate encrypted receipts, followed (on explicit
    # request) by separately storing the SAME first synthetic message. This
    # does not claim background replication or independent retention.
    shared = secrets.token_bytes(256) if remote_probes and latency_probes else None
    immediate_remote = (probe_remote_transit(folder, samples=remote_probes, payload_bytes=256,
                                             first_message=shared)
                        if remote_probes else {"tested": False})
    tiny = (small_message_probe(folder, workers=workers, probes=latency_probes,
                                verified_audit=signed, synthetic_payload=shared)
            if latency_probes else {"tested": False})
    if shared is not None and (immediate_remote.get("first_message_sha256")
                               != tiny.get("message_sha256")
                               or tiny.get("message_sha256") != hashlib.sha256(shared).hexdigest()):
        raise RemoteLabError("cross-mode synthetic message SHA-256 mismatch")
    results = []
    for size in sizes:
        for repeat in range(repeats):
            trial = run_trial(folder, data_size=size, workers=workers, profile=profile,
                              simulate_group_a_failure=outage and not results,
                              preverified_audit=signed)
            source = Path(trial["private_read_capability_file"]).parent / "synthetic-input.bin"
            baseline = baseline_remote(folder, source, node_id=baseline_node)
            if not baseline["sha256_verified"] or not trial["ordinary_recovery"]:
                raise RemoteLabError("qualify failed content-integrity verification")
            stages = trial.get("profiling", {})
            def core_stages(phase):
                selected = ("network.discovery_resolve", "network.discovery_publish",
                            "upload.fragment_wave", "read.primary_wave", "read.parity_wave",
                            "codec.encode", "codec.decode", "crypto.chunk_encrypt",
                            "crypto.chunk_decrypt")
                all_stages = stages.get(phase, {}).get("stages", {})
                return {name: all_stages[name]["cumulative_ms"] for name in selected if name in all_stages}
            # Read-only repetitions use the already-uploaded object; no
            # additional persistent remote fragments are generated.
            read_distribution = (repeat_verified_reads(folder, trial, workers=workers,
                                 count=read_repeats) if read_repeats > 1 else None)
            results.append({
                "bytes": size, "repeat": repeat + 1,
                "mesh_upload_ms": trial["upload_ms"],
                "mesh_read_ms": trial["ordinary_read_ms"],
                "single_node_upload_ms": baseline["upload_ms"],
                "single_node_read_ms": baseline["download_ms"],
                "sha256_verified": True,
                "outage_recovery": trial["three_remote_processes_offline_recovery"],
                **({"read_only_repetitions": read_distribution} if read_distribution else {}),
                **({"profile_ms": {"upload": core_stages("upload"),
                                   "read": core_stages("normal_read")}} if profile else {}),
            })
    summary = []
    for size in sizes:
        group = [entry for entry in results if entry["bytes"] == size]
        stats = {key: round(statistics.median(entry[key] for entry in group), 1)
                 for key in ("mesh_upload_ms", "mesh_read_ms",
                             "single_node_upload_ms", "single_node_read_ms")}
        # A high-percentile statistic on fewer than five samples is misleading.
        distribution = [ms for entry in group for ms in
                        entry.get("read_only_repetitions", {}).get("read_ms", [])]
        summary.append({"bytes": size, "samples": len(group), "median_ms": stats,
                        "p95_ms": ({key: percentile_ms([entry[key] for entry in group])
                                    for key in stats} if len(group) >= 5 else "insufficient_samples"),
                        "read_only_distribution": ({"samples": len(distribution),
                                "p50_ms": round(statistics.median(distribution), 1),
                                "p95_ms": percentile_ms(distribution) if len(distribution) >= 5
                                          else "insufficient_samples"} if distribution
                                else "not-requested")})
    immediate = (probe_local_immediate_delivery(samples=immediate_probes)
                 if immediate_probes else {"tested": False})
    from .version import RELEASE_VERSION
    return {"status": "PASS", "version": RELEASE_VERSION, "nodes_audited": signed["nodes_audited"],
            "signatures_verified": signed["signatures_verified"], "workers": workers,
            "samples": len(results), "container_refreshed": ref["container_refreshed"],
            "outage_tested": outage, "topology": {
                "independent_infrastructure_verified": capacity["topology"]["independent_infrastructure_verified"],
                "distinct_advertised_hostnames": capacity["topology"]["distinct_advertised_hostnames"]},
            "summary": summary, "results": results, "small_message": tiny,
            "immediate_delivery_local": immediate,
            "immediate_delivery_remote": immediate_remote,
            "dual_delivery": ({"tested": True, "same_synthetic_message_sha256_verified": True,
                               "immediate_receipt_ms_p50": immediate_remote["p50_ms"],
                               "separate_storage_upload_ms": tiny["upload_ms"],
                               "separate_storage_first_read_ms": tiny["first_restore_ms"],
                               "note": "Remote acknowledgment first, then independently submitted to durable lab; not background replication or verified retention."}
                              if shared is not None else {"tested": False}),
            "delivery_modes": {"remote_durable": "encrypted fragmented storage with verified recovery",
                               "local_immediate": "ephemeral authenticated UDP loopback (no storage)",
                               "remote_immediate": "ephemeral authenticated Live packets over SSH-framed TCP (no storage)"},
            "caution": "One SSH-tunneled VPS, not independent providers or direct HTTPS. "
                       "Each trial leaves encrypted fragments on the lab; no remote cleanup."}


def inspect_local_file(folder: Path, secret_path: Path, *, workers: int = 6) -> dict:
    read_config(folder)
    secret = _private_capability(secret_path.expanduser().absolute())
    with httpx.Client(timeout=12.0, follow_redirects=False, trust_env=False) as http:
        reader = MeshClient(folder / "peers.json", max_workers=workers, http=http)
        return reader.inspect_file(secret)


def maintenance_once(folder: Path, *, workers: int = 6, max_objects: int = 3,
                     execute: bool = False, acknowledge: bool = False) -> dict:
    """One-shot repair sweep, suitable for EXTERNAL scheduling; no daemon installed.

    Default mode audits only. Authorized repair needs explicit two flags.
    Capability contents are never included in reports.
    """
    read_config(folder)
    if type(max_objects) is not int or not 1 <= max_objects <= 20:
        raise ValueError("max_objects must be an integer from 1 to 20")
    if execute and not acknowledge:
        raise RemoteLabError("writes require --acknowledge-storage-writes")
    if execute:
        _private_writers(folder)
    root = folder / "trials"
    if not root.is_dir() or root.is_symlink():
        return {"objects_scanned": 0, "mode": "repair" if execute else "audit", "results": []}
    secrets_list = sorted((p / "read.secret" for p in root.iterdir()
                           if p.is_dir() and not p.is_symlink() and
                           re.fullmatch(r"[0-9a-f]{12}", p.name) and (p / "read.secret").is_file()))
    report = []
    for cap in secrets_list[:max_objects]:
        try:
            if execute:
                result = repair_local_file(folder, cap, acknowledge=True, workers=workers)
            else:
                result = inspect_local_file(folder, cap, workers=workers)
            report.append({"trial_id": cap.parent.name, "status": "ok", "result": result})
        except Exception as exc:
            # Do not include untrusted response text or secret path in operator logs.
            report.append({"trial_id": cap.parent.name, "status": "error",
                           "error_type": type(exc).__name__})
    return {"mode": "repair" if execute else "audit", "objects_scanned": len(report),
            "more_objects_not_scanned": max(0, len(secrets_list) - max_objects),
            "results": report,
            "caution": "Local one-shot sweep only; no automatic scheduler or migrations. "
                       "Read secrets are never printed."}


def main() -> None:
    parser = argparse.ArgumentParser(description=f"INNERnet {RELEASE_VERSION} experimental research transit + storage pilot")
    parser.add_argument("--dir", default="~/innernet-lab", help="private Mac directory, default ~/innernet-lab")
    sub = parser.add_subparsers(dest="command", required=True)
    local_probe = sub.add_parser("immediate-probe", help="experimental authenticated UDP loopback, never a VPN or internet RTT")
    local_probe.add_argument("--samples", type=int, default=9)
    local_probe.add_argument("--bytes", type=int, default=256)
    remote_probe = sub.add_parser("remote-immediate", help="real Mac-to-Contabo encrypted delivery over private SSH, no storage")
    remote_probe.add_argument("--samples", type=int, default=15)
    remote_probe.add_argument("--bytes", type=int, default=256)
    p = sub.add_parser("prepare", help="fetch pinned lab identities and operator tokens securely over SSH")
    p.add_argument("--ssh", required=True, help="e.g. root@CONTABO_IP; use your normal SSH known_hosts")
    p.add_argument("--container", help="optional exact lab container name; normally auto-detected")
    p.add_argument("--local-port-base", type=int, default=LOCAL_BASE)
    sub.add_parser("tunnel", help="keep private localhost-only forwarding open (separate Terminal)")
    sub.add_parser("audit", help="verify nine lab identities and signatures through SSH tunnel")
    t = sub.add_parser("test", help="upload and recover a synthetic file from Mac through tunneled lab")
    t.add_argument("--outage", action="store_true", help="test loss of all 3 simulated group-a processes")
    t.add_argument("--bytes", type=int, default=180000, help="synthetic payload size, max 100,000,000")
    t.add_argument("--workers", type=int, default=6, help="concurrent HTTP operations, 1 to 9")
    t.add_argument("--profile", action="store_true", help="include aggregate stage timings, never secrets")
    t.add_argument("--chunk-bytes", type=int, default=MAX_CHUNK,
                   help="file chunk size (default 1048576; 65536 for legacy comparison)")
    b = sub.add_parser("benchmark", help="run real SSH-tunnel upload/read trials at selected byte sizes")
    b.add_argument("--sizes", default="1048576,10485760", help="comma-separated byte sizes, max 100000000")
    b.add_argument("--workers", type=int, default=6, help="1 for sequential baseline, 6 default")
    b.add_argument("--profile", action="store_true", help="include aggregate stage timings")
    b.add_argument("--chunk-bytes", type=int, default=MAX_CHUNK)
    up = sub.add_parser("file-upload", help="store a real file in the unaudited persistent lab")
    up.add_argument("--input", type=Path, required=True)
    up.add_argument("--workers", type=int, default=6)
    up.add_argument("--acknowledge-persistent-storage", action="store_true", required=True,
                    help="acknowledge unaudited security and persistent encrypted fragments")
    down = sub.add_parser("file-restore", help="recover a file with a separate read-only client")
    down.add_argument("--secret-file", type=Path, required=True)
    down.add_argument("--output", type=Path, required=True)
    down.add_argument("--workers", type=int, default=6)
    repair = sub.add_parser("repair", help="owner-triggered same-node recovery of missing fragments")
    repair.add_argument("--secret-file", type=Path, required=True)
    repair.add_argument("--admin-file", type=Path, help="required v3 administrator secret; auto-detected beside read.secret")
    repair.add_argument("--workers", type=int, default=6)
    repair.add_argument("--acknowledge-storage-writes", action="store_true", required=True)
    cap = sub.add_parser("capacity", help="signed read-only per-node logical quota report")
    cap.add_argument("--warn-at", type=float, default=0.85, help="warn when >= this fraction full")
    topology = sub.add_parser("topology", help="offline declared failure-domain assessment")
    topology.add_argument("--peers", type=Path, help="override local lab peer registry JSON")
    comparison = sub.add_parser("compare", help="mesh vs one-node baseline, through same SSH tunnel")
    comparison.add_argument("--sizes", default="1048576,10485760")
    comparison.add_argument("--workers", type=int, default=6)
    comparison.add_argument("--baseline-node", default="node-09")
    comparison.add_argument("--profile", action="store_true", help="profile mesh stages without exposing secrets")
    comparison.add_argument("--chunk-bytes", type=int, default=MAX_CHUNK)
    comparison.add_argument("--acknowledge-persistent-storage", action="store_true", required=True)
    qualification = sub.add_parser("qualify", help="one combined audit, capacity, performance, integrity and outage run")
    qualification.add_argument("--sizes", default="1048576", help="one or more synthetic byte sizes, max 3")
    qualification.add_argument("--workers", type=int, default=6)
    qualification.add_argument("--repeats", type=int, default=1, help="fresh upload repeats, default 1 to limit persistent fragments")
    qualification.add_argument("--read-repeats", type=int, default=5,
                               help="read-only repeat samples per object, default 5 for p95")
    qualification.add_argument("--latency-probes", type=int, default=5,
                               help="small 256-byte encrypted object and repeated read-only samples; 0 to disable")
    qualification.add_argument("--no-outage", action="store_true", help="skip disruptive three-process outage")
    qualification.add_argument("--immediate-probes", type=int, default=9,
                               help="local authenticated UDP loopback probes, 0 to disable")
    qualification.add_argument("--remote-probes", type=int, default=15,
                               help="real SSH-carried encrypted Mac-to-Contabo receipts, 0 to disable")
    qualification.add_argument("--no-profile", action="store_true", help="skip timing breakdown")
    qualification.add_argument("--native-udp-host", help="OPTIONAL: separately deployed public native UDP responder host")
    qualification.add_argument("--native-udp-identity", type=Path, help="private Mac Ed25519 seed (0600)")
    qualification.add_argument("--native-udp-server-key", help="pinned server Ed25519 public key (hex)")
    qualification.add_argument("--native-udp-port", type=int, default=29410)
    qualification.add_argument("--native-udp-samples", type=int, default=30)
    qualification.add_argument("--acknowledge-persistent-storage", action="store_true", required=True)
    inspection = sub.add_parser("inspect", help="read-only full hash verification of one stored file")
    inspection.add_argument("--secret-file", type=Path, required=True)
    inspection.add_argument("--workers", type=int, default=6)
    maintenance = sub.add_parser("maintenance", help="one-shot read-only audit or explicit authorized repair")
    maintenance.add_argument("--workers", type=int, default=6)
    maintenance.add_argument("--max-objects", type=int, default=3)
    maintenance.add_argument("--execute-repair", action="store_true")
    maintenance.add_argument("--acknowledge-storage-writes", action="store_true")
    cleanup = sub.add_parser("cleanup-local", help="dry-run synthetic local file cleanup; never remote")
    cleanup.add_argument("--older-than-days", type=int, default=30)
    cleanup.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    folder = Path(args.dir).expanduser()
    try:
        if args.command == "immediate-probe":
            print(json.dumps(probe_local_immediate_delivery(samples=args.samples,
                                                              payload_bytes=args.bytes), indent=2))
        elif args.command == "remote-immediate":
            with qualification_tunnel(folder):
                refresh_container_reference(folder)
                print(json.dumps(probe_remote_transit(folder, samples=args.samples,
                       payload_bytes=args.bytes), indent=2))
        elif args.command == "prepare":
            result = prepare(args.ssh, folder, args.container, args.local_port_base)
            print(json.dumps(result, indent=2))
        elif args.command == "tunnel":
            config = read_config(folder)
            print("Opening 9 loopback-only SSH forwards; keep this Terminal open. Ctrl-C ends tunnels.", flush=True)
            raise SystemExit(subprocess.call(tunnel_args(config, folder)))
        elif args.command == "audit":
            print(json.dumps(audit_local(folder), indent=2))
        elif args.command == "test":
            print(json.dumps(run_trial(folder, simulate_group_a_failure=args.outage,
                                       data_size=args.bytes, workers=args.workers, profile=args.profile,
                                       chunk_bytes=args.chunk_bytes), indent=2))
        elif args.command == "benchmark":
            print(json.dumps(bench_remote(folder, bench_sizes(args.sizes), workers=args.workers,
                                          profile=args.profile, chunk_bytes=args.chunk_bytes), indent=2))
        elif args.command == "file-upload":
            print(json.dumps(upload_local_file(folder, args.input,
                      acknowledge=args.acknowledge_persistent_storage, workers=args.workers), indent=2))
        elif args.command == "file-restore":
            print(json.dumps(restore_local_file(folder, args.secret_file, args.output,
                      workers=args.workers), indent=2))
        elif args.command == "repair":
            print(json.dumps(repair_local_file(folder, args.secret_file,
                      acknowledge=args.acknowledge_storage_writes, workers=args.workers,
                      admin_file=args.admin_file), indent=2))
        elif args.command == "capacity":
            print(json.dumps(capacity_local(folder, warn_at=args.warn_at), indent=2))
        elif args.command == "topology":
            registry = load_registry(args.peers or folder / "peers.json")
            print(json.dumps(topology_report(registry), indent=2))
        elif args.command == "compare":
            print(json.dumps(compare_remote(folder, bench_sizes(args.sizes), workers=args.workers,
                   acknowledge=args.acknowledge_persistent_storage, node_id=args.baseline_node,
                   profile=args.profile, chunk_bytes=args.chunk_bytes), indent=2))
        elif args.command == "qualify":
            if not args.acknowledge_persistent_storage:
                raise RemoteLabError("qualify needs --acknowledge-persistent-storage")
            from .native_udp import native_probe, load_identity, parse_public_hex, local_qualification
            native_args = (args.native_udp_host, args.native_udp_identity, args.native_udp_server_key)
            if any(item is not None for item in native_args) and not all(item is not None for item in native_args):
                raise RemoteLabError("native UDP requires --native-udp-host, --native-udp-identity and --native-udp-server-key together")
            with qualification_tunnel(folder):
                summary = qualify_lab(folder, bench_sizes(args.sizes), workers=args.workers,
                       repeats=args.repeats, outage=not args.no_outage,
                       profile=not args.no_profile, read_repeats=args.read_repeats,
                       latency_probes=args.latency_probes,
                       immediate_probes=args.immediate_probes, remote_probes=args.remote_probes,
                       acknowledge=True)
                # No added remote writes; this is a distinct localhost-native-UDP
                # identity/handshake benchmark, NOT cross-host UDP evidence.
                summary["native_udp_local"] = local_qualification(samples=30, payload_bytes=256)
                if args.native_udp_host is not None:
                    summary["native_udp_remote"] = native_probe(
                        args.native_udp_host, args.native_udp_port,
                        load_identity(args.native_udp_identity),
                        parse_public_hex(args.native_udp_server_key),
                        samples=args.native_udp_samples)
                else:
                    summary["native_udp_remote"] = {"tested": False,
                        "reason": "requires separate opt-in native UDP service with pinned Ed25519 peers; no public port automatically opened"}
                print(json.dumps(summary, indent=2))
        elif args.command == "inspect":
            print(json.dumps(inspect_local_file(folder, args.secret_file, workers=args.workers), indent=2))
        elif args.command == "maintenance":
            print(json.dumps(maintenance_once(folder, workers=args.workers, max_objects=args.max_objects,
                   execute=args.execute_repair, acknowledge=args.acknowledge_storage_writes), indent=2))
        elif args.command == "cleanup-local":
            print(json.dumps(local_trial_cleanup(folder, older_than_days=args.older_than_days,
                   execute=args.execute), indent=2))
    except (RemoteLabError, RemoteTransitError, ImmediateProbeError, FileExistsError, ValueError, OSError, httpx.HTTPError) as exc:
        print(f"INNERnet lab error: {exc}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
