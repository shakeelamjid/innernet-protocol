"""INNERnet v0.3.9: experimental *cross-host* immediate encrypted delivery.

Runs an ephemeral responder inside the EXISTING Contabo lab container, with
stdin/stdout carried by the already authenticated OpenSSH control connection.
Unlike v0.3.8 loopback UDP, the packet and its authenticated receipt really
cross between Mac and Contabo. Unlike a VPN or native remote UDP, SSH provides
ordered, reliable TCP transport; packet loss and raw UDP RTT are NOT measured.

Protocol security is an X25519 ephemeral exchange protected by authenticated
SSH, transcript-bound HKDF-SHA256, and the unchanged INNERnet Live AEAD packet
codec with replay protection. This is not a stand-alone peer identity scheme:
remote authentication depends on the known SSH host key and controlled server.
Only synthetic payloads are allowed. No listening internet ports or disk writes.
"""
from __future__ import annotations

import hashlib
import math
import os
import secrets
import select
import shlex
import statistics
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .live import LiveSession, MAX_PAYLOAD

MAX_FRAME = 4096
MAX_SAMPLES = 32
MAX_PROBE_SECONDS = 35.0
MAGIC_CLIENT = b"IC39"
MAGIC_SERVER = b"IS39"
INFO = b"INNERnet/remote-transit/v0.3.9/ssh-ephemeral"


class RemoteTransitError(RuntimeError):
    """No plaintext, SSH credentials, or ephemeral keys should appear in errors."""


def _session_secret(private: X25519PrivateKey, peer_pub: bytes,
                    sid: bytes, initiator_pub: bytes, responder_pub: bytes) -> bytes:
    if len(peer_pub) != 32 or len(sid) != 16:
        raise ValueError("invalid ephemeral session material")
    shared = private.exchange(X25519PublicKey.from_public_bytes(peer_pub))
    salt = hashlib.sha256(INFO + sid + initiator_pub + responder_pub).digest()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=INFO).derive(shared)


def _public(private: X25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(serialization.Encoding.Raw,
                                             serialization.PublicFormat.Raw)


# On Contabo we execute this self-contained code in the ALREADY DEPLOYED lab
# image, which includes innernet2.live. No image rebuild or remote file writes.
# The responder uses the same handshake, HKDF context and packet codec as the
# local initiating client. This code is intentionally constant: never interpolate
# SSH targets, secrets, file paths, or user-supplied data into it.
REMOTE_WORKER = r'''
import hashlib, struct, sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from innernet2.live import LiveSession, MAX_PAYLOAD

INFO = b"INNERnet/remote-transit/v0.3.9/ssh-ephemeral"
def read_exact(n):
    result = bytearray()
    while len(result) < n:
        part = sys.stdin.buffer.read(n-len(result))
        if not part: raise EOFError('framed input ended')
        result.extend(part)
    return bytes(result)
def read_frame():
    length = struct.unpack('!H',read_exact(2))[0]
    if not 1 <= length <= 4096: raise ValueError('frame length')
    return read_exact(length)
def write_frame(data):
    if not 1 <= len(data) <= 4096: raise ValueError('frame length')
    sys.stdout.buffer.write(struct.pack('!H', len(data))+data)
    sys.stdout.buffer.flush()
def run():
    hello = read_frame()
    if len(hello) != 52 or hello[:4] != b'IC39': raise ValueError('invalid client hello')
    sid, initiator_pub = hello[4:20], hello[20:52]
    private = X25519PrivateKey.generate()
    responder_pub = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    shared = private.exchange(X25519PublicKey.from_public_bytes(initiator_pub))
    salt = hashlib.sha256(INFO+sid+initiator_pub+responder_pub).digest()
    secret = HKDF(algorithm=hashes.SHA256(),length=32,salt=salt,info=INFO).derive(shared)
    session = LiveSession(secret,sid,'responder')
    write_frame(b'IS39'+responder_pub+session.encrypt_packet(b'ready'))
    for _ in range(32):
        try: packet = read_frame()
        except EOFError: break
        path, message = session.decrypt_packet(packet)
        if path != 0 or not 1 <= len(message) <= MAX_PAYLOAD: raise ValueError('invalid payload')
        write_frame(session.encrypt_packet(hashlib.sha256(message).digest()))
if __name__ == '__main__':
    run()
'''.strip()


def _read_exact(fd: int, n: int, deadline: float) -> bytes:
    if n < 1 or n > MAX_FRAME:
        raise RemoteTransitError("invalid remote frame length")
    result = bytearray()
    while len(result) < n:
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise RemoteTransitError("encrypted remote receipt timed out")
        readable, _, _ = select.select([fd], [], [], seconds)
        if not readable:
            raise RemoteTransitError("encrypted remote receipt timed out")
        chunk = os.read(fd, n - len(result))
        if not chunk:
            raise RemoteTransitError("remote transit stream ended unexpectedly")
        result.extend(chunk)
    return bytes(result)


def _recv_frame(fd: int, deadline: float) -> bytes:
    n = struct.unpack("!H", _read_exact(fd, 2, deadline))[0]
    if n < 1 or n > MAX_FRAME:
        raise RemoteTransitError("invalid remote frame length")
    return _read_exact(fd, n, deadline)


def _send_frame(proc: subprocess.Popen, frame: bytes) -> None:
    if not 1 <= len(frame) <= MAX_FRAME or proc.stdin is None:
        raise RemoteTransitError("invalid outbound encrypted frame")
    try:
        proc.stdin.write(struct.pack("!H", len(frame)) + frame)
        proc.stdin.flush()
    except (BrokenPipeError, OSError) as exc:
        raise RemoteTransitError("remote transit process disconnected") from exc


def _nearest_rank(values: list[float], fraction: float) -> float:
    return sorted(values)[math.ceil(len(values) * fraction) - 1]


def probe_process(proc: subprocess.Popen, *, samples: int = 15,
                  payload_bytes: int = 256, timeout_seconds: float = 6.0,
                  first_message: bytes | None = None,
                  claimed_scope: str = "local-process-test") -> dict[str, Any]:
    """Measure encrypted acknowledgments across an existing framed process.

    The first payload can be shared with a subsequent storage test, ensuring
    immediate delivery and durable upload refer to the exact same bytes.
    Only a SHA-256 digest (not the payload, keys or plaintext) enters the report.
    """
    if type(samples) is not int or not 1 <= samples <= MAX_SAMPLES:
        raise ValueError("samples must be 1 through 32")
    if type(payload_bytes) is not int or not 1 <= payload_bytes <= MAX_PAYLOAD:
        raise ValueError(f"payload_bytes must be 1 through {MAX_PAYLOAD}")
    if not isinstance(timeout_seconds, (int, float)) or not 0.2 <= timeout_seconds <= 15:
        raise ValueError("invalid per-message timeout")
    if first_message is not None and (not isinstance(first_message, bytes)
                                      or len(first_message) != payload_bytes):
        raise ValueError("first message has wrong size")
    if proc.stdin is None or proc.stdout is None:
        raise RemoteTransitError("process must expose private framed standard streams")
    client_private = X25519PrivateKey.generate()
    sid = secrets.token_bytes(16)
    initiator_pub = _public(client_private)
    started = time.perf_counter()
    _send_frame(proc, MAGIC_CLIENT + sid + initiator_pub)
    ready = _recv_frame(proc.stdout.fileno(), time.monotonic() + timeout_seconds)
    if len(ready) < 36 or ready[:4] != MAGIC_SERVER:
        raise RemoteTransitError("remote handshake was not authenticated")
    responder_pub = ready[4:36]
    secret = _session_secret(client_private, responder_pub, sid,
                             initiator_pub, responder_pub)
    session = LiveSession(secret, sid, "initiator")
    try:
        path, authenticated_ready = session.decrypt_packet(ready[36:])
    except (InvalidTag, ValueError) as exc:
        raise RemoteTransitError("remote handshake failed packet authentication") from exc
    if path != 0 or authenticated_ready != b"ready":
        raise RemoteTransitError("remote handshake readiness mismatch")
    setup_ms = (time.perf_counter() - started) * 1000
    times: list[float] = []
    first_digest = None
    for i in range(samples):
        message = first_message if i == 0 and first_message is not None else secrets.token_bytes(payload_bytes)
        expected_digest = hashlib.sha256(message).digest()
        if i == 0:
            first_digest = expected_digest.hex()
        start_ns = time.perf_counter_ns()
        _send_frame(proc, session.encrypt_packet(message))
        receipt = _recv_frame(proc.stdout.fileno(), time.monotonic() + timeout_seconds)
        try:
            path, acknowledged_digest = session.decrypt_packet(receipt)
        except (InvalidTag, ValueError) as exc:
            raise RemoteTransitError("remote receipt did not authenticate") from exc
        if path != 0 or acknowledged_digest != expected_digest:
            raise RemoteTransitError("remote receipt did not match submitted message")
        times.append((time.perf_counter_ns() - start_ns) / 1_000_000)
    try:
        proc.stdin.close()  # stop the responder; never leave it running
    except OSError:
        pass
    return {
        "tested": True,
        "scope": claimed_scope,
        "carrier": "SSH-framed reliable stream; NOT direct UDP",
        "payload_bytes": payload_bytes,
        "samples": len(times),
        "session_handshake_ms": round(setup_ms, 3),
        "authenticated_receipts": len(times),
        "failed_receipts": 0,
        "p50_ms": round(statistics.median(times), 3),
        "p95_ms": round(_nearest_rank(times, 0.95), 3),
        "min_ms": round(min(times), 3),
        "max_ms": round(max(times), 3),
        "rtt_jitter_successive_abs_median_ms": round(
            statistics.median(abs(b-a) for a,b in zip(times,times[1:])), 3) if len(times) > 1 else "insufficient_samples",
        "first_message_sha256": first_digest,
        "durability": "none; authenticated delivery acknowledgment only",
        "packet_loss": "not measurable through TCP/SSH; reliable retransmission can hide loss",
        "peer_authentication": "SSH host key and remote command, not independent INNERnet node identity",
        "key_agreement": "ephemeral X25519, transcript-bound HKDF-SHA256, INNERnet Live AEAD",
        "caution": "Real cross-host timing only when run via SSH to Contabo. Not raw UDP RTT, a VPN, independent delivery guarantee or proof of remote storage.",
    }


def _finish_process(proc: subprocess.Popen) -> None:
    if proc.stdin is not None and not proc.stdin.closed:
        try:
            proc.stdin.close()
        except OSError:
            pass
    if proc.poll() is None:
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)


def _remote_ssh_args(config: dict, folder: Path) -> list[str]:
    """Use existing authenticated SSH ControlMaster; no new password or port."""
    from .remote_lab import CONTAINER_RE, safe_ssh_target, RemoteLabError
    target = safe_ssh_target(config.get("ssh", ""))
    container = config.get("container", "")
    if not isinstance(container, str) or not CONTAINER_RE.fullmatch(container):
        raise RemoteLabError("invalid lab container reference")
    control = folder.expanduser().absolute() / ".innernet-ssh.sock"
    if control.is_symlink() or not control.exists():
        raise RemoteLabError("SSH control tunnel missing; run one-command qualification")
    args = ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes",
            "-o", "ControlMaster=auto", "-o", f"ControlPath={control}", target]
    remote_argv = ["docker", "exec", "-i", container, "python", "-u", "-c", REMOTE_WORKER]
    args.append(" ".join(shlex.quote(arg) for arg in remote_argv))
    return args


def probe_remote_transit(folder: Path, *, samples: int = 15,
                         payload_bytes: int = 256, timeout_seconds: float = 6.0,
                         first_message: bytes | None = None) -> dict:
    """Cross Mac↔Contabo via SSH stream; no remote service or port exposed."""
    from .remote_lab import read_config
    config = read_config(folder)
    args = _remote_ssh_args(config, folder)
    try:
        proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, bufsize=0)
    except OSError as exc:
        raise RemoteTransitError("could not launch private remote transit process") from exc
    try:
        report = probe_process(proc, samples=samples, payload_bytes=payload_bytes,
                               timeout_seconds=timeout_seconds, first_message=first_message,
                               claimed_scope="Mac-to-Contabo over SSH")
        return report
    finally:
        _finish_process(proc)
