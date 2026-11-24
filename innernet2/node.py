"""HTTP storage node: authorized writes and anonymous, content-addressed reads.

Research pilot, not hardened for arbitrary untrusted internet exposure. Run
behind TLS, a reverse proxy with request quotas, and one worker per node.
"""
from __future__ import annotations
from .version import RELEASE_VERSION

import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import threading
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from .crypto import canonical, digest, public_key_bytes, verify_directory

HEX64 = re.compile(r"^[a-f0-9]{64}$")
MAX_FRAGMENT = 4 * 1024 * 1024
MAX_DIRECTORY_RECORD = 64 * 1024


def private_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())


def initialize_node(base: Path, node_id: str, url: str, capacity_bytes: int = 1 << 28) -> dict:
    if not re.fullmatch(r"node-[a-z0-9-]{1,40}", node_id):
        raise ValueError("invalid node identifier")
    if base.exists():
        raise FileExistsError(f"node directory already exists: {base}")
    base.mkdir(parents=True, mode=0o700)
    (base / "fragments").mkdir(mode=0o700)
    (base / "records").mkdir(mode=0o700)
    sign = Ed25519PrivateKey.generate()
    key = sign.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    write_token = secrets.token_urlsafe(36)
    private_write(base / "node.key", key)
    private_write(base / "write.token", (write_token + "\n").encode())
    config = {"node_id": node_id, "public_url": url, "capacity_bytes": capacity_bytes}
    (base / "config.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    return {"id": node_id, "url": url, "public_key": public_key_bytes(sign.public_key()).hex(), "write_token": write_token}


def create_app(node_dir: str | Path) -> FastAPI:
    base = Path(node_dir).resolve()
    cfg = json.loads((base / "config.json").read_text(encoding="utf-8"))
    identity = Ed25519PrivateKey.from_private_bytes((base / "node.key").read_bytes())
    pub = public_key_bytes(identity.public_key()).hex()
    token = (base / "write.token").read_text(encoding="utf-8").strip()
    mutex = threading.Lock()
    app = FastAPI(title=f"INNERnet Storage {cfg['node_id']}", version=RELEASE_VERSION, docs_url=None, redoc_url=None)
    # Public fragments may be read from browser applications; cross-origin
    # writes remain blocked pending short-lived upload permits.
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "HEAD"])

    def require_write(request: Request):
        auth = request.headers.get("X-Innernet-Write-Token", "")
        if not auth or not hmac.compare_digest(auth.encode("utf-8"), token.encode("utf-8")):
            raise HTTPException(status_code=401, detail="storage admission required")

    def disk_use() -> int:
        return sum(p.stat().st_size for p in (base / "fragments").iterdir() if p.is_file())

    @app.get("/.well-known/innernet-node")
    def info():
        return {"name": "innernet-http-store", "protocol_version": 2, "node_id": cfg["node_id"],
                "public_key": pub, "public_read": True, "authorized_write": True,
                "max_fragment_bytes": MAX_FRAGMENT}

    @app.get("/v2/offer")
    def offer():
        # Signed pilot capability advertisement; not a price quote or lease.
        offer_data = {"protocol_version": 2, "node_id": cfg["node_id"],
                      "public_key": pub, "admission": "operator-token-pilot",
                      "pricing": "not-implemented", "retention_guarantee": False,
                      "max_fragment_bytes": MAX_FRAGMENT,
                      "capacity_bytes": cfg["capacity_bytes"],
                      "available_bytes_reported": max(0, int(cfg["capacity_bytes"]) - disk_use()),
                      "expires_at_unix": int(time.time()) + 90}
        offer_data["signature"] = identity.sign(canonical(offer_data)).hex()
        return JSONResponse(offer_data, headers={"Cache-Control": "no-store"})

    @app.put("/v2/fragments/{fragment_digest}")
    async def put_fragment(fragment_digest: str, request: Request):
        require_write(request)
        if not HEX64.fullmatch(fragment_digest):
            raise HTTPException(status_code=400, detail="invalid content identifier")
        declared = request.headers.get("content-length")
        if declared:
            try:
                if int(declared) > MAX_FRAGMENT:
                    raise HTTPException(status_code=413, detail="fragment too large")
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="invalid content length") from exc
        path = base / "fragments" / fragment_digest
        tmp = None
        try:
            fd, name = tempfile.mkstemp(prefix=".receiving-", dir=base / "fragments")
            tmp = Path(name)
            h = hashlib.sha256()
            written = 0
            with os.fdopen(fd, "wb") as f:
                for_part = request.stream()
                async for block in for_part:
                    written += len(block)
                    if written > MAX_FRAGMENT:
                        raise HTTPException(status_code=413, detail="fragment too large")
                    h.update(block)
                    f.write(block)
                f.flush()
                os.fsync(f.fileno())
            if h.hexdigest() != fragment_digest:
                raise HTTPException(status_code=422, detail="content hash mismatch")
            with mutex:
                if path.exists():
                    # Idempotent PUT; refuse any on-disk content inconsistency.
                    if digest(path.read_bytes()) != fragment_digest:
                        raise HTTPException(status_code=500, detail="stored fragment hash mismatch")
                else:
                    if disk_use() + written > int(cfg["capacity_bytes"]):
                        raise HTTPException(status_code=507, detail="provider capacity exceeded")
                    # Tempfile created with mode 0600; same filesystem, atomic rename.
                    os.replace(tmp, path)
                    folder = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
                    try: os.fsync(folder)
                    finally: os.close(folder)
                    tmp = None
            receipt = {"protocol_version": 2, "node_id": cfg["node_id"], "digest": fragment_digest,
                       "bytes": written, "stored_at_unix": int(time.time()),
                       "retention_guarantee": False}
            receipt["signature"] = identity.sign(canonical(receipt)).hex()
            return receipt
        finally:
            if tmp and tmp.exists():
                tmp.unlink()

    @app.get("/v2/fragments/{fragment_digest}")
    def get_fragment(fragment_digest: str):
        if not HEX64.fullmatch(fragment_digest):
            raise HTTPException(status_code=404, detail="unknown fragment")
        path = base / "fragments" / fragment_digest
        if not path.is_file():
            raise HTTPException(status_code=404, detail="unknown fragment")
        return FileResponse(path, media_type="application/octet-stream", headers={
            "ETag": f'"{fragment_digest}"', "Cache-Control": "public, max-age=86400, immutable",
            "X-Content-Type-Options": "nosniff"})

    @app.put("/v2/records/{lookup}")
    async def put_record(lookup: str, request: Request):
        require_write(request)
        if not HEX64.fullmatch(lookup):
            raise HTTPException(status_code=400, detail="invalid discovery ID")
        data = bytearray()
        async for block in request.stream():
            data.extend(block)
            if len(data) > MAX_DIRECTORY_RECORD:
                raise HTTPException(status_code=413, detail="record too large")
        raw = bytes(data)
        try:
            record = json.loads(raw)
            if not verify_directory(lookup, record):
                raise HTTPException(status_code=422, detail="invalid signed directory record")
            sequence = record["sequence"]
            if type(sequence) is not int or not 0 <= sequence < 2**32:
                raise HTTPException(status_code=422, detail="invalid directory sequence")
        except (ValueError, KeyError, TypeError) as exc:
            raise HTTPException(status_code=422, detail="invalid record") from exc
        target = base / "records" / lookup
        with mutex:
            if target.exists():
                previous = json.loads(target.read_bytes())
                if sequence == previous["sequence"] and record == previous:
                    return {"accepted": True, "sequence": sequence}
                if sequence <= previous["sequence"]:
                    raise HTTPException(status_code=409, detail="stale record version")
                if record["public_key"] != previous["public_key"]:
                    raise HTTPException(status_code=409, detail="record ownership mismatch")
            fd, tmp_name = tempfile.mkstemp(prefix=".record-", dir=base / "records")
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(canonical(record))
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_name, target)
                folder = os.open(target.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
                try: os.fsync(folder)
                finally: os.close(folder)
            finally:
                if os.path.exists(tmp_name):
                    os.unlink(tmp_name)
        return {"accepted": True, "sequence": sequence}

    @app.get("/v2/records/{lookup}")
    def get_record(lookup: str):
        if not HEX64.fullmatch(lookup):
            raise HTTPException(status_code=404, detail="unknown discovery ID")
        path = base / "records" / lookup
        if not path.is_file():
            raise HTTPException(status_code=404, detail="unknown discovery ID")
        return json.loads(path.read_text(encoding="utf-8"))

    return app
