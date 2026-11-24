"""UV10-1 candidate application payload format for existing recipient-encrypted OB80.

UV10 local containers are PLAINTEXT. Only OB80 delivery encrypts them. Treat local
staging as sensitive; never transmit a bare .uv10 file as though it were secure.
This is an experimental release candidate, NOT a reviewed universal standard.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import struct
import tempfile
import time
from typing import BinaryIO

from .bulk_v080 import MAX_OBJECT_BYTES

MAGIC = b"UV10"
VERSION = "UV10-1"
HEADER_LIMIT = 4096
MAX_MESSAGE = 65536
MAX_STREAM_SEGMENTS = 8192
CHUNK = 1024 * 1024
KINDS = frozenset({"message", "file", "event", "stream-segment"})
ALLOWED_FIELDS = frozenset({"version", "kind", "content_type", "name", "size", "sha256",
                            "created_at", "stream_id", "sequence", "final", "attributes"})
MIME = re.compile(r"^[a-z0-9][a-z0-9.+-]{0,49}/[a-z0-9][a-z0-9.+-]{0,49}$")
TOKEN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.-]{0,39}$")


class UniversalError(ValueError):
    pass


def _strict_json_loads(raw):
    def invalid_constant(label):
        raise ValueError("non-standard JSON constant: " + label)
    return json.loads(raw, parse_constant=invalid_constant)


def _canonical(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _verify_header(h: dict) -> dict:
    if not isinstance(h, dict) or set(h) != ALLOWED_FIELDS:
        raise UniversalError("invalid application header fields")
    if h["version"] != VERSION or not isinstance(h["kind"], str) or h["kind"] not in KINDS:
        raise UniversalError("unknown application kind or version")
    if not isinstance(h["content_type"], str) or not MIME.fullmatch(h["content_type"]):
        raise UniversalError("invalid media type")
    name = h["name"]
    if not isinstance(name, str) or not 1 <= len(name) <= 100 or name in (".", "..") or any(
        c in name for c in ("/", "\\", "\x00", ":")) or name.startswith("."):
        raise UniversalError("unsafe display name")
    def safe_text(value):
        return not any(0xD800 <= ord(c) <= 0xDFFF or ord(c) < 0x20 or ord(c) == 0x7f
                       for c in value)
    if not safe_text(name):
        raise UniversalError("invalid control or surrogate codepoint")
    if type(h["size"]) is not int or not 0 <= h["size"] < MAX_OBJECT_BYTES:
        raise UniversalError("invalid payload length")
    if h["kind"] in ("message", "event") and h["size"] > MAX_MESSAGE:
        raise UniversalError("message/event exceeds 64 KiB")
    if (not isinstance(h["sha256"], str) or not re.fullmatch("[0-9a-f]{64}", h["sha256"])):
        raise UniversalError("invalid SHA-256 digest")
    if type(h["created_at"]) is not int or not 0 <= h["created_at"] < 2**63:
        raise UniversalError("invalid creation time")
    attributes = h["attributes"]
    if not isinstance(attributes, dict) or len(attributes) > 16 or any(
        not isinstance(k, str) or not TOKEN.fullmatch(k) or
        not isinstance(v, str) or len(v) > 160 for k, v in attributes.items()):
        raise UniversalError("unbounded attributes")
    if any(not safe_text(v) for v in attributes.values()):
        raise UniversalError("invalid control or surrogate codepoint")
    if h["kind"] == "stream-segment":
        if (not isinstance(h["stream_id"], str) or not re.fullmatch("[0-9a-f]{32}", h["stream_id"])
                or type(h["sequence"]) is not int or not 0 <= h["sequence"] < MAX_STREAM_SEGMENTS
                or type(h["final"]) is not bool):
            raise UniversalError("invalid stream segment metadata")
    elif h["stream_id"] is not None or h["sequence"] is not None or h["final"] is not None:
        raise UniversalError("unexpected stream fields")
    if len(_canonical(h)) > HEADER_LIMIT:
        raise UniversalError("application header too large")
    return h


def _safe_source(path: Path) -> tuple[int, str]:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise UniversalError("source must be a regular file, not a symlink")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as f:
        for buf in iter(lambda: f.read(CHUNK), b""):
            size += len(buf)
            if size >= MAX_OBJECT_BYTES - HEADER_LIMIT - 8:
                raise UniversalError("application object exceeds OB80 size limit")
            digest.update(buf)
    return size, digest.hexdigest()


def _write_exclusive(path: Path, writer) -> None:
    """Mode 0600 and no overwrites; refuse symlink path/parent."""
    path = Path(path)
    if path.exists() or path.is_symlink() or path.parent.is_symlink():
        raise UniversalError("refusing existing output or symlink")
    if not path.parent.is_dir():
        raise UniversalError("output directory must already exist")
    temp = path.with_name("." + path.name + ".partial-" + secrets.token_hex(8))
    fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as dest:
            writer(dest)
            dest.flush()
            os.fsync(dest.fileno())
        os.link(temp, path, follow_symlinks=False)
    except FileExistsError as exc:
        raise UniversalError("refusing to overwrite output") from exc
    finally:
        temp.unlink(missing_ok=True)


def pack(source: Path, output: Path, *, kind: str, content_type: str,
         name: str = "payload", attributes: dict | None = None,
         stream_id: str | None = None, sequence: int | None = None,
         final: bool | None = None, now: int | None = None) -> dict:
    """Create an owner-only plaintext UV10 staging file for subsequent OB80 sealing."""
    source = Path(source)
    size, digest = _safe_source(source)
    if kind in ("message", "event"):
        if size > MAX_MESSAGE:
            raise UniversalError("message/event too large")
        raw = source.read_bytes()
        if kind == "message":
            try: raw.decode("utf-8")
            except UnicodeDecodeError as exc: raise UniversalError("message must be UTF-8") from exc
        else:
            try: _strict_json_loads(raw)
            except (ValueError, UnicodeDecodeError) as exc: raise UniversalError("event must be JSON") from exc
    head = _verify_header({"version": VERSION, "kind": kind, "content_type": content_type,
                           "name": name, "size": size, "sha256": digest,
                           "created_at": int(time.time()) if now is None else now,
                           "stream_id": stream_id, "sequence": sequence,
                           "final": final, "attributes": attributes or {}})
    rawhead = _canonical(head)
    if 8 + len(rawhead) + size > MAX_OBJECT_BYTES:
        raise UniversalError("UV10 exceeds encrypted object capacity")

    def write(dest: BinaryIO):
        dest.write(MAGIC + struct.pack(">I", len(rawhead)) + rawhead)
        written = 0
        with source.open("rb") as f:
            for block in iter(lambda: f.read(CHUNK), b""):
                written += len(block)
                dest.write(block)
        if written != size or _safe_source(source)[1] != digest:
            raise UniversalError("source changed during packaging")

    _write_exclusive(Path(output), write)
    return head


def inspect(path: Path) -> dict:
    """Validate the UV10 header and exact file framing; no decrypting."""
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise UniversalError("invalid payload file")
    with path.open("rb") as f:
        prefix = f.read(8)
        if len(prefix) != 8 or prefix[:4] != MAGIC:
            raise UniversalError("invalid UV10 magic")
        (size,) = struct.unpack(">I", prefix[4:])
        if not 2 <= size <= HEADER_LIMIT:
            raise UniversalError("invalid UV10 header length")
        raw = f.read(size)
        if len(raw) != size:
            raise UniversalError("truncated UV10 header")
        try:
            h = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise UniversalError("invalid UTF-8/JSON header") from exc
        _verify_header(h)
        if raw != _canonical(h):
            raise UniversalError("noncanonical UV10 header")
        if path.stat().st_size > MAX_OBJECT_BYTES or path.stat().st_size != 8 + size + h["size"]:
            raise UniversalError("truncated or trailing payload data")
    return h


def unpack(source: Path, output: Path) -> dict:
    """Validate SHA-256 before exclusively publishing bytes; caller supplies output path.

    `source` is expected to be an OB80 *authenticated reconstruction*; the
    container digest alone does not provide origin authentication.
    """
    head = inspect(source)
    start = 8 + len(_canonical(head))

    def write(dest: BinaryIO):
        digest = hashlib.sha256()
        total = 0
        application = bytearray() if head["kind"] in ("message","event") else None
        with Path(source).open("rb") as f:
            f.seek(start)
            while total < head["size"]:
                chunk = f.read(min(CHUNK, head["size"] - total))
                if not chunk: raise UniversalError("truncated application bytes")
                digest.update(chunk)
                total += len(chunk)
                if application is not None: application.extend(chunk)
                dest.write(chunk)
        if total != head["size"] or digest.hexdigest() != head["sha256"]:
            raise UniversalError("application digest mismatch")
        if application is not None:
            try:
                text = application.decode("utf-8")
                if head["kind"] == "event": _strict_json_loads(text)
            except (UnicodeDecodeError,ValueError) as exc:
                raise UniversalError("invalid message UTF-8 or event JSON") from exc

    _write_exclusive(Path(output), write)
    return head


def assemble_stream(segments: list[Path], output: Path, *, max_bytes: int = 1024 * 1024 * 1024) -> dict:
    """Assemble a finite ordered stream after validating segment continuity and hashes.

    Encrypted/authenticated *origin* is established only after fetching each
    segment with OB80 and optionally pinning the original sender.
    """
    if not 1 <= len(segments) <= MAX_STREAM_SEGMENTS:
        raise UniversalError("invalid stream segment count")
    checked = sorted([(inspect(p), Path(p)) for p in segments], key=lambda it: it[0]["sequence"] if it[0]["sequence"] is not None else -1)
    head0 = checked[0][0]
    if head0["kind"] != "stream-segment" or head0["sequence"] != 0:
        raise UniversalError("stream must begin at zero")
    stream_id = head0["stream_id"]
    total = 0
    for i, (head, _) in enumerate(checked):
        if (head["kind"] != "stream-segment" or head["stream_id"] != stream_id or
                head["sequence"] != i or head["content_type"] != head0["content_type"] or
                head["final"] != (i == len(checked) - 1)):
            raise UniversalError("stream gap, duplicate, mixed type, or missing final")
        total += head["size"]
        if total > max_bytes:
            raise UniversalError("assembled stream size exceeds limit")

    def write(dest: BinaryIO):
        for head, part in checked:
            with tempfile.TemporaryDirectory(prefix="uv10-segment-") as td:
                intermediate = Path(td) / "verified-bytes"
                unpack(part, intermediate)
                with intermediate.open("rb") as f:
                    for block in iter(lambda: f.read(CHUNK), b""):
                        dest.write(block)

    _write_exclusive(Path(output), write)
    return {"stream_id": stream_id, "segments": len(checked), "bytes": total,
            "content_type": head0["content_type"]}


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description="UV10 application framing. Plaintext local staging, not encrypted until OB80 sealing.")
    cmds = parser.add_subparsers(dest="action", required=True)
    create = cmds.add_parser("pack", help="pack bytes in owner-only UV10 staging file")
    create.add_argument("source", type=Path)
    create.add_argument("output", type=Path)
    create.add_argument("--kind", choices=sorted(KINDS), required=True)
    create.add_argument("--content-type", required=True)
    create.add_argument("--name", default="payload")
    create.add_argument("--stream-id")
    create.add_argument("--sequence", type=int)
    create.add_argument("--final", action="store_true")
    extract = cmds.add_parser("unpack", help="extract from an authenticated reconstruction")
    extract.add_argument("source", type=Path)
    extract.add_argument("output", type=Path)
    peek = cmds.add_parser("inspect")
    peek.add_argument("source", type=Path)
    args = parser.parse_args(argv)
    if args.action == "pack":
        result = pack(args.source, args.output, kind=args.kind, content_type=args.content_type,
                      name=args.name, stream_id=args.stream_id,
                      sequence=args.sequence, final=args.final if args.stream_id else None)
    elif args.action == "unpack":
        result = unpack(args.source, args.output)
    else:
        result = inspect(args.source)
    print(json.dumps({"status": "OK", "application": VERSION, "header": result,
                      "caution": "UV10 file is plaintext until recipient-only OB80 encryption"}, indent=2))


if __name__ == "__main__":
    main()
