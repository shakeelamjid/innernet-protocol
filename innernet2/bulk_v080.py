"""OB80: bounded, end-to-end-encrypted bulk object profile (alpha research).

Uses a fixed 64-KiB AEAD chunk, signed per-chunk hashes, recipient-only object
key, SQLite WAL storage, deterministic retransmission and restart checkpoints.
The server sees ciphertext and metadata, not plaintext. NOT security audited.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import struct
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .mailbox_e2ee import canonical, verify_bundle, E2EEError
from .native_udp import pub_bytes

VERSION = "OB80-2"
LEGACY_VERSION = "OB80-1"
ID_DOMAIN = b"INNERnet/OB80/v2/sender-scoped-id\x00"
DOMAIN = b"INNERnet/OB80/signed-object\x00"
KDF_INFO = b"INNERnet/OB80/object-x25519-v1\x00"
CHUNK_SIZE = 65536
MAX_OBJECT_BYTES = 128 * 1024 * 1024
MAX_CHUNKS = MAX_OBJECT_BYTES // CHUNK_SIZE
MAX_MANIFEST_BYTES = 200_000


class BulkError(ValueError):
    pass


def _bytes(hex_string: str, size: int, label: str) -> bytes:
    try:
        result = bytes.fromhex(hex_string)
    except (TypeError, ValueError) as exc:
        raise BulkError(f"invalid {label}") from exc
    if len(result) != size:
        raise BulkError(f"invalid {label} length")
    return result


def _derive(private: X25519PrivateKey, public: bytes, ident: bytes, sender: bytes, recipient: bytes) -> bytes:
    try:
        shared = private.exchange(X25519PublicKey.from_public_bytes(public))
        return HKDF(algorithm=hashes.SHA256(), length=32,
                    salt=hashlib.sha256(ident + sender + recipient).digest(),
                    info=KDF_INFO).derive(shared)
    except ValueError as exc:
        raise BulkError("invalid recipient public key") from exc


def _aad(ident: bytes, sender: bytes, recipient: bytes) -> bytes:
    return b"INNERnet/OB80/chunk\x00" + ident + sender + recipient


def _nonce(index: int) -> bytes:
    return struct.pack(">IQ", 0, index)


def _digest_file(path: Path) -> tuple[int, bytes]:
    if path.is_symlink() or not path.is_file():
        raise BulkError("source must be regular file, not symlink")
    size = path.stat().st_size
    if not 1 <= size <= MAX_OBJECT_BYTES:
        raise BulkError("source outside 1 byte to 128 MiB limit")
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return size, digest.digest()


@dataclass
class PreparedObject:
    source: Path
    record: dict
    ephemeral: X25519PrivateKey
    key: bytes

    @property
    def payload(self) -> dict:
        return self.record["payload"]

    def chunk(self, index: int) -> bytes:
        p = self.payload
        if type(index) is not int or not 0 <= index < p["chunks"]:
            raise BulkError("chunk index outside signed manifest")
        with self.source.open("rb") as file:
            file.seek(index * CHUNK_SIZE)
            clear = file.read(min(CHUNK_SIZE, p["size"] - index * CHUNK_SIZE))
        if not clear:
            raise BulkError("source changed during transfer")
        ident, sender, recipient = (_bytes(p[n], size, n) for n, size in
                                    (("object_id",16),("sender",32),("recipient",32)))
        cipher = ChaCha20Poly1305(self.key).encrypt(_nonce(index), clear, _aad(ident,sender,recipient))
        if hashlib.sha256(cipher).hexdigest() != p["ciphertext_hashes"][index]:
            raise BulkError("source file mutated; local checkpoint invalid")
        return cipher

    def save(self, destination: Path) -> None:
        """Owner-only local checkpoint. Includes X25519 PRIVATE ephemeral state."""
        destination = Path(destination).expanduser().resolve(strict=False)
        if destination.exists() or destination.is_symlink():
            raise BulkError("refusing to overwrite checkpoint")
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if destination.parent.stat().st_mode & 0o077:
            raise BulkError("checkpoint directory must be mode 0700")
        raw = canonical({"source": str(self.source.absolute()), "record": self.record,
                         "ephemeral_private": self.ephemeral.private_bytes(
                             serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                             serialization.NoEncryption()).hex()})
        fd = os.open(destination, os.O_WRONLY | os.O_EXCL | os.O_CREAT | getattr(os,"O_NOFOLLOW",0), 0o600)
        with os.fdopen(fd, "wb") as file:
            file.write(raw)
            file.flush()
            os.fsync(file.fileno())


def prepare_file(source: Path, identity: Ed25519PrivateKey, bundle: dict,
                 *, expected_recipient: bytes, ttl: int = 86400) -> PreparedObject:
    source = Path(source).expanduser().absolute()
    size, digest = _digest_file(source)
    sender = pub_bytes(identity)
    if not isinstance(expected_recipient, bytes) or len(expected_recipient) != 32:
        raise BulkError("explicit independently pinned recipient Ed25519 key required")
    recipient = expected_recipient
    target_pub = verify_bundle(bundle, expected_recipient)
    if not 60 <= ttl <= 7 * 86400:
        raise BulkError("TTL outside 60 seconds to 7 days")
    ephemeral = X25519PrivateKey.generate()
    # Bind a new object ID to its original sender and unique ephemeral public key.
    # Any other sender attempting the same ID would need a 128-bit hash preimage.
    ephemeral_public = ephemeral.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ident = hashlib.sha256(ID_DOMAIN + sender + ephemeral_public).digest()[:16]
    key = _derive(ephemeral, target_pub, ident, sender, recipient)
    aad = _aad(ident, sender, recipient)
    counts = math.ceil(size / CHUNK_SIZE)
    hashes = []
    with source.open("rb") as file:
        for index in range(counts):
            blob = ChaCha20Poly1305(key).encrypt(_nonce(index), file.read(CHUNK_SIZE), aad)
            hashes.append(hashlib.sha256(blob).hexdigest())
    summary = ChaCha20Poly1305(key).encrypt(b"\xff" * 12, digest,
                        b"INNERnet/OB80/sealed-digest\x00" + aad).hex()
    start = int(time.time())
    payload = {"version": VERSION, "object_id": ident.hex(), "sender": sender.hex(),
               "recipient": recipient.hex(), "ephemeral_x25519": ephemeral.public_key().public_bytes(
                   serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex(),
               "size": size, "chunk_size": CHUNK_SIZE, "chunks": counts,
               "ciphertext_hashes": hashes, "sealed_sha256": summary,
               "created_at": start, "expires_at": start + ttl}
    record = {"payload": payload, "signature": identity.sign(DOMAIN + canonical(payload)).hex()}
    verify_manifest(record)
    return PreparedObject(source, record, ephemeral, key)


def load_prepared(checkpoint: Path, identity: Ed25519PrivateKey, bundle: dict) -> PreparedObject:
    checkpoint = Path(checkpoint)
    if checkpoint.is_symlink() or checkpoint.stat().st_mode & 0o077:
        raise BulkError("checkpoint key must be owner-only and not a symlink")
    if checkpoint.stat().st_size > 250000:
        raise BulkError("checkpoint too large")
    data = json.loads(checkpoint.read_text())
    p = verify_manifest(data["record"])
    if p["sender"] != pub_bytes(identity).hex():
        raise BulkError("checkpoint sender identity mismatch")
    recipient = _bytes(p["recipient"],32,"recipient")
    target = verify_bundle(bundle, recipient)
    ephemeral = X25519PrivateKey.from_private_bytes(_bytes(data["ephemeral_private"],32,"private ephemeral"))
    if ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex() != p["ephemeral_x25519"]:
        raise BulkError("checkpoint ephemeral identity mismatch")
    source = Path(data["source"])
    size, _ = _digest_file(source)
    if size != p["size"]:
        raise BulkError("checkpoint source size changed")
    key = _derive(ephemeral, target, _bytes(p["object_id"],16,"object"),
                  pub_bytes(identity), recipient)
    return PreparedObject(source, data["record"], ephemeral, key)


def verify_manifest(record: dict, *, now: int | None = None) -> dict:
    if not isinstance(record,dict) or set(record) != {"payload","signature"}:
        raise BulkError("invalid signed manifest wrapper")
    p=record["payload"]
    expected={"version","object_id","sender","recipient","ephemeral_x25519","size",
              "chunk_size","chunks","ciphertext_hashes","sealed_sha256","created_at","expires_at"}
    if not isinstance(p,dict) or set(p)!=expected or p["version"] not in (VERSION, LEGACY_VERSION):
        raise BulkError("invalid signed manifest fields")
    instant = int(time.time()) if now is None else now
    for n,size in (("object_id",16),("sender",32),("recipient",32),("ephemeral_x25519",32),
                   ("sealed_sha256",48)):
        _bytes(p[n], size,n)
    if p["version"] == VERSION:
        scoped = hashlib.sha256(ID_DOMAIN + _bytes(p["sender"],32,"sender") +
                                _bytes(p["ephemeral_x25519"],32,"ephemeral")).digest()[:16]
        if _bytes(p["object_id"],16,"object") != scoped:
            raise BulkError("object ID does not match signed sender-scoped namespace")
    if (type(p["size"]) is not int or not 1 <= p["size"] <= MAX_OBJECT_BYTES or
        type(p["chunk_size"]) is not int or p["chunk_size"] != CHUNK_SIZE or
        type(p["chunks"]) is not int or p["chunks"] != math.ceil(p["size"]/CHUNK_SIZE) or
        type(p["created_at"]) is not int or type(p["expires_at"]) is not int or
        p["created_at"] > instant + 300 or not instant < p["expires_at"] or
        not 60 <= p["expires_at"]-p["created_at"] <= 7*86400):
        raise BulkError("invalid size/count/expiry")
    lst=p["ciphertext_hashes"]
    if not isinstance(lst,list) or len(lst)!=p["chunks"] or any(
            not isinstance(x,str) or len(x)!=64 or any(c not in '0123456789abcdef' for c in x) for x in lst):
        raise BulkError("invalid signed chunk hashes")
    if len(canonical(record)) > MAX_MANIFEST_BYTES:
        raise BulkError("manifest too large")
    try:
        sig=_bytes(record["signature"],64,"signature")
        Ed25519PublicKey.from_public_bytes(_bytes(p["sender"],32,"sender")).verify(
            sig,DOMAIN+canonical(p))
    except (ValueError,InvalidSignature) as exc:
        raise BulkError("sender signature invalid") from exc
    return p


class RecipientWriter:
    """Bounded-memory authenticated reconstruction; never publish partial outputs.

    Plaintext is temporarily staged in a mode-0600 file on the recipient's own
    disk. It is published only after *every* authenticated chunk and the sealed
    whole-object digest have been checked. Never write into an existing file.
    """
    def __init__(self, record: dict, recipient_identity: Ed25519PrivateKey,
                 recipient_private: X25519PrivateKey, output: Path):
        p = verify_manifest(record)
        if p["recipient"] != pub_bytes(recipient_identity).hex():
            raise BulkError("recipient identity mismatch")
        self.p = p
        self.output = Path(output)
        if self.output.exists() or self.output.is_symlink():
            raise BulkError("refusing to overwrite existing output")
        ident = _bytes(p["object_id"],16,"object")
        sender = _bytes(p["sender"],32,"sender")
        recipient = pub_bytes(recipient_identity)
        key = _derive(recipient_private, _bytes(p["ephemeral_x25519"],32,"ephemeral"),
                      ident,sender,recipient)
        self.cipher = ChaCha20Poly1305(key)
        self.aad = _aad(ident,sender,recipient)
        try:
            self.expected_digest = self.cipher.decrypt(b"\xff"*12,
                bytes.fromhex(p["sealed_sha256"]),
                b"INNERnet/OB80/sealed-digest\x00" + self.aad)
        except (InvalidTag,ValueError) as exc:
            raise BulkError("sealed object digest authentication failed") from exc
        self.digest = hashlib.sha256()
        self.index = 0
        self.count = 0
        self.output.parent.mkdir(parents=True, exist_ok=True)
        self.temp = self.output.with_name(self.output.name+".partial-"+secrets.token_hex(8))
        self.file = None
        try:
            fd=os.open(self.temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
            self.file=os.fdopen(fd,"wb")
        except BaseException:
            self.temp.unlink(missing_ok=True)
            raise

    def write_chunk(self, blob: bytes) -> None:
        if self.file is None or self.index >= self.p["chunks"]:
            raise BulkError("recipient writer closed or extra chunk")
        expected = min(CHUNK_SIZE,self.p["size"]-self.index*CHUNK_SIZE)+16
        if len(blob)!=expected or hashlib.sha256(blob).hexdigest()!=self.p["ciphertext_hashes"][self.index]:
            raise BulkError("received ciphertext chunk fingerprint invalid")
        try:
            clear=self.cipher.decrypt(_nonce(self.index),blob,self.aad)
        except InvalidTag as exc:
            raise BulkError("recipient chunk authentication failed") from exc
        self.file.write(clear)
        self.digest.update(clear)
        self.count += len(clear)
        self.index += 1

    def finish(self) -> dict:
        if self.file is None: raise BulkError("recipient writer closed")
        if (self.index != self.p["chunks"] or self.count != self.p["size"] or
                self.digest.digest() != self.expected_digest):
            raise BulkError("whole object checksum, length or chunk count mismatch")
        self.file.flush()
        os.fsync(self.file.fileno())
        self.file.close()
        self.file=None
        # Hard-link publish is exclusive: an output created concurrently is not
        # overwritten (unlike os.replace). Both paths share the same filesystem.
        try:
            os.link(self.temp,self.output,follow_symlinks=False)
        except FileExistsError as exc:
            raise BulkError("refusing to overwrite existing output") from exc
        self.temp.unlink(missing_ok=True)
        return {"status":"PASS","bytes":self.p["size"],
                "sha256":self.digest.hexdigest(),"path":str(self.output)}

    def close(self):
        if self.file is not None:
            self.file.close()
            self.file=None
        self.temp.unlink(missing_ok=True)

    def __enter__(self): return self
    def __exit__(self,*_): self.close()


def decrypt_package(record: dict, recipient_identity: Ed25519PrivateKey,
                    recipient_private: X25519PrivateKey, chunks: list[bytes],
                    output: Path) -> dict:
    """Legacy in-memory API; uses the shared secure streaming finalizer."""
    with RecipientWriter(record,recipient_identity,recipient_private,output) as writer:
        for blob in chunks:
            writer.write_chunk(blob)
        return writer.finish()


class ChunkStore:
    """SQLite WAL ciphertext-only object store; per-request connections allowed."""
    def __init__(self, path: Path | str, *, max_storage_bytes: int | None = None,
                 max_objects: int | None = None):
        if max_storage_bytes is not None and (type(max_storage_bytes) is not int or max_storage_bytes < 1):
            raise BulkError("storage quota must be a positive integer")
        if max_objects is not None and (type(max_objects) is not int or max_objects < 1):
            raise BulkError("object quota must be a positive integer")
        self.max_storage_bytes=max_storage_bytes
        self.max_objects=max_objects
        path=Path(path)
        path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        if (path.parent.is_symlink() or path.parent.stat().st_mode & 0o077 or
                path.is_symlink() or (path.exists() and path.stat().st_mode & 0o077)):
            raise BulkError("object database and directory must be private, non-symlink (0600/0700)")
        fd=os.open(path,os.O_CREAT|os.O_RDWR|getattr(os,"O_NOFOLLOW",0),0o600)
        os.fchmod(fd,0o600)
        os.close(fd)
        self.db=sqlite3.connect(str(path),timeout=20, isolation_level=None)
        self.db.execute("PRAGMA busy_timeout=20000")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        # Signed manifests are immutable by object ID; cache *verified* entries
        # per connection to avoid O(chunks²) signature/hash validation on 100 MiB.
        self._verified: dict[str, dict] = {}
        self.db.execute("""CREATE TABLE IF NOT EXISTS objects (
            ident TEXT PRIMARY KEY, manifest TEXT NOT NULL, sender TEXT NOT NULL,
            recipient TEXT NOT NULL, expires INTEGER NOT NULL)""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS chunks (
            ident TEXT NOT NULL, idx INTEGER NOT NULL, payload BLOB NOT NULL,
            PRIMARY KEY(ident,idx), FOREIGN KEY(ident) REFERENCES objects(ident))""")
        self.db.execute("CREATE INDEX IF NOT EXISTS objects_sender_idx ON objects(sender)")
        self.db.execute("""CREATE TABLE IF NOT EXISTS quota_metrics (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            payload_bytes INTEGER NOT NULL, object_count INTEGER NOT NULL)""")
        # Transactionally maintained sender counters, backfilled once on migration.
        self.db.execute("""CREATE TABLE IF NOT EXISTS sender_usage (
            sender TEXT PRIMARY KEY, payload_bytes INTEGER NOT NULL, object_count INTEGER NOT NULL)""")
        # The old RC5 constructor scanned every chunk for EVERY ST81 request.
        # Migrate under the SQLite write lock exactly once per database, rather
        # than repeatedly racing against live request transactions.
        self.db.execute("BEGIN IMMEDIATE")
        try:
            version = self.db.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                self.db.execute("DELETE FROM sender_usage")
                self.db.execute("""INSERT INTO sender_usage(sender,payload_bytes,object_count)
                    SELECT o.sender,COALESCE(SUM(LENGTH(c.payload)),0),COUNT(DISTINCT o.ident)
                    FROM objects o LEFT JOIN chunks c ON c.ident=o.ident GROUP BY o.sender""")
                self.db.execute("DELETE FROM quota_metrics")
                self.db.execute("""INSERT INTO quota_metrics
                    SELECT 1,(SELECT COALESCE(SUM(LENGTH(payload)),0) FROM chunks),
                             (SELECT COUNT(*) FROM objects)""")
                self.db.execute("PRAGMA user_version=1")
            elif version != 1:
                raise BulkError("unsupported ChunkStore schema version")
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def close(self): self.db.close()

    def manifest(self, record: dict, *, allow_legacy_replica: bool=False) -> bool:
        p=verify_manifest(record)
        ident=p["object_id"]
        saved=canonical(record).decode()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row=self.db.execute("SELECT manifest FROM objects WHERE ident=?",(ident,)).fetchone()
            if row is not None and row[0]!=saved:
                raise BulkError("object ID collision or manifest mutation")
            if row is None:
                # OB80-1 objects already on disk remain readable until expiry;
                # accepting new legacy manifests would allow bypassing the
                # sender-bound object ID check via namespace squatting.
                if p["version"] != VERSION and not allow_legacy_replica:
                    raise BulkError("legacy OB80-1 manifest is read-only; upgrade sender")
                if self.max_objects is not None:
                    current=self.db.execute("SELECT object_count FROM quota_metrics WHERE singleton=1").fetchone()[0]
                    if current >= self.max_objects:
                        raise BulkError("object quota exhausted; operator cleanup required")
                    # One identity cannot exhaust all shared object slots.
                    owner = self.db.execute(
                        "SELECT object_count FROM sender_usage WHERE sender=?",(p["sender"],)).fetchone()
                    owner_objects = owner[0] if owner else 0
                    if self.max_objects != 1 and owner_objects >= max(1, (self.max_objects*9)//10):
                        raise BulkError("sender object quota exhausted")
                self.db.execute("INSERT INTO objects VALUES (?,?,?,?,?)",
                    (ident,saved,p["sender"],p["recipient"],p["expires_at"]))
                self.db.execute("UPDATE quota_metrics SET object_count=object_count+1 WHERE singleton=1")
                self.db.execute("INSERT INTO sender_usage VALUES (?,?,1) "
                    "ON CONFLICT(sender) DO UPDATE SET object_count=object_count+1",(p["sender"],0))
            self.db.execute("COMMIT")
            self._verified[ident] = record
            return row is None
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def get_manifest(self,ident: str) -> dict:
        _bytes(ident,16,"object")
        record=self._verified.get(ident)
        if record is not None:
            if int(time.time()) >= record["payload"]["expires_at"]:
                raise BulkError("object expired")
            return record
        row=self.db.execute("SELECT manifest FROM objects WHERE ident=? AND expires>?",
                            (ident,int(time.time()))).fetchone()
        if row is None: raise BulkError("object missing or expired")
        record=json.loads(row[0]);verify_manifest(record)
        self._verified[ident]=record
        return record

    def put(self,ident: str,index: int, blob: bytes) -> str:
        p=self.get_manifest(ident)["payload"]
        if type(index) is not int or not 0 <= index < p["chunks"]:
            raise BulkError("chunk index invalid")
        exp=min(CHUNK_SIZE,p["size"]-index*CHUNK_SIZE)+16
        if len(blob)!=exp or hashlib.sha256(blob).hexdigest()!=p["ciphertext_hashes"][index]:
            raise BulkError("chunk size or authenticated signed fingerprint mismatch")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row=self.db.execute("SELECT payload FROM chunks WHERE ident=? AND idx=?",(ident,index)).fetchone()
            if row is not None and row[0]!=blob:
                raise BulkError("immutable encrypted chunk mutation")
            if row is None:
                if self.max_storage_bytes is not None:
                    current=self.db.execute("SELECT payload_bytes FROM quota_metrics WHERE singleton=1").fetchone()[0]
                    if current+len(blob)>self.max_storage_bytes:
                        raise BulkError("ciphertext storage quota exhausted")
                    sender = self.db.execute(
                        "SELECT payload_bytes FROM sender_usage WHERE sender=?",(p["sender"],)).fetchone()
                    sender_bytes = sender[0] if sender else 0
                    if (self.max_objects != 1 and
                            sender_bytes+len(blob)>max(len(blob),self.max_storage_bytes*9//10)):
                        raise BulkError("sender ciphertext quota exhausted")
                self.db.execute("INSERT INTO chunks VALUES (?,?,?)",(ident,index,blob))
                self.db.execute("UPDATE quota_metrics SET payload_bytes=payload_bytes+? WHERE singleton=1",(len(blob),))
                self.db.execute("UPDATE sender_usage SET payload_bytes=payload_bytes+? WHERE sender=?",
                                (len(blob),p["sender"]))
            self.db.execute("COMMIT")
            return "STORED" if row is None else "DUPLICATE"
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def missing(self,ident: str) -> list[int]:
        p=self.get_manifest(ident)["payload"]
        saved={v[0] for v in self.db.execute("SELECT idx FROM chunks WHERE ident=?",(ident,))}
        return [i for i in range(p["chunks"]) if i not in saved]

    def get(self,ident: str,index: int) -> bytes:
        p=self.get_manifest(ident)["payload"]
        if type(index) is not int or not 0 <= index < p["chunks"]:
            raise BulkError("chunk index invalid")
        row=self.db.execute("SELECT payload FROM chunks WHERE ident=? AND idx=?",(ident,index)).fetchone()
        if row is None: raise BulkError("chunk absent")
        return row[0]

    def get_range(self, ident: str, start: int, count: int) -> bytes:
        """Get at most four consecutive encrypted chunks in a single bounded frame.

        This adds no authorization: the authenticated caller is checked by R90.
        The response is unambiguously split using signed manifest sizes.
        """
        p = self.get_manifest(ident)["payload"]
        if (type(start) is not int or type(count) is not int or
                not 0 <= start < p["chunks"] or not 1 <= count <= 4 or
                start + count > p["chunks"]):
            raise BulkError("range outside signed object or four-chunk limit")
        rows = self.db.execute(
            "SELECT idx,payload FROM chunks WHERE ident=? AND idx>=? AND idx<? ORDER BY idx",
            (ident, start, start + count)).fetchall()
        if len(rows) != count or any(row[0] != start + i for i, row in enumerate(rows)):
            raise BulkError("missing chunk in requested range")
        return b"".join(row[1] for row in rows)

    def usage(self) -> dict:
        used,objects=self.db.execute(
            "SELECT payload_bytes,object_count FROM quota_metrics WHERE singleton=1").fetchone()
        return {"ciphertext_bytes":used,"objects":objects,
                "max_ciphertext_bytes":self.max_storage_bytes,
                "max_objects":self.max_objects}

    def prune_expired(self, *, now: int | None = None) -> dict:
        """Explicit operator maintenance. Deletes only expired objects and chunks."""
        instant=int(time.time()) if now is None else now
        if type(instant) is not int:
            raise BulkError("invalid cleanup clock")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            deleted=self.db.execute(
                "SELECT COUNT(*),COALESCE(SUM(LENGTH(payload)),0) FROM chunks "
                "WHERE ident IN (SELECT ident FROM objects WHERE expires<=?)",
                (instant,)).fetchone()
            objects=self.db.execute("SELECT COUNT(*) FROM objects WHERE expires<=?",(instant,)).fetchone()[0]
            per_owner = self.db.execute(
                "SELECT o.sender,COUNT(DISTINCT o.ident),COALESCE(SUM(LENGTH(c.payload)),0) "
                "FROM objects o LEFT JOIN chunks c ON c.ident=o.ident "
                "WHERE o.expires<=? GROUP BY o.sender",(instant,)).fetchall()
            for owner, count, used in per_owner:
                self.db.execute("UPDATE sender_usage SET object_count=object_count-?, "
                                "payload_bytes=payload_bytes-? WHERE sender=?",(count,used,owner))
            self.db.execute("DELETE FROM chunks WHERE ident IN (SELECT ident FROM objects WHERE expires<=?)",(instant,))
            self.db.execute("DELETE FROM objects WHERE expires<=?",(instant,))
            self.db.execute("UPDATE quota_metrics SET payload_bytes=payload_bytes-?, object_count=object_count-? "
                            "WHERE singleton=1",(deleted[1],objects))
            self.db.execute("COMMIT")
            self._verified.clear()
            return {"expired_objects_deleted":objects,"chunks_deleted":deleted[0],
                    "ciphertext_bytes_reclaimed":deleted[1],**self.usage()}
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def statistics(self,ident: str) -> dict:
        p=self.get_manifest(ident)["payload"]
        count=self.db.execute("SELECT COUNT(*) FROM chunks WHERE ident=?",(ident,)).fetchone()[0]
        return {"stored":count,"total":p["chunks"],"complete":count==p["chunks"],
                "bytes":p["size"]}
