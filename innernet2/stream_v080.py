"""ST81 experimental mutually authenticated TCP session and AEAD framing.

NOT TLS, not audited, no forward secrecy against compromised endpoint secrets
beyond ephemeral session keys. Strict peer identity pinning; per-direction
counters prevent in-session replay and frame reordering. No 0-RTT.
"""
from __future__ import annotations

import hashlib
import json
import math
import secrets
import socket
import struct
import time

from cryptography.exceptions import InvalidTag, InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from .native_udp import pub_bytes

MAGIC_C=b"S81C"
MAGIC_S=b"S81S"
MAGIC_CHALLENGE=b"S81H"
# ST81 is explicitly incompatible with ST80; never silently downgrade.
DOMAIN_C=b"INNERnet/ST80/client-auth\x00"
DOMAIN_S=b"INNERnet/ST80/server-auth\x00"
MAX_FRAME=400_000
MAX_JSON=240_000


class StreamError(ValueError): pass


def _read(sock: socket.socket, count: int, *, deadline: float | None=None) -> bytes:
    chunks=[]
    while count:
        if deadline is not None:
            remaining=deadline-time.monotonic()
            if remaining <= 0: raise StreamError("handshake total deadline exceeded")
            sock.settimeout(remaining)
        part=sock.recv(count)
        if not part: raise StreamError("peer disconnected before full frame")
        chunks.append(part);count-=len(part)
    return b"".join(chunks)


def _rawpub(x: X25519PrivateKey) -> bytes:
    return x.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)


def _session_keys(ephemeral: X25519PrivateKey, peer: bytes, hello: bytes, response: bytes) -> tuple[bytes,bytes]:
    try:
        shared=ephemeral.exchange(X25519PublicKey.from_public_bytes(peer))
    except ValueError as exc:
        raise StreamError("bad ephemeral public key") from exc
    material=HKDF(algorithm=hashes.SHA256(), length=64,
                  salt=hashlib.sha256(hello+response).digest(),
                  info=b"INNERnet/ST80/key-schedule-v1\x00").derive(shared)
    return material[:32],material[32:]


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON object key")
        result[name] = value
    return result


def _reject_nonfinite(value: str):
    raise ValueError("non-finite JSON constant")


def _bounded_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite JSON float")
    return number


def _bounded_integer(value: str) -> int:
    if len(value.lstrip("-")) > 19:
        raise ValueError("JSON integer too long")
    number = int(value)
    if not -(2**63) <= number < 2**63:
        raise ValueError("JSON integer outside signed 64-bit range")
    return number


def _check_json_depth(obj, max_depth: int = 64) -> None:
    # Iterative traversal avoids recursive Python stack exhaustion.
    pending = [(obj, 1)]
    while pending:
        value, depth = pending.pop()
        if depth > max_depth:
            raise ValueError("JSON nesting exceeds limit")
        if isinstance(value, dict):
            pending.extend((item, depth + 1) for item in value.values()
                           if isinstance(item, (dict, list)))
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value
                           if isinstance(item, (dict, list)))


class Session:
    def __init__(self, sock: socket.socket, peer: bytes, send_key: bytes, recv_key: bytes, *, initiator: bool):
        self.sock=sock
        self.peer=peer
        self.send=ChaCha20Poly1305(send_key)
        self.recv=ChaCha20Poly1305(recv_key)
        self.send_num=0
        self.recv_num=0
        self.send_tag=b"C" if initiator else b"S"
        self.recv_tag=b"S" if initiator else b"C"

    def write(self, header: dict, data: bytes=b"") -> None:
        raw=json.dumps(header,sort_keys=True,separators=(",",":"),allow_nan=False).encode("utf-8")
        if len(raw)>MAX_JSON or len(data)+len(raw)+4+16>MAX_FRAME:
            raise StreamError("outgoing frame exceeds fixed safety bound")
        clear=struct.pack(">I",len(raw))+raw+data
        nonce=struct.pack(">IQ",0,self.send_num)
        blob=self.send.encrypt(nonce,clear,self.send_tag+struct.pack(">Q",self.send_num))
        self.sock.sendall(struct.pack(">I",len(blob))+blob)
        self.send_num+=1

    def read(self, *, deadline: float | None=None,
             frame_limit: int=MAX_FRAME) -> tuple[dict,bytes]:
        # A total frame deadline prevents an authenticated peer from holding
        # its connection slot indefinitely by sending one byte per timeout.
        if deadline is None:
            # Preserve the caller's intentionally extended RPC timeout (such
            # as the 180s replication operation) while bounding total frame
            # reception, rather than each recv() independently.
            configured=self.sock.gettimeout()
            deadline=time.monotonic()+(configured if configured is not None else 15.0)
        (size,)=struct.unpack(">I",_read(self.sock,4,deadline=deadline))
        if not 20<=size<=min(MAX_FRAME,frame_limit):
            raise StreamError("peer frame outside bound")
        cipher=_read(self.sock,size,deadline=deadline)
        nonce=struct.pack(">IQ",0,self.recv_num)
        try:
            clear=self.recv.decrypt(nonce,cipher,self.recv_tag+struct.pack(">Q",self.recv_num))
        except InvalidTag as exc:
            raise StreamError("invalid frame AEAD or replayed counter") from exc
        self.recv_num+=1
        if len(clear)<4: raise StreamError("frame truncated")
        (length,)=struct.unpack(">I",clear[:4])
        if not 2<=length<=MAX_JSON or len(clear)<4+length:
            raise StreamError("invalid framed JSON length")
        try:
            head=json.loads(clear[4:4+length], object_pairs_hook=_unique_json_object,
                            parse_constant=_reject_nonfinite, parse_int=_bounded_integer,
                            parse_float=_bounded_float)
            _check_json_depth(head)
        except (UnicodeDecodeError,ValueError,RecursionError) as exc:
            raise StreamError("invalid JSON frame") from exc
        if not isinstance(head,dict): raise StreamError("frame must contain JSON object")
        return head,clear[4+length:]


def connect(host: str, port: int, key: Ed25519PrivateKey, pinned_server: bytes,
            *, timeout: float=10) -> Session:
    """ST81 challenge-bound handshake with explicit bidirectional key confirmation.

    No downgrade to ST80 is offered. The server challenge makes a previously
    recorded client hello invalid on any new TCP connection.
    """
    if len(pinned_server)!=32: raise StreamError("server pin must be 32 bytes")
    sock=socket.create_connection((host,port),timeout=timeout)
    return handshake(sock, key, pinned_server, timeout=timeout)


def handshake(sock, key: Ed25519PrivateKey, pinned_server: bytes, *, timeout: float=10) -> Session:
    """Initiator side of ST81 over an already connected socket-like object (a TCP socket,
    or a stream through an RLY-0 relay). Identical wire behaviour to `connect`."""
    if len(pinned_server)!=32: raise StreamError("server pin must be 32 bytes")
    try:
        deadline=time.monotonic()+timeout
        challenge_msg=_read(sock,68,deadline=deadline)
        if challenge_msg[:4]!=MAGIC_CHALLENGE or challenge_msg[4:36]!=pinned_server:
            raise StreamError("invalid server challenge or pin")
        ephemeral=X25519PrivateKey.generate()
        prefix=MAGIC_C+pub_bytes(key)+_rawpub(ephemeral)+secrets.token_bytes(32)
        hello=prefix+key.sign(DOMAIN_C+challenge_msg+prefix)
        sock.sendall(hello)
        response=_read(sock,196,deadline=deadline)
        if response[:4]!=MAGIC_S or response[4:36]!=pinned_server or response[68:100]!=hello[68:100]:
            raise StreamError("untrusted server identity or handshake nonce")
        try:
            Ed25519PublicKey.from_public_bytes(pinned_server).verify(
                response[-64:],DOMAIN_S+challenge_msg+hello+response[:-64])
        except InvalidSignature as exc:
            raise StreamError("invalid server handshake signature") from exc
        send,recv=_session_keys(ephemeral,response[36:68],challenge_msg+hello,response)
        session=Session(sock,pinned_server,send,recv,initiator=True)
        session.write({"handshake":"key-confirm-v1"})
        sock.settimeout(max(.001,deadline-time.monotonic()))
        ack,data=session.read(deadline=deadline,frame_limit=512)
        if ack!={"handshake":"key-confirmed-v1"} or data:
            raise StreamError("missing authenticated server key confirmation")
        sock.settimeout(timeout)
        return session
    except BaseException:
        sock.close();raise


def accept(sock: socket.socket, identity: Ed25519PrivateKey,
           authorized: set[bytes]) -> Session:
    """ST81 server; the return value is authenticated AND key-confirmed."""
    deadline=time.monotonic()+2.0
    challenge_msg=MAGIC_CHALLENGE+pub_bytes(identity)+secrets.token_bytes(32)
    sock.settimeout(2.0)
    sock.sendall(challenge_msg)
    hello=_read(sock,164,deadline=deadline)
    client=hello[4:36]
    if hello[:4]!=MAGIC_C or client not in authorized:
        raise StreamError("untrusted connecting identity")
    try:
        Ed25519PublicKey.from_public_bytes(client).verify(
            hello[-64:],DOMAIN_C+challenge_msg+hello[:-64])
    except InvalidSignature as exc:
        raise StreamError("invalid client handshake signature") from exc
    ephemeral=X25519PrivateKey.generate()
    prefix=MAGIC_S+pub_bytes(identity)+_rawpub(ephemeral)+hello[68:100]+secrets.token_bytes(32)
    response=prefix+identity.sign(DOMAIN_S+challenge_msg+hello+prefix)
    sock.sendall(response)
    send,recv=_session_keys(ephemeral,hello[36:68],challenge_msg+hello,response)
    session=Session(sock,client,recv,send,initiator=False)
    sock.settimeout(max(.001,deadline-time.monotonic()))
    first,data=session.read(deadline=deadline,frame_limit=512)
    if first!={"handshake":"key-confirm-v1"} or data:
        raise StreamError("client failed cryptographic key confirmation")
    session.write({"handshake":"key-confirmed-v1"})
    sock.settimeout(15)
    return session
