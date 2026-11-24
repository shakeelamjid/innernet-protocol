"""PM11: synthetic, recipient-encrypted IE60 roundtrip via an untrusted MQTT broker.

An anonymous public MQTT broker is a *transport service*, not an INNERnet node.
This module does not confer peer authentication on the broker, durable storage,
replication, or access control; the IE60 envelope authenticates the end points.
For public use, authenticated TLS is mandatory. Only tiny, synthetic messages.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import secrets
import socket
import ssl
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .mailbox_e2ee import (generate_bundle, load_recipient_secret, open_message,
                           seal_message, inspect_envelope)
from .native_udp import pub_bytes

MAX_PACKET = 4096
MAX_TOPIC = 160

class PublicRelayError(ValueError):
    """Malformed MQTT frame, broker/network failure or invalid synthetic test."""


def _utf8(text: str) -> bytes:
    data=text.encode('utf-8', errors='strict')
    if len(data)>MAX_TOPIC:
        raise PublicRelayError('MQTT field too long')
    return struct.pack('>H',len(data))+data


def _varint(length: int) -> bytes:
    if type(length) is not int or not 0 <= length <= MAX_PACKET:
        raise PublicRelayError('MQTT packet too long')
    result=bytearray()
    while True:
        part=length%128
        length//=128
        result.append(part | (128 if length else 0))
        if not length:
            return bytes(result)


def _frame(kind: int, body: bytes) -> bytes:
    if len(body)>MAX_PACKET:
        raise PublicRelayError('MQTT frame exceeds bound')
    return bytes([kind])+_varint(len(body))+body


def _recv_exact(connection, size: int) -> bytes:
    if not 0 <= size <= MAX_PACKET:
        raise PublicRelayError('invalid inbound packet length')
    chunks=[]
    while size:
        piece=connection.recv(size)
        if not piece:
            raise PublicRelayError('MQTT broker disconnected')
        chunks.append(piece)
        size-=len(piece)
    return b''.join(chunks)


def _read_packet(connection) -> tuple[int,bytes]:
    kind=_recv_exact(connection,1)[0]
    total=0
    multiplier=1
    for _ in range(4):
        b=_recv_exact(connection,1)[0]
        total+=(b&127)*multiplier
        if not b&128:
            break
        multiplier*=128
    else:
        raise PublicRelayError('malformed MQTT remaining-length encoding')
    if total>MAX_PACKET:
        raise PublicRelayError('oversized inbound MQTT frame')
    return kind,_recv_exact(connection,total)


def _parse_publish(kind: int, payload: bytes) -> tuple[str,bytes]:
    if kind & 0xf0 != 0x30 or kind & 0x06:
        raise PublicRelayError('unexpected MQTT publish type or QoS')
    if len(payload)<2:
        raise PublicRelayError('truncated MQTT topic')
    length=struct.unpack('>H',payload[:2])[0]
    if length>MAX_TOPIC or len(payload)<2+length:
        raise PublicRelayError('malformed MQTT topic')
    try:
        topic=payload[2:2+length].decode('utf-8')
    except UnicodeDecodeError as exc:
        raise PublicRelayError('invalid topic encoding') from exc
    return topic,payload[2+length:]


def _connect_mqtt(host: str, port: int, timeout: float, *, tls: bool):
    if not 1<=port<=65535 or not 1<=timeout<=20:
        raise PublicRelayError('invalid connection settings')
    if not tls:
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise PublicRelayError('plaintext MQTT allowed only on literal loopback IP')
        except ValueError as exc:
            if isinstance(exc,PublicRelayError):
                raise
            raise PublicRelayError('plaintext requires localhost literal IP') from exc
    conn=socket.create_connection((host,port),timeout=timeout)
    try:
        conn.settimeout(timeout)
        if tls:
            conn=ssl.create_default_context().wrap_socket(conn,server_hostname=host)
        cid='inn11-'+secrets.token_hex(12)
        # MQTT 3.1.1 clean session, anonymous; no retained messages.
        body=_utf8('MQTT')+bytes([4,2])+struct.pack('>H',30)+_utf8(cid)
        conn.sendall(_frame(0x10,body))
        kind,data=_read_packet(conn)
        if kind!=0x20 or data!=b'\x00\x00':
            raise PublicRelayError(f'MQTT CONNECT rejected ({kind}, {data[:8].hex()})')
        return conn
    except BaseException:
        conn.close()
        raise


def _subscribe(conn,topic: str):
    conn.sendall(_frame(0x82,b'\x12\x34'+_utf8(topic)+b'\x00'))
    kind,data=_read_packet(conn)
    if kind!=0x90 or data!=b'\x12\x34\x00':
        raise PublicRelayError('MQTT subscription not confirmed')


def _publish(conn,topic: str, payload: bytes):
    if len(payload)>960:
        raise PublicRelayError('public experiment envelope exceeds 960-byte cap')
    conn.sendall(_frame(0x30,_utf8(topic)+payload))


def _close(conn):
    if conn is not None:
        try: conn.sendall(b'\xe0\x00')
        except OSError: pass
        try: conn.close()
        except OSError: pass


def relay_probe(host: str='test.mosquitto.org',port: int=8886,
                *,timeout: float=8, tls: bool=True) -> dict:
    """Two independent client connections via an existing third-party broker.

    Only an IE60 recipient-encrypted SYNTHETIC message is published. Network
    errors propagate as probe failures; no real identities or data are used.
    """
    topic='innernet/research/pm11/'+secrets.token_hex(16)
    sender=Ed25519PrivateKey.generate()
    recipient=Ed25519PrivateKey.generate()
    message_id=secrets.token_bytes(16)
    clear=b'SYNTHETIC:PM11-PUBLIC-BROKER-TEST:'+secrets.token_bytes(32)
    with TemporaryDirectory(prefix='inn-pm11-') as td:
        root=Path(td);root.chmod(0o700)
        bundle=generate_bundle(recipient,root/'recipient.key',ttl=3600)
        secret=load_recipient_secret(root/'recipient.key')
        envelope=seal_message(sender,bundle,message_id,clear,ttl=600,expected_recipient=pub_bytes(recipient))
        sub=None;pub=None
        start=time.monotonic()
        try:
            sub=_connect_mqtt(host,port,timeout,tls=tls)
            _subscribe(sub,topic)
            pub=_connect_mqtt(host,port,timeout,tls=tls)
            _publish(pub,topic,envelope)
            received=None
            # MQTT public brokers might send an initial PING or metadata; refuse
            # anything except a valid publish on the exact random topic.
            for _ in range(3):
                kind,raw=_read_packet(sub)
                if kind&0xf0!=0x30:
                    raise PublicRelayError('broker returned unexpected MQTT packet')
                target,payload=_parse_publish(kind,raw)
                if target != topic:
                    raise PublicRelayError('broker delivered incorrect random topic')
                received=payload
                break
            if received is None:
                raise PublicRelayError('no encrypted message received')
            inspect_envelope(received,sender=pub_bytes(sender),
                             recipient=pub_bytes(recipient),message_id=message_id)
            if open_message(recipient,secret,received,expected_sender=pub_bytes(sender),
                            expected_message_id=message_id)!=clear:
                raise PublicRelayError('recipient plaintext not equal after relay')
            return {
                'status':'PASS','profile':'PM11/IE60','broker':host,'port':port,
                'transport':'MQTT over verified TLS' if tls else 'local MQTT',
                'sender_connections':1,'recipient_connections':1,
                'encrypted_envelope_bytes':len(envelope),
                'roundtrip_ms':round((time.monotonic()-start)*1000,1),
                'sha256_of_synthetic_plaintext':hashlib.sha256(clear).hexdigest(),
                'limits':'Anonymous untrusted public broker; not INNERnet server, storage, autonomous routing, or independent-host test'
            }
        finally:
            _close(pub);_close(sub)


def main(argv=None):
    parser=argparse.ArgumentParser(description='INNERnet PM11 public MQTT ciphertext experiment')
    parser.add_argument('--broker',default='test.mosquitto.org')
    parser.add_argument('--port',type=int,default=8886)
    parser.add_argument('--timeout',type=float,default=8)
    parser.add_argument('--plain-localhost',action='store_true',
                        help='Only permit non-TLS when broker is 127.0.0.1 or ::1')
    args=parser.parse_args(argv)
    try:
        print(json.dumps(relay_probe(args.broker,args.port,timeout=args.timeout,
                                    tls=not args.plain_localhost),indent=2))
    except (OSError,ssl.SSLError,PublicRelayError,TimeoutError) as exc:
        print(json.dumps({'status':'UNAVAILABLE','broker':args.broker,
                          'reason':str(exc),'interpretation':'public broker probe failed; not a core INNERnet qualification failure'},indent=2))
        raise SystemExit(1)

if __name__=='__main__':main()
