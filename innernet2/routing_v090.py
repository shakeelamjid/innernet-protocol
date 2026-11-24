"""R90 signed, bounded multi-node routing plans with pinned publisher identity.

Not decentralized discovery: authority is static and user-pinned; failure-domain
values are operator assertions, not independently proven. Plan expires strictly.
"""
from __future__ import annotations
import time
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from .mailbox_e2ee import canonical
from .native_udp import pub_bytes
from .bulk_v080 import BulkError,_bytes
from .relay_v090 import Peer

DOMAIN=b"INNERnet/R90/signed-route-plan\x00"
VERSION="R90-ROUTE-1"


def _validate(payload: dict, instant: int) -> None:
    if not isinstance(payload,dict) or set(payload)!={"version","issued_at","expires_at","nodes","routes"}:
        raise BulkError("malformed signed route plan")
    if payload['version'] != VERSION:
        raise BulkError('unsupported route plan version')
    start,end=payload['issued_at'],payload['expires_at']
    if any(type(x) is not int for x in (start,end)) or start>instant+300 or not instant<end or not 60<=end-start<=86400:
        raise BulkError('route plan expired or invalid')
    nodes=payload['nodes'];routes=payload['routes']
    if not isinstance(nodes,list) or not 1<=len(nodes)<=32:
        raise BulkError('invalid node list')
    if not isinstance(routes,list) or not 1<=len(routes)<=128:
        raise BulkError('invalid route list')
    names=set();keys=set()
    for n in nodes:
        if not isinstance(n,dict) or set(n)!={'id','host','port','public_ed25519','failure_domain'}:
            raise BulkError('invalid node fields')
        if any(not isinstance(n[k],str) or not 1<=len(n[k])<=128 for k in ('id','host','failure_domain')):
            raise BulkError('invalid route name, hostname or failure-domain declaration')
        if any(ch.isspace() for ch in n['host']):
            raise BulkError('invalid host')
        if type(n['port']) is not int or not 1<=n['port']<=65535:
            raise BulkError('invalid port')
        key=_bytes(n['public_ed25519'],32,'node key').hex()
        if n['id'] in names or key in keys:
            raise BulkError('duplicate node identity')
        names.add(n['id']);keys.add(key)
    seen=set()
    for r in routes:
        if not isinstance(r,dict) or set(r)!={'recipient','ordered_nodes'}:
            raise BulkError('invalid recipient route')
        recipient=_bytes(r['recipient'],32,'recipient').hex()
        order=r['ordered_nodes']
        if (recipient in seen or not isinstance(order,list) or not 1<=len(order)<=len(nodes)
            or len(set(order))!=len(order) or any(n not in names for n in order)):
            raise BulkError('invalid ordered recipient endpoints')
        seen.add(recipient)


def sign_plan(payload: dict, publisher: Ed25519PrivateKey, *, now: int | None=None) -> dict:
    instant=int(time.time()) if now is None else now
    _validate(payload,instant)
    return {'payload':payload,'publisher':pub_bytes(publisher).hex(),
            'signature':publisher.sign(DOMAIN+canonical(payload)).hex()}


def verify_plan(record: dict, pinned_publisher: bytes, *, now: int | None=None) -> dict:
    if not isinstance(record,dict) or set(record)!={'payload','publisher','signature'}:
        raise BulkError('invalid route plan wrapper')
    if len(pinned_publisher)!=32 or record['publisher']!=pinned_publisher.hex():
        raise BulkError('route-plan publisher not pinned')
    try:
        Ed25519PublicKey.from_public_bytes(pinned_publisher).verify(
            _bytes(record['signature'],64,'signature'),DOMAIN+canonical(record['payload']))
    except (ValueError,InvalidSignature) as exc:
        raise BulkError('route plan signature invalid') from exc
    instant=int(time.time()) if now is None else now
    _validate(record['payload'],instant)
    return record['payload']


def recipient_peers(signed: dict, pinned_publisher: bytes, recipient: bytes) -> list[Peer]:
    payload=verify_plan(signed,pinned_publisher)
    mapping={n['id']:n for n in payload['nodes']}
    for route in payload['routes']:
        if route['recipient']==recipient.hex():
            return [Peer(mapping[i]['host'],mapping[i]['port'],
                         _bytes(mapping[i]['public_ed25519'],32,'node key'))
                    for i in route['ordered_nodes']]
    raise BulkError('recipient absent from signed route plan')
