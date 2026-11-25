"""R90 signed, bounded multi-node routing plans with pinned publisher identity.

Not decentralized discovery: authority is static and user-pinned; failure-domain
values are operator assertions, not independently proven. Plan expires strictly.
"""
from __future__ import annotations
import json
import os
import time
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from .mailbox_e2ee import canonical
from .native_udp import pub_bytes
from .bulk_v080 import BulkError,_bytes
from .relay_v090 import Peer

DOMAIN=b"INNERnet/R90/signed-route-plan\x00"
VERSION="R90-ROUTE-1"
# ROUTE-2 adds a mandatory monotonic `sequence` field. When a client verifies
# with a SequenceStore, a plan whose sequence is <= the highest already seen
# from that publisher is rejected, which prevents replay/rollback of an older
# but still-unexpired plan. ROUTE-1 is retained verbatim for read/forward
# compatibility and has NO anti-rollback, exactly as before.
VERSION2="R90-ROUTE-2"
MAX_SEQUENCE=2**63-1


def _validate(payload: dict, instant: int) -> None:
    if not isinstance(payload,dict):
        raise BulkError("malformed signed route plan")
    version=payload.get('version')
    if version==VERSION:
        expected_fields={"version","issued_at","expires_at","nodes","routes"}
    elif version==VERSION2:
        expected_fields={"version","sequence","issued_at","expires_at","nodes","routes"}
    else:
        raise BulkError('unsupported route plan version')
    if set(payload)!=expected_fields:
        raise BulkError("malformed signed route plan")
    if version==VERSION2 and (type(payload['sequence']) is not int
                              or not 0<=payload['sequence']<=MAX_SEQUENCE):
        raise BulkError('invalid route plan sequence')
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


class SequenceStore:
    """Owner-private highest-sequence-seen record per R90 publisher.

    This is the client-side state that makes ROUTE-2 anti-rollback work: the
    publisher key must be independently pinned, and the store simply refuses to
    move backwards. File-backed, created mode 0600 in a 0700 directory.
    """
    def __init__(self, path: Path | str):
        self.path=Path(path).expanduser().absolute()
        if self.path.is_symlink() or self.path.parent.is_symlink():
            raise BulkError("sequence store must not be a symlink")
        self.path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        if self.path.parent.stat().st_mode & 0o077:
            raise BulkError("sequence store directory must be owner-only (0700)")
        if not self.path.exists():
            fd=os.open(self.path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,"O_NOFOLLOW",0),0o600)
            os.close(fd)
            self.path.write_text("{}")
        elif self.path.stat().st_mode & 0o077:
            raise BulkError("sequence store permissions are not owner-only")
        raw=json.loads(self.path.read_text() or "{}")
        if not isinstance(raw,dict) or any(not isinstance(k,str) or type(v) is not int for k,v in raw.items()):
            raise BulkError("corrupt sequence store")
        self._seen=raw

    def check_and_update(self, publisher_hex: str, sequence: int) -> None:
        highest=self._seen.get(publisher_hex)
        if highest is not None and sequence<=highest:
            raise BulkError("route plan sequence rolled back or replayed")
        self._seen[publisher_hex]=sequence
        tmp=self.path.with_name(self.path.name+".tmp")
        tmp.write_text(json.dumps(self._seen,sort_keys=True,separators=(",",":")))
        os.replace(tmp,self.path)


def sign_plan(payload: dict, publisher: Ed25519PrivateKey, *, now: int | None=None) -> dict:
    instant=int(time.time()) if now is None else now
    _validate(payload,instant)
    return {'payload':payload,'publisher':pub_bytes(publisher).hex(),
            'signature':publisher.sign(DOMAIN+canonical(payload)).hex()}


def verify_plan(record: dict, pinned_publisher: bytes, *, now: int | None=None,
                sequence_store: "SequenceStore | None"=None) -> dict:
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
    payload=record['payload']
    _validate(payload,instant)
    # Anti-rollback is only enforceable for ROUTE-2 plans that carry a sequence.
    # A caller that pins a store but is handed a legacy ROUTE-1 plan is told so,
    # rather than silently getting no rollback protection.
    if sequence_store is not None:
        if payload['version']!=VERSION2:
            raise BulkError('anti-rollback requires a ROUTE-2 sequenced plan')
        sequence_store.check_and_update(record['publisher'],payload['sequence'])
    return payload


def recipient_peers(signed: dict, pinned_publisher: bytes, recipient: bytes,
                    *, sequence_store: "SequenceStore | None"=None) -> list[Peer]:
    payload=verify_plan(signed,pinned_publisher,sequence_store=sequence_store)
    mapping={n['id']:n for n in payload['nodes']}
    for route in payload['routes']:
        if route['recipient']==recipient.hex():
            return [Peer(mapping[i]['host'],mapping[i]['port'],
                         _bytes(mapping[i]['public_ed25519'],32,'node key'))
                    for i in route['ordered_nodes']]
    raise BulkError('recipient absent from signed route plan')
