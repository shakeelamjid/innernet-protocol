"""Candidate UV10 application API on top of pinned ST80/recipient-only OB80.

Public deployments require independent security review; no automatic
node discovery, NAT traversal, or group messaging is provided.
"""
from __future__ import annotations

import json
from pathlib import Path
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .bulk_v080 import prepare_file, load_prepared, BulkError
from .relay_v090 import BulkClient, Peer
from .routing_v090 import recipient_peers
from .native_udp import pub_bytes, parse_public_hex, load_identity
from .mailbox_e2ee import load_recipient_secret
from .transit_v100 import fetch_any
from .universal_v1 import pack, unpack, UniversalError


def publish(stage: Path, sender: Ed25519PrivateKey, bundle: dict,
            peer: Peer, *, expected_recipient: bytes, checkpoint: Path | None=None, window: int=32) -> dict:
    """Commit a local UV10 container to pinned OB80 relay; save sender checkpoint.

    Stage is plaintext local source. The relay receives recipient-only OB80
    ciphertext. Checkpoint includes sensitive ephemeral material (0600).
    """
    from .universal_v1 import inspect
    inspect(stage)
    if not isinstance(expected_recipient, bytes) or len(expected_recipient) != 32:
        raise BulkError("independently pinned recipient identity is required")
    from .mailbox_e2ee import verify_bundle
    verify_bundle(bundle, expected_recipient)
    if checkpoint is not None and Path(checkpoint).exists():
        prepared=load_prepared(Path(checkpoint),sender,bundle)
        if prepared.payload["recipient"] != expected_recipient.hex():
            raise BulkError("checkpoint recipient does not match pinned recipient")
        if Path(prepared.source).resolve()!=Path(stage).resolve():
            raise UniversalError("checkpoint references different staging file")
    else:
        prepared=prepare_file(stage,sender,bundle,expected_recipient=expected_recipient)
        if checkpoint is not None:
            prepared.save(Path(checkpoint))
    with BulkClient(peer,sender) as client:
        result=client.upload(prepared,window=window)
    if not result["complete"]:
        raise BulkError("not all encrypted chunks committed")
    return {"status":"COMMITTED_TO_RELAY","object_id":prepared.payload["object_id"],
            "bytes":prepared.payload["size"],"chunks":prepared.payload["chunks"],
            "receipt":"relay SQLite commit, NOT recipient consumption",**result}


def receive(signed_routes: dict, pinned_publisher: bytes, ident: str,
            recipient: Ed25519PrivateKey, recipient_secret: X25519PrivateKey,
            expected_sender: bytes, output: Path, *, window: int=16,
            resume_dir: Path | None=None) -> dict:
    """Verify signed route, pinned original sender and OB80, then unpack UV10.

    Recipient explicitly supplies final output path. An unknown source file
    cannot choose a filesystem path or overwrite existing data.
    """
    peers=recipient_peers(signed_routes,pinned_publisher,pub_bytes(recipient))
    with tempfile.TemporaryDirectory(prefix="innernet-uv10-recv-") as td:
        plain=Path(td)/"authenticated.uv10"
        result=fetch_any(peers,ident,recipient,recipient_secret,plain,window=window,
                         resume_dir=resume_dir,expected_sender=expected_sender)
        app=unpack(plain,output)
        return {"status":"VERIFIED_APPLICATION_DELIVERY","object_id":ident,
                "kind":app["kind"],"content_type":app["content_type"],
                "size":app["size"],"name":app["name"],
                "node_used":result["node_used"],
                "failed_prior_nodes":result["failed_prior_nodes"],
                "authenticated_object_sha256":result["sha256"]}


def main(argv=None):
    import argparse
    ap=argparse.ArgumentParser(description="INNERnet universal experimental application delivery (NOT audited)")
    sub=ap.add_subparsers(dest="action",required=True)
    s=sub.add_parser("publish",help="encrypt UV10 staging file and commit to pinned ST80 node")
    s.add_argument("--stage",required=True,type=Path)
    s.add_argument("--sender-key",required=True,type=Path)
    s.add_argument("--recipient-bundle",required=True,type=Path)
    s.add_argument("--recipient",required=True,help="independently verified Ed25519 recipient public key")
    s.add_argument("--host",required=True)
    s.add_argument("--port",required=True,type=int)
    s.add_argument("--pinned-node",required=True)
    s.add_argument("--checkpoint",type=Path)
    s.add_argument("--window",type=int,default=32)
    r=sub.add_parser("receive",help="fetch from pinned route, validate OB80 and unpack application bytes")
    r.add_argument("--routes",required=True,type=Path)
    r.add_argument("--pinned-publisher",required=True)
    r.add_argument("--object-id",required=True)
    r.add_argument("--recipient-key",required=True,type=Path)
    r.add_argument("--recipient-secret",required=True,type=Path)
    r.add_argument("--expected-sender",required=True)
    r.add_argument("--output",required=True,type=Path)
    r.add_argument("--resume-dir",type=Path)
    r.add_argument("--window",type=int,default=16)
    args=ap.parse_args(argv)
    if args.action=="publish":
        peer=Peer(args.host,args.port,parse_public_hex(args.pinned_node))
        result=publish(args.stage,load_identity(args.sender_key),
                       json.loads(args.recipient_bundle.read_text()),peer,
                       expected_recipient=parse_public_hex(args.recipient),
                       checkpoint=args.checkpoint,window=args.window)
    else:
        result=receive(json.loads(args.routes.read_text()),
                       parse_public_hex(args.pinned_publisher),args.object_id,
                       load_identity(args.recipient_key),
                       load_recipient_secret(args.recipient_secret),
                       parse_public_hex(args.expected_sender),args.output,
                       resume_dir=args.resume_dir,window=args.window)
    print(json.dumps(result,indent=2))


if __name__=="__main__": main()
