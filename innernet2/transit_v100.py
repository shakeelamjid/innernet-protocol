"""INNERnet v0.8-0.10 combined ST80/OB80/R90 alpha demo and failover client.

No public deployment, no audited crypto, no independent implementation.
"""
from __future__ import annotations
from .version import RELEASE_VERSION

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .bulk_v080 import prepare_file,load_prepared,ChunkStore,BulkError
from .mailbox_e2ee import generate_bundle,load_recipient_secret
from .native_udp import pub_bytes
from .relay_v090 import Peer,BulkServer,BulkClient,serve_background
from .routing_v090 import sign_plan,recipient_peers


def fetch_any(peers: list[Peer], ident: str, recipient: Ed25519PrivateKey,
              secret, output: Path, *, window: int=16,
              resume_dir: Path | None=None,
              expected_sender: bytes | None=None) -> dict:
    """Verified client-side node failover; only trusts explicitly pinned endpoints."""
    if not isinstance(expected_sender, bytes) or len(expected_sender) != 32:
        raise BulkError("original sender Ed25519 identity must be explicitly pinned")
    failures=[]
    for peer in peers:
        try:
            with BulkClient(peer,recipient,timeout=3) as client:
                result=client.fetch(ident,recipient,secret,output,window=window,
                                    resume_dir=resume_dir,expected_sender=expected_sender)
                return {**result,"node_used":f"{peer.host}:{peer.port}",
                        "failed_prior_nodes":len(failures)}
        except MemoryError:
            raise
        except Exception as exc:
            # Any malformed response or parser failure on a pinned node is a
            # per-peer availability failure, not permission to skip sender pinning.
            # Never copy potentially attacker-controlled exception text to logs.
            failures.append(type(exc).__name__)
    raise BulkError(f"all {len(peers)} explicitly pinned endpoints failed: {failures}")


def _generate_file(path: Path,mib: int):
    """Generate data in bounded memory; artificial synthetic-only content."""
    with path.open('xb') as file:
        file.write(b"SYNTHETIC:INNERnet/v0.10.0\n")
        remaining=mib*1048576-file.tell()
        while remaining:
            data=os.urandom(min(remaining,1024*1024))
            file.write(data)
            remaining-=len(data)


def run_demo(mib: int=10,*,window: int=16) -> dict:
    if not 1<=mib<=100 or not 1<=window<=64:
        raise ValueError("demo supports 1..100 MiB and pipeline window 1..64")
    with tempfile.TemporaryDirectory(prefix="innernet-v100-alpha-") as td:
        root=Path(td)
        root.chmod(0o700)
        sender=Ed25519PrivateKey.generate()
        recipient=Ed25519PrivateKey.generate()
        node_a=Ed25519PrivateKey.generate()
        node_b=Ed25519PrivateKey.generate()
        bundle=generate_bundle(recipient,root/'recipient.key')
        secret=load_recipient_secret(root/'recipient.key')
        src=root/'synthetic-object.bin';_generate_file(src,mib)
        prepared=prepare_file(src,sender,bundle,expected_recipient=pub_bytes(recipient))
        prepared.save(root/'checkpoint.json')
        ident=prepared.payload['object_id']
        # Two real independent TCP listeners with separate keys and SQLite databases.
        allowed_a={pub_bytes(sender),pub_bytes(recipient)}
        allowed_b={pub_bytes(node_a),pub_bytes(recipient)}
        server_b=BulkServer(('127.0.0.1',0),node_b,root/'B.sqlite',allowed_b,
                            relays={pub_bytes(node_a)})
        peer_b=Peer('127.0.0.1',server_b.server_address[1],pub_bytes(node_b))
        server_a=BulkServer(('127.0.0.1',0),node_a,root/'A.sqlite',allowed_a,
                            peers={'replica-b':peer_b})
        peer_a=Peer('127.0.0.1',server_a.server_address[1],pub_bytes(node_a))
        serve_background(server_b);serve_background(server_a)
        operator=Ed25519PrivateKey.generate()
        now=int(time.time())
        signed_routes=sign_plan({
            'version':'R90-ROUTE-1','issued_at':now,'expires_at':now+3600,
            'nodes':[{'id':'A','host':peer_a.host,'port':peer_a.port,
                      'public_ed25519':peer_a.pinned_key.hex(),'failure_domain':'Contabo-simulated'},
                     {'id':'B','host':peer_b.host,'port':peer_b.port,
                      'public_ed25519':peer_b.pinned_key.hex(),'failure_domain':'Mac-simulated'}],
            'routes':[{'recipient':pub_bytes(recipient).hex(),'ordered_nodes':['A','B']}]},operator)
        verified_peers=recipient_peers(signed_routes,pub_bytes(operator),pub_bytes(recipient))
        try:
            started=time.monotonic()
            if os.environ.get('INN_TRACE'): print('phase first upload',flush=True)
            with BulkClient(peer_a,sender) as client:
                first=client.upload(prepared,window=window,stop_after=max(1,prepared.payload['chunks']//3))
                assert not first['complete']
            # Resumption from a saved private ephemeral sender checkpoint.
            if os.environ.get('INN_TRACE'): print('phase resumed upload',flush=True)
            restored=load_prepared(root/'checkpoint.json',sender,bundle)
            with BulkClient(peer_a,sender) as client:
                second=client.upload(restored,window=window)
                assert second['complete']
                if os.environ.get('INN_TRACE'): print('phase forwarding',flush=True)
                replica=client.call('forward',ident=ident,peer_id='replica-b')[0]
                assert replica['replica_complete']
            # Simulate a replica process restart: only its separate persistent
            # SQLite volume survives. This must happen BEFORE primary outage.
            if os.environ.get('INN_TRACE'): print('phase replica restart',flush=True)
            server_b.shutdown();server_b.server_close()
            server_b=BulkServer(('127.0.0.1',peer_b.port),node_b,root/'B.sqlite',allowed_b,
                                relays={pub_bytes(node_a)})
            serve_background(server_b)
            with BulkClient(peer_b,recipient) as recipient_probe:
                if not recipient_probe.call('stats',ident=ident)[0]['complete']:
                    raise AssertionError('replica lost chunks on process restart')
            # Actual source node failure. Recipient tries it, then uses replicated node.
            if os.environ.get('INN_TRACE'): print('phase primary outage',flush=True)
            server_a.shutdown();server_a.server_close()
            if os.environ.get('INN_TRACE'): print('phase recipient fallback',flush=True)
            result=fetch_any(verified_peers,ident,recipient,secret,root/'reconstructed.bin',window=window,expected_sender=pub_bytes(sender))
            if result['failed_prior_nodes']!=1:
                raise AssertionError('replica recovery did not exercise actual fallback')
            if hashlib.sha256(src.read_bytes()).hexdigest()!=result['sha256']:
                raise AssertionError('whole-object SHA256 mismatch')
            elapsed=time.monotonic()-started
            return {
                'status':'PASS',
                'release':RELEASE_VERSION,
                'v080_bulk':{'mib':mib,'chunks':prepared.payload['chunks'],
                             'window':window,'resumed_chunks':second['committed'],
                             'first_partial_chunks':first['committed']},
                'v090_forwarding':replica,
                'v090_signed_fallback_routes':len(verified_peers),
                'v090_replica_restart_persistence':True,
                'v090_failed_primary_fallback':result['failed_prior_nodes'],
                'v100_recipient_sha256':result['sha256'],
                'v110_fetch':{'mode':result['fetch_mode'],
                              'requests':result['fetch_requests'],
                              'cached_chunks':result['recipient_cached_chunks'],
                              'downloaded_chunks':result['recipient_downloaded_chunks'],
                              'memory_profile':result['receiver_memory_profile']},
                'elapsed_seconds':round(elapsed,3),
                'transfer_profile':'authenticated TCP ST81 + pinned recipient OB80-2',
                'limitations':'2 local listener nodes; no WAN qualification, no audit, no autonomous topology'}
        finally:
            server_b.shutdown();server_b.server_close()
            try: server_a.server_close()
            except OSError: pass


def main(argv: list[str] | None=None) -> None:
    parser=argparse.ArgumentParser(description='Combined v0.8-v0.10 research milestone demo')
    parser.add_argument('command',choices=['demo'])
    parser.add_argument('--mib',type=int,default=10,help='1-100 MiB synthetic input')
    parser.add_argument('--window',type=int,default=16,help='1-64 pipelined chunk commits')
    args=parser.parse_args(argv)
    print(json.dumps(run_demo(args.mib,window=args.window),indent=2))

if __name__=='__main__':main()
