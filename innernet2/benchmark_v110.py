"""Bounded, synthetic, localhost-only read-request comparison, never a WAN claim.

Run: python -m benchmarks.v110_retrieval --mib 8 --window 16
Requires the v0.11 source installed or on PYTHONPATH.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from innernet2.bulk_v080 import CHUNK_SIZE,prepare_file
from innernet2.mailbox_e2ee import generate_bundle,load_recipient_secret
from innernet2.native_udp import pub_bytes
from innernet2.relay_v090 import BulkClient,BulkServer,Peer,serve_background


def run(mib: int=8,window: int=16)->dict:
    if not 1<=mib<=100 or not 1<=window<=64:
        raise ValueError('benchmark supports 1-100 MiB, 1-64 window')
    with tempfile.TemporaryDirectory(prefix='inn11-local-benchmark-') as td:
        root=Path(td);root.chmod(0o700)
        sender=Ed25519PrivateKey.generate()
        receiver=Ed25519PrivateKey.generate()
        key=Ed25519PrivateKey.generate()
        bundle=generate_bundle(receiver,root/'r.key')
        secret=load_recipient_secret(root/'r.key')
        src=root/'synthetic.bin'
        with src.open('xb') as out:
            out.write(b'SYNTHETIC:INNERnet/v0.11\n')
            remaining=mib*1048576-out.tell()
            while remaining>0:
                block=os.urandom(min(1048576,remaining));out.write(block);remaining-=len(block)
        prepared=prepare_file(src,sender,bundle,expected_recipient=pub_bytes(receiver))
        node=BulkServer(('127.0.0.1',0),key,root/'storage.db',
                        {pub_bytes(sender),pub_bytes(receiver)})
        peer=Peer('127.0.0.1',node.server_address[1],pub_bytes(key))
        serve_background(node)
        try:
            with BulkClient(peer,sender) as writer:
                upload=writer.upload(prepared,window=window)
                assert upload['complete']
            with BulkClient(peer,receiver) as reader:
                improved=reader.fetch(prepared.payload['object_id'],receiver,secret,
                                      root/'optimized.bin',window=window,expected_sender=pub_bytes(sender))
            class OldReadClient(BulkClient):
                def call(self,cmd,**kwargs):
                    if cmd=='ping':return ({'pong':True},b'')
                    return super().call(cmd,**kwargs)
            # OldReadClient emulates only the old v0.10 feature-negotiation result.
            # Storage and transport are identical, making request-count comparable.
            with OldReadClient(peer,receiver) as reader:
                legacy=reader.fetch(prepared.payload['object_id'],receiver,secret,
                                    root/'legacy.bin',window=window,expected_sender=pub_bytes(sender))
            expected=hashlib.sha256(src.read_bytes()).hexdigest()
            assert improved['sha256']==legacy['sha256']==expected
            return {'status':'PASS','scope':'single-machine TCP with same v0.11 server',
                    'mib':mib,'chunks':prepared.payload['chunks'],
                    'optimized':{k:improved[k] for k in ('fetch_requests','fetch_seconds','fetch_mib_s','fetch_mode')},
                    'legacy_compatible_path':{k:legacy[k] for k in ('fetch_requests','fetch_seconds','fetch_mib_s','fetch_mode')},
                    'request_count_reduction_factor':round(legacy['fetch_requests']/max(improved['fetch_requests'],1),2),
                    'note':'localhost timings vary; this is not a v0.10 WAN comparison or proof of network speedup'}
        finally:node.shutdown();node.server_close()


def main(argv=None):
    parser=argparse.ArgumentParser()
    parser.add_argument('--mib',type=int,default=8)
    parser.add_argument('--window',type=int,default=16)
    args=parser.parse_args(argv)
    print(json.dumps(run(args.mib,args.window),indent=2))

if __name__=='__main__':main()
