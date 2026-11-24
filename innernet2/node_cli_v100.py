"""Explicit operator opt-in ST80 bulk node (synthetic test traffic only)."""
from __future__ import annotations
from .version import RELEASE_VERSION

import argparse
import json
import ipaddress
from pathlib import Path
from .native_udp import generate_identity_file,load_identity,pub_bytes,parse_public_hex
from .relay_v090 import BulkServer,Peer
from .bulk_v080 import ChunkStore


def main(argv=None):
    parser=argparse.ArgumentParser(description='INNERnet experimental ST80 node; localhost by default')
    sub=parser.add_subparsers(dest='action',required=True)
    gen=sub.add_parser('identity-init',help='create 0600 Ed25519 key, never overwrite')
    gen.add_argument('--key',required=True,type=Path)
    maintenance=sub.add_parser('maintenance',help='local read-only usage, optional explicit expired-data cleanup')
    maintenance.add_argument('--db',required=True,type=Path)
    maintenance.add_argument('--prune-expired',action='store_true',help='delete only signed-expired test objects')
    serve=sub.add_parser('serve',help='serve synthetic encrypted objects; default loopback only')
    serve.add_argument('--key',required=True,type=Path)
    serve.add_argument('--db',required=True,type=Path)
    serve.add_argument('--host',default='127.0.0.1')
    serve.add_argument('--port',type=int,default=29420)
    serve.add_argument('--allow-client',action='append',required=True)
    serve.add_argument('--allow-relay',action='append',default=[])
    serve.add_argument('--max-storage-mib',type=int,default=512,
                       help='ciphertext payload quota, 1..65536 MiB (default 512)')
    serve.add_argument('--max-objects',type=int,default=128,
                       help='maximum signed object records, 1..100000')
    serve.add_argument('--max-connections',type=int,default=32,
                       help='maximum active socket handlers, 1..256')
    serve.add_argument('--peer-config',type=Path,
                       help='optional local JSON object of named, statically pinned peers')
    serve.add_argument('--unsafe-public-listen',action='store_true',help='explicit authorization for a non-loopback bind; configure external firewall separately')
    args=parser.parse_args(argv)
    if args.action=='identity-init':
        print(json.dumps({'public_ed25519':generate_identity_file(args.key),
                          'private_seed_path':str(args.key),'warning':'NEVER SHARE THE PRIVATE SEED'},indent=2))
        return
    if args.action=='maintenance':
        if not args.db.is_file() or args.db.is_symlink():
            raise SystemExit('maintenance requires existing regular SQLite database (no symlinks)')
        with_store=ChunkStore(args.db)
        try:
            result=with_store.prune_expired() if args.prune_expired else with_store.usage()
        finally:with_store.close()
        print(json.dumps({'status':'OK','action':'prune-expired' if args.prune_expired else 'usage',**result},indent=2))
        return
    if not 1<=args.max_storage_mib<=65536 or not 1<=args.max_objects<=100000 or not 1<=args.max_connections<=256:
        raise SystemExit('quota or connection limit outside allowed bounds')
    try:
        loopback=ipaddress.ip_address(args.host).is_loopback
    except ValueError:
        raise SystemExit('host must be a literal IPv4 address')
    if not loopback and not args.unsafe_public_listen:
        raise SystemExit('Refusing public bind without --unsafe-public-listen AND firewall review')
    if not 1<=args.port<=65535:
        raise SystemExit('invalid port')
    identity=load_identity(args.key)
    allowed={parse_public_hex(k) for k in args.allow_client}
    relays={parse_public_hex(k) for k in args.allow_relay}
    if not relays.issubset(allowed):
        raise SystemExit('every relay must also be explicitly listed in --allow-client')
    peers={}
    if args.peer_config:
        if args.peer_config.stat().st_size>20000:
            raise SystemExit('peer file too large')
        raw=json.loads(args.peer_config.read_text())
        if not isinstance(raw,dict) or len(raw)>16:
            raise SystemExit('peer configuration must be a bounded map')
        for label,rec in raw.items():
            if not isinstance(label,str) or not label or len(label)>64 or set(rec)!={'host','port','public_ed25519'}:
                raise SystemExit('invalid peer configuration')
            port=int(rec['port'])
            if not 1 <= port <= 65535:
                raise SystemExit('peer port outside 1..65535')
            peers[label]=Peer(rec['host'],port,parse_public_hex(rec['public_ed25519']))
    server=BulkServer((args.host,args.port),identity,args.db,allowed,relays=relays,peers=peers,
                      max_storage_bytes=args.max_storage_mib*1048576,
                      max_objects=args.max_objects,
                      max_connections=args.max_connections)
    print(json.dumps({'ready':True,'release':RELEASE_VERSION,'wire':'ST81/OB80-2/R90',
                      'bind':args.host,'port':args.port,
                      'node_public_ed25519':pub_bytes(identity).hex(),
                      'authorized_clients':len(allowed),'configured_relays':len(relays),
                      'peers':sorted(peers),'synthetic_only':True,
                      'max_storage_mib':args.max_storage_mib,
                      'max_objects':args.max_objects,'max_connections':args.max_connections,
                      'security':'research only; bounded resources are not a DoS audit'},indent=2),flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()

if __name__=='__main__':main()
