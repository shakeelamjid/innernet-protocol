"""R90 explicit two-hop replica forwarding and recipient retrieval.

Recipient ciphertext passes unchanged across both nodes. Configured static
peer allowlist, no arbitrary network targets, no autonomous topology or routing.
"""
from __future__ import annotations

import socketserver
import socket
from collections import OrderedDict
import sqlite3
import os
import stat
from pathlib import Path
from dataclasses import dataclass
import threading
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .native_udp import pub_bytes
from .stream_v080 import accept, connect, StreamError
from .bulk_v080 import ChunkStore, BulkError, verify_manifest, PreparedObject, decrypt_package, RecipientWriter, CHUNK_SIZE


@dataclass(frozen=True)
class Peer:
    host: str
    port: int
    pinned_key: bytes


class BulkClient:
    """Pinned authenticated persistent channel; chunk PUTs are pipelined."""
    def __init__(self, peer: Peer, identity: Ed25519PrivateKey, *, timeout: float=15):
        self.session=connect(peer.host,peer.port,identity,peer.pinned_key,timeout=timeout)
        self.sequence=0

    def close(self): self.session.sock.close()
    def __enter__(self): return self
    def __exit__(self,*_): self.close()

    def call(self, command: str, **fields):
        # Forwarding a 100-MiB encrypted replica can involve thousands of fsynced
        # commits; it must not inherit the ordinary 15-second per-RPC deadline.
        if command == "forward":
            before=self.session.sock.gettimeout()
            try:
                self.session.sock.settimeout(180)
                replies=self.batch([(dict(cmd=command,**fields),b"")])
            finally:
                self.session.sock.settimeout(before)
        else:
            replies=self.batch([(dict(cmd=command,**fields),b"")])
        return replies[0]

    def iter_batch(self, commands: list[tuple[dict,bytes]]):
        """Pipeline bounded RPCs; consume replies one at a time to cap memory."""
        if not 1<=len(commands)<=64: raise BulkError("pipeline size must be 1-64")
        expected=[]
        for head,blob in commands:
            self.sequence+=1
            rid=self.sequence
            self.session.write({**head,"rid":rid},blob)
            expected.append(rid)
        for rid in expected:
            head,blob=self.session.read()
            if head.get("rid")!=rid:
                raise StreamError("out-of-order or mismatched authenticated receipt")
            if head.get("status")!="OK":
                raise BulkError(f"peer rejected {rid}: {head.get('error','unknown')}")
            yield head,blob

    def batch(self, commands: list[tuple[dict,bytes]]) -> list[tuple[dict,bytes]]:
        return list(self.iter_batch(commands))

    def upload(self, prepared: PreparedObject, *, window: int=16,
               stop_after: int | None=None) -> dict:
        if not 1<=window<=64: raise BulkError("invalid pipeline window")
        record=prepared.record; ident=record["payload"]["object_id"]
        self.call("manifest",record=record)
        missing=self.call("missing",ident=ident)[0]["indexes"]
        if stop_after is not None:
            missing=missing[:stop_after]
        start=time.monotonic()
        for offset in range(0,len(missing),window):
            numbers=missing[offset:offset+window]
            cmds=[({"cmd":"put","ident":ident,"idx":i},prepared.chunk(i)) for i in numbers]
            self.batch(cmds)
        elapsed=time.monotonic()-start
        state=self.call("stats",ident=ident)[0]
        return {"committed":len(missing),"elapsed_seconds":round(elapsed,3),
                "throughput_mib_s":round(len(missing)*65536/max(elapsed,.000001)/1048576,3),
                "stored":state["stored"],"total":state["total"],"complete":state["complete"]}

    def fetch(self, ident: str, recipient_identity, recipient_secret, output: Path,
              *, window: int=16, resume_dir: Path | None=None,
              expected_sender: bytes | None=None) -> dict:
        """Stream authenticated ciphertext; optionally checkpoint to a private disk.

        ``resume_dir`` keeps only recipient-encrypted chunks and their signed
        manifest. It must be an existing owner-only directory (0700). A failed
        fetch leaves it intact for retry. Completed fetch removes its checkpoint.
        This is not seamless migration if node routing or availability changes:
        use the same verified object ID and recipient keys on a pinned fallback.
        """
        if type(window) is not int or not 1<=window<=64:
            raise BulkError("invalid recipient read window")
        if not isinstance(expected_sender, bytes) or len(expected_sender) != 32:
            raise BulkError("original sender Ed25519 identity must be explicitly pinned")
        manifest_reply=self.call("get_manifest",ident=ident)[0]
        if not isinstance(manifest_reply,dict) or not isinstance(manifest_reply.get("record"),dict):
            raise BulkError("malformed peer manifest response")
        record=manifest_reply["record"]
        p=verify_manifest(record)
        if ident != p['object_id']:
            raise BulkError("requested object ID not signed manifest ID")
        if p["sender"] != expected_sender.hex():
            raise BulkError("unexpected original sender identity")
        if p["recipient"] != pub_bytes(recipient_identity).hex():
            raise BulkError("object addressed to a different recipient")
        features_reply=self.call("ping")[0]
        capabilities=features_reply.get("features",[]) if isinstance(features_reply,dict) else None
        if not isinstance(capabilities,list) or any(not isinstance(f,str) for f in capabilities):
            raise BulkError("malformed peer capability response")
        fast="get-range-v1" in capabilities
        checkpoint=None
        checkpoint_path=None
        writer=None
        finished=False
        requests=0
        downloaded=0
        started=time.monotonic()
        try:
            if resume_dir is not None:
                directory=Path(resume_dir)
                if (directory.is_symlink() or not directory.is_dir() or
                        directory.stat().st_mode & 0o077):
                    raise BulkError("recipient checkpoint directory must exist and be owner-only (0700)")
                checkpoint_path=directory / ('innernet-recv-'+ident+'.sqlite')
                if checkpoint_path.is_symlink():
                    raise BulkError("refusing recipient checkpoint symlink")
                if not checkpoint_path.exists():
                    # Exclusive owner-only create; SQLite then opens this file.
                    fd=os.open(checkpoint_path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|
                               getattr(os,"O_NOFOLLOW",0),0o600)
                    os.close(fd)
                elif checkpoint_path.stat().st_mode & 0o077:
                    raise BulkError("recipient checkpoint permissions are not owner-only")
                checkpoint=ChunkStore(checkpoint_path,max_objects=1,
                                      max_storage_bytes=128*1024*1024+32768)
                checkpoint.manifest(record,allow_legacy_replica=True)
                missing=checkpoint.missing(ident)
                reused=p['chunks']-len(missing)
            else:
                writer=RecipientWriter(record,recipient_identity,recipient_secret,output)
                missing=list(range(p['chunks']))
                reused=0

            def receive(idx: int, cipher: bytes):
                nonlocal downloaded
                if checkpoint is not None:
                    checkpoint.put(ident,idx,cipher)
                else:
                    writer.write_chunk(cipher)
                downloaded+=1

            if fast:
                ranges=[]
                offset=0
                while offset<len(missing):
                    begin=missing[offset]
                    count=1
                    while (count<4 and offset+count<len(missing) and
                           missing[offset+count]==begin+count):
                        count+=1
                    ranges.append((begin,count))
                    offset+=count
                for offset in range(0,len(ranges),window):
                    group=ranges[offset:offset+window]
                    batch=[({"cmd":"get_range","ident":ident,"start":i,"count":count},b"")
                           for i,count in group]
                    for (i,count),(_,blob) in zip(group,self.iter_batch(batch)):
                        expected=sum(min(CHUNK_SIZE,p["size"]-j*CHUNK_SIZE)+16
                                     for j in range(i,i+count))
                        if len(blob)!=expected:
                            raise BulkError("malformed concatenated encrypted range")
                        cursor=0
                        for j in range(i,i+count):
                            size=min(CHUNK_SIZE,p["size"]-j*CHUNK_SIZE)+16
                            receive(j,blob[cursor:cursor+size]);cursor+=size
                    requests+=len(batch)
            else:
                for offset in range(0,len(missing),window):
                    group=missing[offset:offset+window]
                    batch=[({"cmd":"get","ident":ident,"idx":i},b"") for i in group]
                    for i,(_,blob) in zip(group,self.iter_batch(batch)):
                        receive(i,blob)
                    requests+=len(batch)
            fetch_seconds=time.monotonic()-started
            if checkpoint is not None:
                # No plaintext output until the complete authenticated set exists.
                if checkpoint.missing(ident):
                    raise BulkError("recipient checkpoint still missing encrypted chunks")
                writer=RecipientWriter(record,recipient_identity,recipient_secret,output)
                for i in range(p['chunks']):
                    writer.write_chunk(checkpoint.get(ident,i))
            result=writer.finish()
            finished=True
            downloaded_bytes=sum(min(CHUNK_SIZE,p['size']-i*CHUNK_SIZE)
                                 for i in missing)
            result.update({'fetch_mode':'get-range-v1' if fast else 'legacy-get',
                           'fetch_requests':requests,'fetch_seconds':round(fetch_seconds,3),
                           'fetch_mib_s':round(downloaded_bytes/1048576/max(fetch_seconds,.000001),3),
                           'recipient_cached_chunks':reused,
                           'recipient_downloaded_chunks':downloaded,
                           'receiver_memory_profile':'bounded one response frame; optional encrypted on-disk checkpoint'})
            return result
        finally:
            if writer is not None:writer.close()
            if checkpoint is not None:checkpoint.close()
            if finished and checkpoint_path is not None:
                for suffix in ('','-wal','-shm'):
                    (Path(str(checkpoint_path)+suffix)).unlink(missing_ok=True)



def _forward(source_db: Path, ident: str, peer: Peer, identity: Ed25519PrivateKey) -> dict:
    started=time.monotonic()
    local=ChunkStore(source_db)
    try:
        record=local.get_manifest(ident)
        if local.missing(ident):
            raise BulkError("cannot forward incomplete source object")
        with BulkClient(peer,identity) as link:
            link.call("manifest",record=record)
            missing=link.call("missing",ident=ident)[0]["indexes"]
            for off in range(0,len(missing),16):
                numbers=missing[off:off+16]
                link.batch([({"cmd":"put","ident":ident,"idx":i},local.get(ident,i))
                            for i in numbers])
            status=link.call("stats",ident=ident)[0]
            if not status["complete"]:
                raise BulkError("peer replica missing chunks after forwarding")
            elapsed=time.monotonic()-started
            return {"forwarded":len(missing),"replica_complete":True,
                    "forward_elapsed_seconds":round(elapsed,3),
                    "forward_payload_mib_s":round(len(missing)*CHUNK_SIZE/1048576/max(elapsed,.000001),3),
                    "peer_receipt":"authenticated hop store acknowledgement"}
    finally:
        local.close()


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        active = False
        try:
            try:
                link=accept(self.request,self.server.identity,self.server.allowed)
            except (StreamError,OSError,TimeoutError):
                return
            finally:
                self.server.release_pre_auth(self.request)
            # Authentication completed: move from admission pool to active slots.
            if not self.server.reserve_active(link.peer):
                return
            active = True
            try:
                store=ChunkStore(self.server.database,
                                 max_storage_bytes=self.server.max_storage_bytes,
                                 max_objects=self.server.max_objects)
            except (OSError,ValueError):
                return
            while True:
                try: head,blob=link.read()
                except (StreamError,OSError): break
                rid=head.get("rid")
                try:
                    op=head.get("cmd")
                    ident=head.get("ident")
                    if op=="manifest":
                        record=head["record"]
                        p=verify_manifest(record)
                        if link.peer!=bytes.fromhex(p["sender"]) and link.peer not in self.server.relays:
                            raise BulkError("only owner or configured relay can publish object")
                        new=store.manifest(record,allow_legacy_replica=(
                            p["version"] != "OB80-2" and link.peer in self.server.relays))
                        result={"new":new};reply=b""
                    elif op in ("put","missing","stats","get","get_range","get_manifest","forward"):
                        record=store.get_manifest(ident)
                        p=record["payload"]
                        sender=bytes.fromhex(p["sender"])
                        recipient=bytes.fromhex(p["recipient"])
                        if op in ("put","missing","stats"):
                            if link.peer not in (sender,recipient) and link.peer not in self.server.relays:
                                raise BulkError("not authorized for object access")
                        elif op in ("get","get_range","get_manifest"):
                            if link.peer not in (recipient,sender) and link.peer not in self.server.relays:
                                raise BulkError("not authorized for object retrieval")
                        elif op=="forward" and link.peer!=sender:
                            raise BulkError("only original sender may order replication")
                        if op=="put":
                            result={"commit":store.put(ident,head["idx"],blob)};reply=b""
                        elif op=="missing":
                            result={"indexes":store.missing(ident)};reply=b""
                        elif op=="stats":
                            result=store.statistics(ident);reply=b""
                        elif op=="get":
                            result={"idx":head["idx"]};reply=store.get(ident,head["idx"])
                        elif op=="get_range":
                            start,count=head["start"],head["count"]
                            reply=store.get_range(ident,start,count)
                            result={"start":start,"count":count}
                        elif op=="get_manifest":
                            result={"record":record};reply=b""
                        elif op=="forward":
                            name=head.get("peer_id")
                            if not isinstance(name,str) or name not in self.server.peers:
                                raise BulkError("target not in static allowlisted peers")
                            result=_forward(self.server.database,ident,self.server.peers[name],self.server.identity)
                            reply=b""
                    elif op=="ping":
                        result={"pong":True,"node":pub_bytes(self.server.identity).hex(),
                                "features":["get-range-v1","streaming-fetch-v1","quota-v1"]};reply=b""
                    else: raise BulkError("unrecognized command")
                    link.write({"status":"OK","rid":rid,**result},reply)
                except (BulkError,ValueError,TypeError,KeyError,OSError,sqlite3.Error) as exc:
                    try: link.write({"status":"ERR","rid":rid,"error":str(exc)[:160]})
                    except (StreamError,OSError): break
        finally:
            if 'store' in locals():
                store.close()
            if active:
                self.server.release_active(link.peer)


class BulkServer(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True
    request_queue_size=32

    def __init__(self, address: tuple[str,int], identity: Ed25519PrivateKey,
                 db: Path, allowed: set[bytes], *, relays: set[bytes] | None=None,
                 peers: dict[str,Peer] | None=None,
                 max_storage_bytes: int | None=512*1024*1024,
                 max_objects: int | None=128, max_connections: int=32):
        if type(max_connections) is not int or not 1<=max_connections<=256:
            raise BulkError("invalid server connection cap")
        self.max_connections=max_connections
        self._slots=threading.BoundedSemaphore(max_connections)
        self._active_by_identity={}
        self._active_lock=threading.Lock()
        self._active_per_identity=min(8,max_connections)
        # A separate pre-auth budget must not be limited by the authenticated
        # connection cap. Bound it independently, evict the oldest stalled
        # socket under pressure, and retain per-IP admission limits.
        self._pre_auth=threading.BoundedSemaphore(64)
        self._pre_auth_ips={}
        self._pre_auth_sockets=OrderedDict()
        self._pre_auth_lock=threading.Lock()
        self.max_storage_bytes=max_storage_bytes
        self.max_objects=max_objects
        self.identity=identity
        self.database=Path(db)
        self.allowed=set(allowed)
        self.relays=set(relays or ())
        self.peers=dict(peers or {})
        if not self.relays.issubset(self.allowed):
            raise BulkError("configured relays must be in authenticated allowlist")
        super().__init__(address,_Handler)

    def reserve_active(self, peer: bytes) -> bool:
        # An allowlisted identity must not monopolize all authenticated slots.
        with self._active_lock:
            if self._active_by_identity.get(peer,0) >= self._active_per_identity:
                return False
            if not self._slots.acquire(blocking=False):
                return False
            self._active_by_identity[peer]=self._active_by_identity.get(peer,0)+1
            return True

    def release_active(self, peer: bytes) -> None:
        with self._active_lock:
            count=self._active_by_identity[peer]
            if count == 1:
                del self._active_by_identity[peer]
            else:
                self._active_by_identity[peer]=count-1
            self._slots.release()

    def verify_request(self,request,client_address):
        ip=client_address[0]
        with self._pre_auth_lock:
            if self._pre_auth_ips.get(ip,0)>=2:
                return False
            if not self._pre_auth.acquire(blocking=False):
                # Oldest-first eviction prevents a handful of slow sockets
                # from indefinitely denying admission to every new client.
                oldest,oldip=self._pre_auth_sockets.popitem(last=False)
                count=self._pre_auth_ips[oldip]
                if count==1:self._pre_auth_ips.pop(oldip,None)
                else:self._pre_auth_ips[oldip]=count-1
                self._pre_auth.release()
                try:oldest.shutdown(socket.SHUT_RDWR)
                except OSError:pass
                if not self._pre_auth.acquire(blocking=False):
                    return False
            self._pre_auth_ips[ip]=self._pre_auth_ips.get(ip,0)+1
            self._pre_auth_sockets[request]=ip
        return True

    def release_pre_auth(self,request):
        with self._pre_auth_lock:
            ip=self._pre_auth_sockets.pop(request,None)
            if ip is not None:
                count=self._pre_auth_ips[ip]
                if count==1:self._pre_auth_ips.pop(ip,None)
                else:self._pre_auth_ips[ip]=count-1
                self._pre_auth.release()


def serve_background(server: BulkServer):
    import threading
    t=threading.Thread(target=server.serve_forever,daemon=True)
    t.start()
    return t
