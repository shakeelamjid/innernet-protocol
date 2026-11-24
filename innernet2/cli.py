"""Small, safe-by-default CLI for INNERnet's localhost research pilot."""
from __future__ import annotations
from .version import RELEASE_VERSION

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import httpx
import uvicorn

from .network import MeshClient
from .audit import audit_node, audit_registry
from .node import create_app, initialize_node, private_write
from .observability import topology_report, load_registry, https_sample_baseline


def create_demo(path: Path, number: int, start_port: int):
    if not 9 <= number <= 24:
        raise ValueError("9-24 nodes supported by local demo")
    if path.exists():
        raise FileExistsError("demo directory already exists; choose a new path")
    path.mkdir(parents=True, mode=0o700)
    public, private = [], {}
    for i in range(number):
        node_id = f"node-{i + 1:02d}"
        node = initialize_node(path / node_id, node_id, f"http://127.0.0.1:{start_port + i}")
        public.append({k: node[k] for k in ("id", "url", "public_key")})
        private[node_id] = node["write_token"]
    (path / "peers.json").write_text(json.dumps({"nodes": public}, indent=2) + "\n")
    private_write(path / "writers.json", (json.dumps({"tokens": private}, indent=2) + "\n").encode())
    print(json.dumps({"nodes": number, "directory": str(path),
                      "public_registry": str(path / 'peers.json'),
                      "private_writers": str(path / 'writers.json')}, indent=2))


def start_demo(path: Path):
    registry = json.loads((path / "peers.json").read_text())
    procs = []
    try:
        for node in registry["nodes"]:
            from urllib.parse import urlsplit
            port = urlsplit(node["url"]).port
            p = subprocess.Popen([sys.executable, "-m", "innernet2.cli", "serve-node",
                                  "--dir", str(path / node["id"]), "--port", str(port)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            procs.append(p)
        with httpx.Client(timeout=0.75) as client:
            for _ in range(40):
                ready = sum(reachable(client, n["url"]) for n in registry["nodes"])
                if ready == len(registry["nodes"]):
                    break
                time.sleep(0.15)
        if ready != len(registry["nodes"]):
            raise RuntimeError(f"only {ready}/{len(registry['nodes'])} demo nodes started; check ports")
        print(f"Running {ready} independent loopback HTTP processes. Ctrl-C to stop.", flush=True)
        while True:
            if any(p.poll() is not None for p in procs):
                raise RuntimeError("a node process exited unexpectedly")
            time.sleep(0.5)
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()


def reachable(client, url):
    try:
        client.get(url + "/.well-known/innernet-node").raise_for_status()
        return True
    except httpx.HTTPError:
        return False


def main():
    parser = argparse.ArgumentParser(prog="innernet", description=f"INNERnet {RELEASE_VERSION} research pilot")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init-demo", help="create independent localhost storage node identities")
    init.add_argument("--dir", required=True)
    init.add_argument("--nodes", type=int, default=9)
    init.add_argument("--base-port", type=int, default=9400)
    run = sub.add_parser("demo-start", help="start demo's independent HTTP storage processes")
    run.add_argument("--dir", required=True)
    node = sub.add_parser("serve-node", help="serve one storage node; bind to loopback by default")
    node.add_argument("--dir", required=True)
    node.add_argument("--host", default="127.0.0.1")
    node.add_argument("--port", type=int, required=True)
    put = sub.add_parser("put", help="encrypt and disperse a file to independent nodes")
    put.add_argument("file")
    put.add_argument("--peers", required=True)
    put.add_argument("--writers", required=True)
    put.add_argument("--cap-out", required=True, help="NEW private file where read capability is saved")
    put.add_argument("--capability-version", type=int, choices=[2,3], default=3,
                     help="secure v3 is default; 2 is unsafe legacy and grants both")
    put.add_argument("--legacy-full-authority", action="store_true",
                     help="required acknowledgement when creating unsafe v2 objects")
    put.add_argument("--admin-out", help="REQUIRED with v3: separate NEW 0600 administrator secret file")
    put.add_argument("--k", type=int, default=4)
    put.add_argument("--n", type=int, default=6)
    put.add_argument("--chunk-bytes", type=int, default=1048576)
    put.add_argument("--require-diverse-domains", action="store_true", help="require operator-labelled distinct failure domains for all selected nodes")
    put.add_argument("--survive-one-domain", action="store_true", help="balance 4-of-6 data and 2-of-3 metadata across 3 declared failure domains")
    plan = sub.add_parser("plan-domains", help="offline preview of a three-domain survivable placement")
    plan.add_argument("--peers", required=True)
    writer = sub.add_parser("writer-add", help="privately save an SSH tunnel write endpoint and operator token")
    writer.add_argument("--writers", required=True)
    writer.add_argument("--id", required=True)
    writer.add_argument("--endpoint", required=True, help="e.g. http://127.0.0.1:19400 (SSH forwarded)")
    get = sub.add_parser("get", help="recover data with privately stored root capability")
    get.add_argument("--peers", required=True)
    get.add_argument("--cap-file", required=True)
    get.add_argument("--out", required=True)
    audit = sub.add_parser("audit-node", help="read-only verification of pinned public node identity, offer and sample")
    audit.add_argument("--url", required=True)
    audit.add_argument("--id", required=True)
    audit.add_argument("--public-key", required=True, help="independently pinned Ed25519 public key")
    audit.add_argument("--sample-sha256", help="optional publicly retrievable test fragment CID")
    peers = sub.add_parser("audit-peers", help="verify identity and signed offers for each configured public peer")
    peers.add_argument("--peers", required=True)
    topology = sub.add_parser("topology", help="offline peer domain report; never attests independence")
    topology.add_argument("--peers", required=True)
    https_sample = sub.add_parser("https-sample", help="read-only signed HTTPS node fragment download timing")
    https_sample.add_argument("--peers", required=True, help="public registry with pinned signing keys")
    https_sample.add_argument("--node", required=True, help="node ID present in public registry")
    https_sample.add_argument("--sha256", required=True, help="SHA256 of EXISTING public test fragment")
    https_sample.add_argument("--bytes", type=int, required=True, help="exact size of existing fragment")
    https_sample.add_argument("--samples", type=int, default=3)
    args = parser.parse_args()
    try:
        if args.command == "init-demo":
            create_demo(Path(args.dir), args.nodes, args.base_port)
        elif args.command == "demo-start":
            start_demo(Path(args.dir))
        elif args.command == "serve-node":
            # For external services, terminate TLS at a hardened reverse proxy.
            if args.host != "127.0.0.1" and args.host != "::1":
                raise ValueError("v0.2 pilot will only bind loopback; use a TLS reverse proxy")
            uvicorn.run(create_app(args.dir), host=args.host, port=args.port, log_level="warning")
        elif args.command == "plan-domains":
            from .placement import placement_summary
            registry = json.loads(Path(args.peers).read_text(encoding="utf-8"))
            nodes = {peer["id"]: peer for peer in registry["nodes"]}
            print(json.dumps(placement_summary(nodes), indent=2))
        elif args.command == "writer-add":
            from .network import _check_url, NODE_PATTERN
            import getpass
            endpoint = args.endpoint.rstrip("/")
            _check_url(endpoint)
            if not NODE_PATTERN.fullmatch(args.id):
                raise ValueError("invalid node id")
            path = Path(args.writers)
            if path.exists():
                if path.is_symlink():
                    raise ValueError("refusing to edit symlink as a secret file")
                if path.stat().st_mode & 0o077:
                    raise ValueError("writer file is group/world readable; chmod 600 first")
                saved = json.loads(path.read_text(encoding="utf-8"))
            else:
                saved = {"tokens": {}, "endpoints": {}}
            if (not isinstance(saved, dict) or not isinstance(saved.get("tokens"), dict)
                    or not isinstance(saved.get("endpoints", {}), dict)):
                raise ValueError("malformed writer file")
            key = getpass.getpass("Paste private node upload token (not shown): ")
            if len(key) < 24 or len(key) > 256:
                raise ValueError("upload token length is invalid")
            saved["tokens"][args.id] = key
            saved.setdefault("endpoints", {})[args.id] = endpoint
            data = (json.dumps(saved, sort_keys=True, indent=2) + "\n").encode()
            if path.exists():
                import tempfile
                fd, tmp_path = tempfile.mkstemp(prefix=".innernet-writers-", dir=path.parent)
                try:
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(data)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(tmp_path, path)
                finally:
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)
            else:
                private_write(path, data)
            print(json.dumps({"saved": str(path), "node": args.id,
                              "endpoint": endpoint, "token": "[redacted]"}, indent=2))
        elif args.command == "put":
            if args.capability_version == 2 and not args.legacy_full_authority:
                raise ValueError("legacy v2 requires --legacy-full-authority")
            if args.capability_version == 3 and args.legacy_full_authority:
                raise ValueError("legacy flag only applies to v2")
            if Path(args.cap_out).exists():
                raise FileExistsError("capability output exists; will not overwrite a secret")
            if args.capability_version == 3:
                if not args.admin_out or Path(args.admin_out).exists():
                    raise ValueError("v3 requires a new --admin-out path")
                if Path(args.admin_out).resolve() == Path(args.cap_out).resolve():
                    raise ValueError("administrator and reader secrets require different paths")
            elif args.admin_out:
                raise ValueError("--admin-out is only valid with v3")
            # Keys are minted INSIDE upload_file; no reusable key pair is
            # accepted. Persist both independently before any fragment PUT.
            def persist_capabilities(reader: str, admin: str) -> None:
                private_write(Path(args.admin_out), (admin + "\n").encode())
                private_write(Path(args.cap_out), (reader + "\n").encode())

            client = MeshClient(args.peers, args.writers)
            try:
                result = client.upload_file(args.file, k=args.k, n=args.n, chunk_bytes=args.chunk_bytes,
                                            require_diverse_domains=args.require_diverse_domains,
                                            survive_one_domain=args.survive_one_domain,
                                            capability_version=args.capability_version,
                                            persist_capabilities=(persist_capabilities if args.capability_version == 3 else None))
            finally:
                client.http.close()
            capability = result.pop("capability")
            administrator = result.pop("admin_capability", None)
            if args.capability_version == 2:
                private_write(Path(args.cap_out), (capability + "\n").encode())
            print(json.dumps({**result, "private_capability_file": args.cap_out,
                              "administrator_file": args.admin_out if administrator is not None else None}, indent=2))
        elif args.command == "audit-node":
            with httpx.Client(timeout=httpx.Timeout(8.0, connect=4.0), follow_redirects=False) as http:
                result = audit_node({"id": args.id, "url": args.url, "public_key": args.public_key},
                                    http, sample_sha256=args.sample_sha256)
                print(json.dumps(result, indent=2))
        elif args.command == "audit-peers":
            registry = json.loads(Path(args.peers).read_text(encoding="utf-8"))
            with httpx.Client(timeout=httpx.Timeout(8.0, connect=4.0), follow_redirects=False) as http:
                result = audit_registry(registry, http)
                print(json.dumps(result, indent=2))
                if result["failed"]:
                    parser.exit(2, f"audit failed for {result['failed']} nodes\n")
        elif args.command == "topology":
            print(json.dumps(topology_report(load_registry(args.peers)), indent=2))
        elif args.command == "https-sample":
            registry = load_registry(args.peers)
            choices = [node for node in registry["nodes"] if node["id"] == args.node]
            if len(choices) != 1:
                raise ValueError("HTTPS baseline node not found exactly once in pinned registry")
            with httpx.Client(timeout=httpx.Timeout(12.0, connect=4.0),
                              follow_redirects=False, trust_env=False) as http:
                print(json.dumps(https_sample_baseline(choices[0], http,
                      sample_sha256=args.sha256, expected_bytes=args.bytes,
                      samples=args.samples), indent=2))
        elif args.command == "get":
            cap = Path(args.cap_file).read_text(encoding="utf-8").strip()
            client = MeshClient(args.peers)
            try:
                print(json.dumps(client.restore_file(cap, args.out), indent=2))
            finally:
                client.http.close()
    except Exception as exc:
        parser.exit(2, f"error: {exc}\n")


if __name__ == "__main__":
    main()
