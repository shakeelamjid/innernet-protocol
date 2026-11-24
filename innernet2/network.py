"""INNERnet v0.2 interoperable HTTP pilot: independently hosted public shards.

For laboratory/developer use only. Excludes production contracts, DHT, anonymity,
node audits, intrusion prevention, key delegation and billing.
"""
from __future__ import annotations

import hashlib
import math
import copy
import json
import os
import re
import secrets
import tempfile
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import codec
from .profiler import OperationProfiler
from .crypto import (canonical, decrypt_chunk, decrypt_metadata, derive, digest,
                     encode_root, encrypt_chunk, encrypt_metadata, interleave, deinterleave,
                     new_root, parse_root, root_lookup, sign_directory, verify_directory,
                     new_v3_capabilities, parse_read_capability, v3_admin_sign)

PROTO = 2
DATA_CELL = 4096
INDEX_CELL = 64
INDEX_K = 2
INDEX_N = 3
MAX_CHUNK = 1024 * 1024
MAX_CHUNKS = 10000
MAX_META = 4 * 1024 * 1024
MAX_SHARD = 4 * 1024 * 1024
NODE_PATTERN = re.compile(r"^node-[a-z0-9-]{1,40}$")
HEX = re.compile(r"^[0-9a-f]{64}$")
TRANSIENT_HTTP = {408, 425, 429, 500, 502, 503, 504}
MAX_WORKERS = 9
PIPELINE_CHUNKS = 8  # Bounded ~8 MiB logical chunk window; no wire-format changes
DEFAULT_DISCOVERY_TTL = 10.0  # Per-client *verified* records; short-lived, optional.
MAX_CACHED_RECORDS = 32
FAILURE_COOLDOWN = 12.0  # Prioritize healthy alternatives after a proven failure.
RETRY_ATTEMPTS = 3
DOMAIN_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.-]{0,63}$")


class INNERnetError(Exception):
    """Protocol operation failed. A partial upload may require GC later."""


def _check_url(value: str) -> None:
    u = urlsplit(value)
    # No credentials or query parts; no remote HTTP with write secrets over cleartext.
    if u.username or u.password or u.query or u.fragment or u.path not in ("", "/"):
        raise ValueError("node URL may not contain credentials, query, or path")
    if u.scheme == "https" and u.hostname:
        return
    if u.scheme == "http" and u.hostname in {"127.0.0.1", "localhost", "::1"}:
        return
    raise ValueError("require HTTPS for remote nodes; HTTP is allowed only on loopback")


class MeshClient:
    def __init__(self, public_registry: str | Path | dict, writers: str | Path | dict | None = None,
                 http: httpx.Client | None = None, *, max_workers: int = 6,
                 retry_attempts: int = RETRY_ATTEMPTS, profile: bool = False,
                 discovery_ttl_seconds: float = DEFAULT_DISCOVERY_TTL):
        if isinstance(public_registry, (str, Path)):
            public_registry = json.loads(Path(public_registry).read_text(encoding="utf-8"))
        if isinstance(writers, (str, Path)):
            writers = json.loads(Path(writers).read_text(encoding="utf-8"))
        if not isinstance(public_registry, dict) or not isinstance(public_registry.get("nodes"), list):
            raise ValueError("invalid public node registry")
        self.nodes: dict[str, dict] = {}
        for node in public_registry["nodes"]:
            node_id, url, public_key = node["id"], node["url"], node["public_key"]
            if (not NODE_PATTERN.fullmatch(node_id) or node_id in self.nodes
                    or not isinstance(url, str) or not isinstance(public_key, str)
                    or len(bytes.fromhex(public_key)) != 32):
                raise ValueError("invalid registry entry")
            _check_url(url)
            failure_domain = node.get("failure_domain")
            if failure_domain is not None and (not isinstance(failure_domain, str)
                    or not DOMAIN_PATTERN.fullmatch(failure_domain)):
                raise ValueError("invalid failure_domain label")
            self.nodes[node_id] = {"id": node_id, "url": url.rstrip("/"), "public_key": public_key}
            if failure_domain is not None:
                self.nodes[node_id]["failure_domain"] = failure_domain
        if len(self.nodes) < 6:
            raise ValueError("pilot requires at least 6 independent node configurations")
        self.writers = (writers or {}).get("tokens", {})
        # Private, operator-configured tunnel endpoints are distinct from public read URLs.
        # Keep endpoints and upload tokens ONLY in the local, untracked writers file.
        self.write_endpoints = (writers or {}).get("endpoints", {})
        if not isinstance(self.writers, dict) or not isinstance(self.write_endpoints, dict):
            raise ValueError("invalid writers configuration")
        for node_id, address in self.write_endpoints.items():
            if node_id not in self.nodes or not isinstance(address, str):
                raise ValueError("private writer endpoint references an unknown node")
            _check_url(address)
        if type(max_workers) is not int or not 1 <= max_workers <= MAX_WORKERS:
            raise ValueError("max_workers must be between 1 and 9")
        if type(retry_attempts) is not int or not 1 <= retry_attempts <= 4:
            raise ValueError("retry_attempts must be between 1 and 4")
        if (isinstance(discovery_ttl_seconds, bool) or
                not isinstance(discovery_ttl_seconds, (int, float)) or
                not 0 <= discovery_ttl_seconds <= 60 or
                not math.isfinite(discovery_ttl_seconds)):
            raise ValueError("discovery_ttl_seconds must be finite, between 0 and 60")
        self.discovery_ttl_seconds = float(discovery_ttl_seconds)
        self._cache_lock = threading.Lock()
        self._verified_directory_cache: dict[str, tuple[float, dict]] = {}
        self._highest_sequences: dict[str, int] = {}
        self._unhealthy_until: dict[str, float] = {}
        self.profiler = OperationProfiler(profile)
        self.max_workers = max_workers
        self.retry_attempts = retry_attempts
        self._latency_lock = threading.Lock()
        self._verified_get_latency: dict[str, float] = {}
        self.http = http or httpx.Client(timeout=httpx.Timeout(7.0, connect=3.0),
                                         limits=httpx.Limits(max_connections=24,
                                                             max_keepalive_connections=18,
                                                             keepalive_expiry=30.0),
                                         follow_redirects=False, trust_env=False)

    def timing_report(self) -> dict:
        """Safe, aggregate synthetic-trial profiling report; contains no secrets."""
        return self.profiler.snapshot()

    def _with_retry(self, operation):
        """Retry bounded, idempotent requests only on transient transport/HTTP failures.

        Never retry invalid signatures, hashes, authorization failures, or 4xx
        except temporary 408/425/429. Do not print secrets or remote response data.
        """
        for attempt in range(self.retry_attempts):
            try:
                return operation()
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code not in TRANSIENT_HTTP or attempt + 1 == self.retry_attempts:
                    raise
            except httpx.RequestError:
                if attempt + 1 == self.retry_attempts:
                    raise
            time.sleep(min(0.08 * (2 ** attempt), 0.4))

    def _parallel_map(self, operation, values: list):
        """Preserve input order (critical: locator index is the erasure-code index)."""
        if len(values) < 2 or self.max_workers == 1:
            return [operation(v) for v in values]
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(values))) as pool:
            return list(pool.map(operation, values))

    def _parallel_directory(self, operation, values: list):
        """Query all signed directory replicas in a single bounded wave.

        Unlike shard operations, directory consistency needs responses from all
        configured peers so a slower valid, newer sequence is not ignored.
        """
        if len(values) < 2:
            return [operation(value) for value in values]
        with ThreadPoolExecutor(max_workers=min(len(values), MAX_WORKERS)) as pool:
            return list(pool.map(operation, values))

    def _primary_indices(self, locators: list[dict], k: int) -> list[int]:
        """Prefer previously fast *verified* nodes, without trusting node claims.

        When no measurements are available, preserve legacy primary shard order.
        Parity may be selected as a primary, but K distinct verified indices
        are always required. Authenticated data validity is never relaxed.
        """
        now = time.monotonic()
        with self._latency_lock:
            latency = dict(self._verified_get_latency)
            unhealthy = {node for node, until in self._unhealthy_until.items() if until > now}
        if not latency and not unhealthy:
            return list(range(k))
        # Never omit a shard: a degraded node remains eligible if there are
        # not enough healthier alternatives to form K independent shares.
        indices = sorted(range(len(locators)),
                         key=lambda i: (locators[i]["node"] in unhealthy,
                                        latency.get(locators[i]["node"], float("inf")), i))
        return sorted(indices[:k])

    def _url(self, node: str, endpoint: str) -> str:
        if node not in self.nodes or not endpoint.startswith("/"):
            raise ValueError("unknown node or endpoint")
        return self.nodes[node]["url"] + endpoint

    def _write_url(self, node: str, endpoint: str) -> str:
        if node not in self.nodes or not endpoint.startswith("/"):
            raise ValueError("unknown node or endpoint")
        return self.write_endpoints.get(node, self.nodes[node]["url"]).rstrip("/") + endpoint

    def _write_headers(self, node: str) -> dict:
        if node not in self.writers or not isinstance(self.writers[node], str):
            raise INNERnetError(f"no upload authorization configured for {node}")
        return {"X-Innernet-Write-Token": self.writers[node]}

    def put_fragment(self, node_id: str, data: bytes) -> dict:
        if len(data) > MAX_SHARD:
            raise ValueError("fragment too large")
        hash_value = digest(data)
        try:
            def upload():
                with self.http.stream("PUT", self._write_url(node_id, f"/v2/fragments/{hash_value}"),
                                      content=data, headers=self._write_headers(node_id)) as response:
                    response.raise_for_status()
                    payload = bytearray()
                    for part in response.iter_bytes(4096):
                        payload.extend(part)
                        if len(payload) > 16384:
                            raise ValueError("storage receipt exceeds maximum size")
                return json.loads(payload)

            with self.profiler.span("network.fragment_put"):
                receipt = self._with_retry(upload)
            sign = bytes.fromhex(receipt["signature"])
            unsigned = dict(receipt)
            del unsigned["signature"]
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.nodes[node_id]["public_key"]))
            pub.verify(sign, canonical(unsigned))
            if (receipt["node_id"] != node_id or receipt["digest"] != hash_value
                    or type(receipt["bytes"]) is not int or receipt["bytes"] != len(data)):
                raise ValueError("invalid storage receipt")
        except Exception as exc:
            # A failed PUT can have reached its destination: no automatic rollback.
            raise INNERnetError(f"fragment upload failed on {node_id}: {type(exc).__name__}") from exc
        return {"node": node_id, "sha256": hash_value, "bytes": len(data)}

    def get_fragment(self, loc: dict) -> bytes:
        node_id, hash_value = loc["node"], loc["sha256"]
        expected = loc["bytes"]
        if (node_id not in self.nodes or not isinstance(hash_value, str) or not HEX.fullmatch(hash_value)
                or type(expected) is not int or not 0 <= expected <= MAX_SHARD):
            raise ValueError("invalid fragment locator")

        def download():
            with self.http.stream("GET", self._url(node_id, f"/v2/fragments/{hash_value}")) as res:
                res.raise_for_status()
                data = bytearray()
                for part in res.iter_bytes(65536):
                    data.extend(part)
                    if len(data) > expected:
                        raise ValueError("oversized fragment")
            if len(data) != expected or digest(data) != hash_value:
                raise ValueError("fragment hash/length mismatch")
            return bytes(data)

        start = time.monotonic()
        try:
            with self.profiler.span("network.fragment_get"):
                verified = self._with_retry(download)
        except (httpx.HTTPError, ValueError) as exc:
            # In-memory, temporary scheduling penalty only. Authentication and
            # content validation are NEVER skipped; failures still propagate.
            with self._latency_lock:
                self._unhealthy_until[node_id] = time.monotonic() + FAILURE_COOLDOWN
            raise
        elapsed = time.monotonic() - start
        with self._latency_lock:
            self._unhealthy_until.pop(node_id, None)
            previous = self._verified_get_latency.get(node_id)
            self._verified_get_latency[node_id] = (elapsed if previous is None else
                                                   0.70 * previous + 0.30 * elapsed)
        return verified

    def _recover(self, locators: list[dict], k: int, n: int, mixed_length: int) -> bytes:
        shares: dict[int, bytes] = {}

        def fetch(pair):
            index, locator = pair
            try:
                return index, self.get_fragment(locator)
            except (httpx.HTTPError, ValueError, KeyError, OSError):
                return index, None

        # Fetch only K initially to avoid unnecessary bandwidth. If any fail,
        # query additional parity nodes in one bounded concurrent fallback wave.
        primary = self._primary_indices(locators, k)
        remaining = [index for index in range(n) if index not in primary]
        for batch in ([(index, locators[index]) for index in primary],
                      [(index, locators[index]) for index in remaining]):
            if not batch:
                continue
            for index, fragment in self._parallel_map(fetch, batch):
                if fragment is not None:
                    shares[index] = fragment
            if len(shares) >= k:
                break
        if len(shares) < k:
            raise INNERnetError(f"not enough valid fragments: {len(shares)} of {k} required")
        with self.profiler.span("codec.decode"):
            return codec.decode(shares, k, n, mixed_length)

    def _recover_many(self, requests: list[tuple[list[dict], int, int, int]]) -> list[bytes]:
        """Recover a bounded set of chunks with a shared, worker-limited GET queue.

        K authenticated fragments are attempted per chunk first. Only chunks
        missing enough valid shares fetch parity in one extra bounded wave.
        Returned plaintext order is identical to manifest chunk order.
        """
        if len(requests) > PIPELINE_CHUNKS:
            raise ValueError("recovery window exceeds safe bound")
        shares: list[dict[int, bytes]] = [{} for _ in requests]

        def fetch(job):
            chunk_index, shard_index, locator = job
            try:
                return chunk_index, shard_index, self.get_fragment(locator)
            except (httpx.HTTPError, ValueError, KeyError, OSError):
                return chunk_index, shard_index, None

        primaries = [self._primary_indices(locators, k)
                     for locators, k, n, mixed_len in requests]
        primary = [(j, index, locators[index])
                   for j, (locators, k, n, mixed_len) in enumerate(requests)
                   for index in primaries[j]]
        with self.profiler.span("read.primary_wave"):
            for j, index, data in self._parallel_map(fetch, primary):
                if data is not None:
                    shares[j][index] = data
        parity = [(j, index, locators[index])
                  for j, (locators, k, n, mixed_len) in enumerate(requests)
                  if len(shares[j]) < k for index in range(n)
                  if index not in primaries[j]]
        if parity:
            with self.profiler.span("read.parity_wave"):
                for j, index, data in self._parallel_map(fetch, parity):
                    if data is not None:
                        shares[j][index] = data
        reconstructed = []
        for j, (locators, k, n, mixed_len) in enumerate(requests):
            if len(shares[j]) < k:
                raise INNERnetError(f"not enough valid fragments: {len(shares[j])} of {k} required")
            with self.profiler.span("codec.decode"):
                reconstructed.append(codec.decode(shares[j], k, n, mixed_len))
        return reconstructed

    def publish_record(self, root: bytes, entry: dict, *, read_capability: str | None = None,
                       admin_capability: str | None = None) -> int:
        if read_capability is not None:
            if admin_capability is None:
                raise ValueError("version 3 publishing requires independent administrator authority")
            parsed_root, lookup, is_v3 = parse_read_capability(read_capability)
            if not is_v3 or parsed_root != root:
                raise ValueError("incorrect version 3 read capability")
            record = v3_admin_sign(admin_capability, entry, read_capability)
        else:
            if admin_capability is not None:
                raise ValueError("administrator key given without v3 reader")
            lookup = root_lookup(root)
            record = sign_directory(root, entry)

        def publish(node_id):
            try:
                def put():
                    r = self.http.put(self._write_url(node_id, f"/v2/records/{lookup}"),
                                      json=record, headers=self._write_headers(node_id))
                    r.raise_for_status()
                self._with_retry(put)
                return True
            except httpx.HTTPError:
                return False

        nodes = [node_id for node_id in self.nodes if node_id in self.writers]
        with self.profiler.span("network.discovery_publish"):
            successes = sum(self._parallel_directory(publish, nodes))
        if successes < 3:
            raise INNERnetError(f"root discovery replicated to only {successes} nodes; need 3")
        # Updating directory replicas invalidates stale session-local records.
        with self._cache_lock:
            self._verified_directory_cache.pop(lookup, None)
        return successes

    def resolve(self, root: bytes, *, fresh: bool = False, lookup_override: str | None = None) -> dict:
        """Fetch a signed root record, optionally using short-lived verified cache.

        Cached records may be stale for at most the configured TTL. Operators
        performing maintenance should use fresh=True. Cache misses always
        verify ALL peer responses, including the newest available sequence.
        Cache is private, in-memory and never includes upload credentials.
        """
        lookup = lookup_override if lookup_override is not None else root_lookup(root)
        if not fresh and self.discovery_ttl_seconds:
            with self._cache_lock:
                cached = self._verified_directory_cache.get(lookup)
                if cached and cached[0] > time.monotonic():
                    with self.profiler.span("network.discovery_cache_hit"):
                        return copy.deepcopy(cached[1])

        def query(node_id):
            try:
                def read():
                    # Stream with a hard size limit: an untrusted node must not
                    # force allocation of an unbounded response body.
                    with self.http.stream("GET", self._url(node_id, f"/v2/records/{lookup}")) as r:
                        if r.status_code == 404:
                            return None
                        r.raise_for_status()
                        buffer = bytearray()
                        for part in r.iter_bytes(8192):
                            buffer.extend(part)
                            if len(buffer) > 65536:
                                return None
                    return json.loads(buffer)

                obj = self._with_retry(read)
                if obj is not None and verify_directory(lookup, obj) and self._validate_index(obj):
                    return obj
            except (httpx.HTTPError, ValueError, TypeError, KeyError):
                pass
            return None

        with self.profiler.span("network.discovery_resolve"):
            candidates = [v for v in self._parallel_directory(query, list(self.nodes)) if v is not None]
        if not candidates:
            raise INNERnetError("no authentic root discovery record is available")
        chosen = max(candidates, key=lambda v: v["sequence"])
        with self._cache_lock:
            previous = self._highest_sequences.get(lookup, -1)
            if chosen["sequence"] < previous:
                # A newly fetched signed record can still be a rollback if
                # replicas are stale. Reject it rather than silently using it.
                raise INNERnetError("signed discovery record sequence regressed during this client session")
            self._highest_sequences[lookup] = chosen["sequence"]
            if self.discovery_ttl_seconds:
                if len(self._verified_directory_cache) >= MAX_CACHED_RECORDS:
                    self._verified_directory_cache.pop(next(iter(self._verified_directory_cache)))
                self._verified_directory_cache[lookup] = (
                    time.monotonic() + self.discovery_ttl_seconds, copy.deepcopy(chosen))
        # This does NOT prevent rollback at initial lookup or between clients.
        return copy.deepcopy(chosen)

    def _validate_locs(self, locs: Any, n: int):
        if not isinstance(locs, list) or len(locs) != n:
            raise ValueError("invalid locator count")
        seen = set()
        for loc in locs:
            if not isinstance(loc, dict) or loc.get("node") not in self.nodes or loc["node"] in seen:
                raise ValueError("invalid or repeated storage node")
            seen.add(loc["node"])
            if not isinstance(loc.get("sha256"), str) or not HEX.fullmatch(loc["sha256"]):
                raise ValueError("malformed fragment hash")
            if type(loc.get("bytes")) is not int or not 0 <= loc["bytes"] <= MAX_SHARD:
                raise ValueError("invalid fragment size")

    def _validate_index(self, record: dict) -> bool:
        try:
            if (record["protocol_version"] != PROTO or type(record["sequence"]) is not int
                    or not 0 <= record["sequence"] < 2**32 or record["index_cell"] != INDEX_CELL
                    or record["index_k"] != INDEX_K or record["index_n"] != INDEX_N
                    or type(record["cipher_length"]) is not int
                    or not 16 <= record["cipher_length"] <= MAX_META):
                return False
            self._validate_locs(record["fragments"], INDEX_N)
            return True
        except (TypeError, KeyError, ValueError):
            return False

    def upload_file(self, path: str | Path, k: int = 4, n: int = 6,
                    chunk_bytes: int = MAX_CHUNK, *, require_diverse_domains: bool = False,
                    survive_one_domain: bool = False, capability_version: int = 3,
                    persist_capabilities: Callable[[str, str], None] | None = None) -> dict:
        path = Path(path)
        if not 2 <= k <= n <= 12 or len(self.nodes) < n + INDEX_N:
            raise ValueError("need k<=n data nodes and 3 separate metadata nodes")
        if chunk_bytes < 4096 or chunk_bytes > MAX_CHUNK or chunk_bytes % DATA_CELL:
            raise ValueError("chunk size must be a 4096-byte multiple, <=1 MiB")
        # Fail before creating remote shards if metadata can never fit.
        # Actual signed metadata size is validated again before publishing.
        estimated_chunks = (path.stat().st_size + chunk_bytes - 1) // chunk_bytes
        if estimated_chunks > MAX_CHUNKS:
            raise INNERnetError("maximum number of chunks exceeded")
        if estimated_chunks * (n * 220 + 80) > MAX_META:
            raise INNERnetError("estimated metadata exceeds capacity; increase chunk size")
        if capability_version not in (2, 3) or type(capability_version) is not int:
            raise ValueError("capability_version must be 2 or 3")
        if persist_capabilities is not None and not callable(persist_capabilities):
            raise TypeError("persist_capabilities must be a callable")
        if capability_version != 3 and persist_capabilities is not None:
            raise ValueError("capability persistence callback requires v3")
        # Optional placement to tolerate the outage of ONE complete declared site.
        # Requires 3 domains with 3 storage nodes each, 4-of-6 data and 2-of-3 metadata.
        # These labels are operator assertions, not independently verified ownership.
        if survive_one_domain:
            if require_diverse_domains:
                raise ValueError("choose at most one placement policy")
            from .placement import plan_one_domain_outage
            data_nodes, metadata_nodes = plan_one_domain_outage(self.nodes, k=k, n=n)
        elif require_diverse_domains:
            domains = {}
            for node_id, entry in self.nodes.items():
                domain = entry.get("failure_domain")
                if domain is not None:
                    domains.setdefault(domain, []).append(node_id)
            if len(domains) < n + INDEX_N:
                raise INNERnetError(f"need {n + INDEX_N} distinct declared failure domains, "
                                    f"only {len(domains)} provided")
            rng = secrets.SystemRandom()
            selected_domains = rng.sample(list(domains), n + INDEX_N)
            selected = [rng.choice(domains[domain]) for domain in selected_domains]
            data_nodes, metadata_nodes = selected[:n], selected[n:]
        elif not survive_one_domain:
            selected = secrets.SystemRandom().sample(list(self.nodes), n + INDEX_N)
            data_nodes, metadata_nodes = selected[:n], selected[n:]
        # All local placement checks have passed. Generate and durably persist
        # a fresh single-object root immediately before remote writes begin.
        # The HTTP-v3 on-wire AEAD format is NOT misuse-resistant to root reuse.
        if capability_version == 3:
            read_capability, administrator_capability = new_v3_capabilities()
            root, _, _ = parse_read_capability(read_capability)
            if persist_capabilities is not None:
                persist_capabilities(read_capability, administrator_capability)
        else:
            read_capability = administrator_capability = None
            root = new_root()
        object_id = secrets.token_bytes(16)
        chunks = []
        physical_fragment_bytes = 0
        hash_file = hashlib.sha256()
        total = 0
        pending: list[tuple[int, list[bytes]]] = []

        def flush_pending():
            nonlocal physical_fragment_bytes
            if not pending:
                return
            # Multiple chunks share the same bounded worker queue. The order
            # of PUT receipts remains chunk index, then shard index.
            jobs = [(index, shard_index, data_nodes[(shard_index + index) % n], shard)
                    for index, shards in pending for shard_index, shard in enumerate(shards)]
            with self.profiler.span("upload.fragment_wave"):
                receipts = self._parallel_map(lambda job: self.put_fragment(job[2], job[3]), jobs)
            position = 0
            for _, shards in pending:
                locators = receipts[position:position + len(shards)]
                physical_fragment_bytes += sum(loc["bytes"] for loc in locators)
                chunks.append({"fragments": locators})
                position += len(shards)
            pending.clear()

        with path.open("rb") as stream:
            while block := stream.read(chunk_bytes):
                index = len(chunks) + len(pending)
                if index >= MAX_CHUNKS:
                    raise INNERnetError("maximum number of chunks exceeded")
                hash_file.update(block)
                total += len(block)
                with self.profiler.span("crypto.chunk_encrypt"):
                    ciphertext = encrypt_chunk(root, object_id, index, block)
                with self.profiler.span("crypto.chunk_interleave"):
                    mixed = interleave(ciphertext, derive(root, f"data/interleave/{index}"), DATA_CELL)
                with self.profiler.span("codec.encode"):
                    shards = codec.encode(mixed, k, n)
                pending.append((index, shards))
                if len(pending) >= PIPELINE_CHUNKS:
                    flush_pending()
            flush_pending()
        manifest = {"protocol_version": PROTO, "object_id": object_id.hex(),
                    "filename": path.name, "total_bytes": total,
                    "plaintext_sha256": hash_file.hexdigest(), "chunk_bytes": chunk_bytes,
                    "data_cell": DATA_CELL, "k": k, "n": n, "chunks": chunks}
        with self.profiler.span("crypto.metadata_encrypt"):
            index_cipher = encrypt_metadata(root, manifest, 0)
        if len(index_cipher) > MAX_META:
            raise INNERnetError("encrypted manifest exceeds v0.2 size limit")
        with self.profiler.span("crypto.metadata_interleave"):
            index_mixed = interleave(index_cipher, derive(root, "metadata/interleave/0"), INDEX_CELL)
        with self.profiler.span("codec.encode"):
            index_shards = codec.encode(index_mixed, INDEX_K, INDEX_N)
        with self.profiler.span("upload.metadata_wave"):
            metadata_locs = self._parallel_map(
                lambda pair: self.put_fragment(pair[0], pair[1]),
                list(zip(metadata_nodes, index_shards)))
        record = {"protocol_version": PROTO, "sequence": 0,
                  "cipher_length": len(index_cipher), "index_k": INDEX_K,
                  "index_n": INDEX_N, "index_cell": INDEX_CELL, "fragments": metadata_locs}
        replicas = self.publish_record(root, record,
                                       read_capability=read_capability,
                                       admin_capability=administrator_capability)
        physical_fragment_bytes += sum(loc["bytes"] for loc in metadata_locs)
        result = {"capability": read_capability or encode_root(root), "bytes": total, "chunks": len(chunks),
                "physical_fragment_bytes": physical_fragment_bytes,
                "physical_overhead_ratio": round(physical_fragment_bytes / max(total, 1), 3),
                "data_shards": len(chunks) * n, "metadata_shards": INDEX_N,
                "discovery_replicas": replicas}
        if capability_version == 3:
            # Caller MUST secure this separate administrator token independently.
            result["admin_capability"] = administrator_capability
        return result

    def _validate_manifest(self, m: dict):
        if (m.get("protocol_version") != PROTO or not isinstance(m.get("object_id"), str)
                or not re.fullmatch(r"[0-9a-f]{32}", m["object_id"])
                or type(m.get("total_bytes")) is not int or not 0 <= m["total_bytes"] <= MAX_CHUNKS * MAX_CHUNK
                or type(m.get("chunk_bytes")) is not int
                or not 4096 <= m["chunk_bytes"] <= MAX_CHUNK or m["chunk_bytes"] % DATA_CELL
                or m.get("data_cell") != DATA_CELL
                or type(m.get("k")) is not int or type(m.get("n")) is not int
                or not 2 <= m["k"] <= m["n"] <= 12
                or not isinstance(m.get("filename"), str) or len(m["filename"]) > 255
                or not isinstance(m.get("plaintext_sha256"), str) or not HEX.fullmatch(m["plaintext_sha256"])):
            raise ValueError("malformed authenticated file metadata")
        length = (m["total_bytes"] + m["chunk_bytes"] - 1) // m["chunk_bytes"]
        if not isinstance(m.get("chunks"), list) or length != len(m["chunks"]) or length > MAX_CHUNKS:
            raise ValueError("invalid chunk count")
        for chunk in m["chunks"]:
            self._validate_locs(chunk["fragments"], m["n"])

    def inspect_file(self, capability: str) -> dict:
        """Read-only fragment inventory for one private capability (no writes).

        Full GET plus SHA-256 is required: a 200 response alone cannot prove
        retention. Network/HTTP failures are reported as uncertain, not missing.
        """
        root, lookup, _ = parse_read_capability(capability)
        entry = self.resolve(root, fresh=True, lookup_override=lookup)
        cipher_len = entry["cipher_length"]
        index_length = ((cipher_len + INDEX_CELL - 1) // INDEX_CELL) * INDEX_CELL
        index_mixed = self._recover(entry["fragments"], INDEX_K, INDEX_N, index_length)
        meta_cipher = deinterleave(index_mixed, derive(root, f"metadata/interleave/{entry['sequence']}"),
                                   INDEX_CELL, cipher_len)
        manifest = decrypt_metadata(root, meta_cipher, entry["sequence"])
        self._validate_manifest(manifest)
        all_locs = [("metadata", loc) for loc in entry["fragments"]]
        for chunk in manifest["chunks"]:
            all_locs.extend(("data", loc) for loc in chunk["fragments"])

        def inspect(pair):
            kind, locator = pair
            try:
                self.get_fragment(locator)
                return kind, "verified"
            except httpx.HTTPStatusError as exc:
                return kind, "missing" if exc.response.status_code == 404 else "unavailable"
            except (httpx.RequestError, OSError):
                return kind, "unavailable"
            except ValueError:
                return kind, "corrupt"

        totals = {"verified": 0, "missing": 0, "unavailable": 0, "corrupt": 0}
        metadata = dict.fromkeys(totals, 0)
        for kind, status in self._parallel_map(inspect, all_locs):
            totals[status] += 1
            if kind == "metadata":
                metadata[status] += 1
        return {"total_shards": len(all_locs), "shard_status": totals,
                "metadata_shard_status": metadata,
                "chunks": len(manifest["chunks"]),
                "caution": "Full verified downloads; summary does not guarantee per-chunk K-of-N or future retention."}

    def repair_file(self, capability: str, *, admin_capability: str | None = None) -> dict:
        """Operator-authorized *same-node* repair after previously missing nodes return.

        Reconstructs ciphertext shards from K valid shares and re-uploads the
        exact content hash to its original node. Does not move data to other
        providers, replace a corrupt existing file, or promise autonomous repair.
        """
        root, lookup, is_v3 = parse_read_capability(capability)
        # Authorization must be established before any HTTP read or shard write.
        if is_v3:
            if admin_capability is None:
                raise INNERnetError("v3 repair requires separate administrator capability before I/O")
            try:
                v3_admin_sign(admin_capability,{"sequence":0},capability)
            except ValueError as exc:
                raise INNERnetError("administrator capability does not match v3 reader") from exc
        if not self.writers:
            raise INNERnetError("repair requires separately authorized storage writer credentials")
        entry = self.resolve(root, fresh=True, lookup_override=lookup)
        cipher_len = entry["cipher_length"]
        index_length = ((cipher_len + INDEX_CELL - 1) // INDEX_CELL) * INDEX_CELL
        index_mixed = self._recover(entry["fragments"], INDEX_K, INDEX_N, index_length)
        meta_cipher = deinterleave(index_mixed, derive(root, f"metadata/interleave/{entry['sequence']}"),
                                   INDEX_CELL, cipher_len)
        manifest = decrypt_metadata(root, meta_cipher, entry["sequence"])
        self._validate_manifest(manifest)
        repaired = 0
        already_valid = 0
        metadata_fixed = 0

        def repair_shards(locators, shards, *, is_metadata=False):
            nonlocal repaired, already_valid, metadata_fixed
            for index, (locator, shard) in enumerate(zip(locators, shards)):
                if digest(shard) != locator["sha256"] or len(shard) != locator["bytes"]:
                    raise INNERnetError("regenerated shard does not match authenticated locator")
                try:
                    self.get_fragment(locator)
                    already_valid += 1
                    continue
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code != 404:
                        raise INNERnetError("cannot safely repair: node returned a non-404 HTTP error") from exc
                except (httpx.RequestError, ValueError, OSError) as exc:
                    raise INNERnetError("cannot safely repair: node unreachable or fragment failed integrity") from exc
                if locator["node"] not in self.writers:
                    raise INNERnetError(f"missing writer credential for {locator['node']}; cannot repair")
                self.put_fragment(locator["node"], shard)
                repaired += 1
                if is_metadata:
                    metadata_fixed += 1

        repair_shards(entry["fragments"], codec.encode(index_mixed, INDEX_K, INDEX_N), is_metadata=True)
        total = 0
        for index, chunk in enumerate(manifest["chunks"]):
            plain_len = min(manifest["chunk_bytes"], manifest["total_bytes"] - total)
            ciphertext_len = plain_len + 16
            mixed_length = ((ciphertext_len + DATA_CELL - 1) // DATA_CELL) * DATA_CELL
            mixed = self._recover(chunk["fragments"], manifest["k"], manifest["n"], mixed_length)
            repair_shards(chunk["fragments"], codec.encode(mixed, manifest["k"], manifest["n"]))
            total += plain_len
        if total != manifest["total_bytes"]:
            raise INNERnetError("unexpected manifest size during repair")
        replicas = self.publish_record(root, entry,
                                       read_capability=capability if capability.startswith("inn3_") else None,
                                       admin_capability=admin_capability)
        return {"repaired_shards": repaired, "metadata_repaired": metadata_fixed,
                "already_valid_shards": already_valid, "root_record_replicas": replicas,
                "note": "Same-node repair only; cannot heal offline nodes or corrupt files requiring operator deletion."}

    def restore_file(self, capability: str, destination: str | Path) -> dict:
        root, lookup, _ = parse_read_capability(capability)
        entry = self.resolve(root, lookup_override=lookup)
        cipher_len = entry["cipher_length"]
        mixed_len = ((cipher_len + INDEX_CELL - 1) // INDEX_CELL) * INDEX_CELL
        mixed = self._recover(entry["fragments"], INDEX_K, INDEX_N, mixed_len)
        with self.profiler.span("crypto.metadata_deinterleave"):
            meta_cipher = deinterleave(mixed, derive(root, f"metadata/interleave/{entry['sequence']}"), INDEX_CELL, cipher_len)
        with self.profiler.span("crypto.metadata_decrypt"):
            manifest = decrypt_metadata(root, meta_cipher, entry["sequence"])
        self._validate_manifest(manifest)
        object_id = bytes.fromhex(manifest["object_id"])
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() or target.is_symlink():
            raise INNERnetError("refusing to overwrite existing destination")
        temp_name = None
        try:
            fd, temp_name = tempfile.mkstemp(prefix=".innernet-restore-", dir=target.parent)
            digest_file = hashlib.sha256()
            total = 0
            with os.fdopen(fd, "wb") as f:
                for start_index in range(0, len(manifest["chunks"]), PIPELINE_CHUNKS):
                    batch = manifest["chunks"][start_index:start_index + PIPELINE_CHUNKS]
                    requests = []
                    for offset, item in enumerate(batch):
                        index = start_index + offset
                        plain_len = min(manifest["chunk_bytes"],
                                        manifest["total_bytes"] - index * manifest["chunk_bytes"])
                        cipher_size = plain_len + 16
                        mix_len = ((cipher_size + DATA_CELL - 1) // DATA_CELL) * DATA_CELL
                        requests.append((item["fragments"], manifest["k"], manifest["n"], mix_len))
                    mixed_blocks = self._recover_many(requests)
                    for offset, mix in enumerate(mixed_blocks):
                        index = start_index + offset
                        plain_len = min(manifest["chunk_bytes"], manifest["total_bytes"] - total)
                        cipher_size = plain_len + 16
                        with self.profiler.span("crypto.chunk_deinterleave"):
                            cipher = deinterleave(mix, derive(root, f"data/interleave/{index}"), DATA_CELL, cipher_size)
                        with self.profiler.span("crypto.chunk_decrypt"):
                            plain = decrypt_chunk(root, object_id, index, cipher, plain_len)
                        digest_file.update(plain)
                        f.write(plain)
                        total += len(plain)
                with self.profiler.span("disk.restore_sync"):
                    f.flush()
                    os.fsync(f.fileno())
            if total != manifest["total_bytes"] or digest_file.hexdigest() != manifest["plaintext_sha256"]:
                raise INNERnetError("file integrity verification failed")
            try:
                os.link(temp_name, target, follow_symlinks=False)
            except FileExistsError as exc:
                raise INNERnetError("destination appeared during restore") from exc
            folder = os.open(target.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
            try: os.fsync(folder)
            finally: os.close(folder)
            os.unlink(temp_name)
            temp_name = None
            return {"filename": manifest["filename"], "bytes": total,
                    "chunks": len(manifest["chunks"])}
        finally:
            if temp_name and os.path.exists(temp_name):
                os.unlink(temp_name)
