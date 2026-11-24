"""Read-only signed-capacity monitoring and untrusted topology assessment.

A peer's signed offer is an *assertion*, not a disk measurement or retention proof.
A failure-domain label is also operator-asserted; it cannot attest independence.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from .audit import audit_registry, validate_registry_entry


def capacity_report(registry: dict, client: httpx.Client, *, warn_at: float = 0.85,
                    now: int | None = None) -> dict:
    """Validate all signed offers, report per-node usage and unknown/failed nodes.

    Deliberately DO NOT sum advertised capacity: all nodes can share a disk.
    """
    if not 0.1 <= warn_at < 1.0:
        raise ValueError("warn_at must be between 0.1 and 1.0 (exclusive upper)")
    audit = audit_registry(registry, client, now=now)
    nodes = []
    for item in audit["nodes"]:
        if not item["ok"]:
            nodes.append({"node_id": item.get("node_id"), "status": "unavailable-or-untrusted",
                          "reason": item["reason"]})
            continue
        capacity, available = item["capacity_bytes_reported"], item["available_bytes_reported"]
        used = capacity - available
        ratio = used / capacity if capacity else None
        status = "unknown-capacity" if ratio is None else "warning" if ratio >= warn_at else "ok"
        nodes.append({"node_id": item["node_id"], "status": status,
                      "advertised_capacity_bytes": capacity,
                      "advertised_available_bytes": available,
                      "advertised_used_bytes": used,
                      "advertised_utilization_pct": round(ratio * 100, 1) if ratio is not None else None,
                      "offer_expires_at_unix": item["offer_expires_at_unix"]})
    return {"verified": audit["passed"], "failed": audit["failed"],
            "warn_at_percent": round(warn_at * 100, 1), "nodes": nodes,
            "note": "Self-reported signed logical quotas; NOT physical disk free, retention proof, "
                    "or independently attestable provider capacity. Do not sum across nodes on one VPS."}


def topology_report(registry: dict) -> dict:
    """Offline, no-network sanity check for pre-enrollment multi-operator registries."""
    if not isinstance(registry, dict) or not isinstance(registry.get("nodes"), list):
        raise ValueError("registry must contain a nodes list")
    entries = [validate_registry_entry(item) for item in registry["nodes"]]
    if not entries or len(entries) > 256:
        raise ValueError("registry must contain 1 to 256 nodes")
    ids, keys, urls = set(), set(), set()
    hosts, domains = Counter(), Counter()
    simulated = False
    for e in entries:
        if e["id"] in ids or e["public_key"] in keys or e["url"] in urls:
            raise ValueError("registry contains duplicate ID, public key or URL")
        ids.add(e["id"])
        keys.add(e["public_key"])
        urls.add(e["url"])
        hosts[urlsplit(e["url"]).hostname] += 1
        if "failure_domain" in e:
            domains[e["failure_domain"]] += 1
            simulated |= "simulat" in e["failure_domain"].lower()
    ready = sum(count >= 3 for count in domains.values()) >= 3
    return {"nodes": len(entries), "distinct_advertised_hostnames": len(hosts),
            "declared_failure_domains": dict(sorted(domains.items())),
            "repeated_hostnames": sorted(h for h, n in hosts.items() if n > 1),
            "simulated_domain_labels_detected": simulated,
            "one_declared_domain_outage_profile_placeable": ready,
            "independent_infrastructure_verified": False,
            "notes": ["Hostnames and domain labels are self-reported and may share a host, owner or disk.",
                      "Placement eligibility is not a redundancy or disaster-recovery guarantee."]}


def load_registry(path: str | Path) -> dict:
    file = Path(path).expanduser()
    if file.is_symlink() or file.stat().st_size > 256 * 1024:
        raise ValueError("registry must be a non-symlink JSON file <= 256 KiB")
    return json.loads(file.read_text(encoding="utf-8"))


def https_sample_baseline(entry: dict, client: httpx.Client, *, sample_sha256: str,
                          expected_bytes: int, samples: int = 3) -> dict:
    """Read-only transport timing of a pinned HTTPS node, no storage writes.

    The sample must already exist on the node. It can be compared only against
    the same node/path/network setup, not equated with full mesh upload/restore.
    """
    import hashlib
    import re
    import time
    from .audit import audit_node
    from .network import MAX_SHARD

    entry = validate_registry_entry(entry)
    if urlsplit(entry["url"]).scheme != "https":
        raise ValueError("HTTPS sample baseline requires an HTTPS peer URL")
    if not isinstance(sample_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", sample_sha256):
        raise ValueError("invalid sample sha256")
    if type(expected_bytes) is not int or not 1 <= expected_bytes <= MAX_SHARD:
        raise ValueError("expected sample must be 1 to 4 MiB")
    if type(samples) is not int or not 1 <= samples <= 10:
        raise ValueError("samples must be 1 to 10")
    # Verify both identity and a fresh signed offer before timing transfers.
    audit_node(entry, client)
    times_ms = []
    for _ in range(samples):
        digest = hashlib.sha256()
        total = 0
        start = time.monotonic()
        with client.stream("GET", entry["url"] + "/v2/fragments/" + sample_sha256,
                           headers={"Cache-Control": "no-cache"}) as response:
            response.raise_for_status()
            for chunk in response.iter_bytes(65536):
                total += len(chunk)
                if total > expected_bytes:
                    raise ValueError("HTTPS sample exceeded expected size")
                digest.update(chunk)
        elapsed = (time.monotonic() - start) * 1000
        if total != expected_bytes or digest.hexdigest() != sample_sha256:
            raise ValueError("HTTPS sample failed length/SHA256 verification")
        times_ms.append(round(elapsed, 3))
    return {"status": "PASS", "node_id": entry["id"], "sample_bytes": expected_bytes,
            "samples": samples, "download_ms": times_ms,
            "sha256_verified_each_time": True,
            "note": "Read-only direct HTTPS sample; not comparable to a full mesh file upload, "
                    "not a same-node controlled experiment unless test conditions match."}
