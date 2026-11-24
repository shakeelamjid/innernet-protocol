"""Conservative placement planner for a *three-failure-domain* research mesh.

This does not attest the operators' claimed domains. Every three-node group should
be hosted on separate independent infrastructure; a group can be fully offline.
"""
from __future__ import annotations

import secrets
from collections import defaultdict


class PlacementError(ValueError):
    pass


def plan_one_domain_outage(nodes: dict[str, dict], *, k: int = 4,
                           n: int = 6) -> tuple[list[str], list[str]]:
    """Choose 2 data + 1 metadata node in each of three distinct domains.

    Losing one declared domain leaves 4/6 data and 2/3 metadata shares.
    This is intentionally limited to the standard 4-of-6 / 2-of-3 profile.
    """
    if (k, n) != (4, 6):
        raise PlacementError("one-domain-outage profile requires 4-of-6 data and 2-of-3 metadata")
    by_domain: dict[str, list[str]] = defaultdict(list)
    for node_id, entry in nodes.items():
        label = entry.get("failure_domain")
        if label:
            by_domain[label].append(node_id)
    candidates = [name for name, pool in by_domain.items() if len(pool) >= 3]
    if len(candidates) < 3:
        raise PlacementError("requires 3 distinct declared domains with at least 3 nodes each")
    rng = secrets.SystemRandom()
    chosen = rng.sample(candidates, 3)
    data, metadata = [], []
    for label in chosen:
        selected = rng.sample(by_domain[label], 3)
        data.extend(selected[:2])
        metadata.append(selected[2])
    rng.shuffle(data)
    rng.shuffle(metadata)
    return data, metadata


def placement_summary(nodes: dict[str, dict], *, k: int = 4, n: int = 6) -> dict:
    data, metadata = plan_one_domain_outage(nodes, k=k, n=n)
    counts: dict[str, dict[str, int]] = {}
    for name in data:
        label = nodes[name]["failure_domain"]
        counts.setdefault(label, {"data": 0, "metadata": 0})["data"] += 1
    for name in metadata:
        label = nodes[name]["failure_domain"]
        counts.setdefault(label, {"data": 0, "metadata": 0})["metadata"] += 1
    return {"profile": "one-declared-domain-outage-4of6-data-2of3-meta",
            "data_nodes": data, "metadata_nodes": metadata,
            "counts_by_domain": counts, "note": "Domain labels are self-reported; no physical independence attested."}
