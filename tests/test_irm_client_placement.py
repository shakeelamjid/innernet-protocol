"""Shard placement and the seal -> mix -> 4-of-6 pipeline, without providers."""
from __future__ import annotations

import os

from innernet2 import codec
from innernet2.crypto import decrypt_chunk, deinterleave, encrypt_chunk, interleave, new_root
from innernet2.irm_client import CELL, K, N, _mix_key, _pick


def entry(i: int, region: str, uptime: str = "1.0", price: str = "0.002") -> dict:
    return {"id": f"{i:064x}", "name": f"p{i}", "region": region, "services": ["STO-1"],
            "prices": {"STO-1": {"amount": price}}, "reputation": {"uptime_7d": uptime}}


def place(candidates: list[dict]) -> list[dict]:
    holders: list[dict] = []
    for slot in range(N):
        e = _pick(candidates, holders, set())
        if e is None:
            break
        holders.append({"slot": slot, "provider": e["id"], "name": e["name"], "region": e["region"]})
    return holders


def test_six_providers_get_one_slot_each_regions_first():
    regions = ["asia-south", "asia-south", "eu-central", "us-east", "eu-central", "us-west", "af-south"]
    holders = place([entry(i, r) for i, r in enumerate(regions)])
    assert len(holders) == 6 and len({h["provider"] for h in holders}) == 6
    assert len({h["region"] for h in holders[:5]}) == 5          # every region once before any repeats


def test_three_providers_get_two_slots_each_and_two_are_not_enough():
    holders = place([entry(i, r) for i, r in enumerate(["a", "b", "c"])])
    counts = {}
    for h in holders:
        counts[h["name"]] = counts.get(h["name"], 0) + 1
    assert len(holders) == 6 and set(counts.values()) == {2}
    assert len(place([entry(0, "a"), entry(1, "b")])) == 4        # 2 + 2: put() refuses this


def test_pipeline_round_trip_any_four_shards_and_mixing_moves_cells():
    root, obj = new_root(), os.urandom(16)
    plain = os.urandom(64 * 1024)
    cipher = encrypt_chunk(root, obj, 7, plain)
    mixed = interleave(cipher, _mix_key(root, 7), CELL)
    assert mixed != cipher                                        # cells really moved (any one cell may stay put)
    shards = codec.encode(mixed, K, N)
    for drop in [(0, 1), (2, 5), (4, 5)]:
        some = {i: s for i, s in enumerate(shards) if i not in drop}
        back = deinterleave(codec.decode(some, K, N, len(mixed)), _mix_key(root, 7), CELL, len(cipher))
        assert decrypt_chunk(root, obj, 7, back, len(plain)) == plain
