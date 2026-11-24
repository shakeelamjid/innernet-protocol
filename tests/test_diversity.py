"""Operator-labelled anti-concentration placement tests."""
from __future__ import annotations

import json

import pytest

from innernet2.network import INNERnetError, MeshClient


def test_strict_placement_fails_without_domains(mesh, tmp_path):
    client, _, _ = mesh
    path = tmp_path / "plaintext"
    path.write_bytes(b"not yet uploaded")
    with pytest.raises(INNERnetError, match="distinct declared failure domains"):
        client.upload_file(path, require_diverse_domains=True, capability_version=2)


def test_strict_placement_with_nine_distinct_operator_domains(mesh, tmp_path):
    client, _, _ = mesh
    nodes = []
    for i, peer in enumerate(client.nodes.values()):
        nodes.append({**peer, "failure_domain": f"example-operator-{i}"})
    strict = MeshClient({"nodes": nodes}, {"tokens": client.writers}, http=client.http)
    path = tmp_path / "plaintext"
    path.write_bytes(b"all nodes independently labelled" * 67)
    result = strict.upload_file(path, chunk_bytes=8192, require_diverse_domains=True, capability_version=2)
    target = tmp_path / "restored"
    strict.restore_file(result["capability"], target)
    assert target.read_bytes() == path.read_bytes()


def test_strict_placement_fails_with_repeated_domains(mesh, tmp_path):
    client, _, _ = mesh
    nodes = [dict(n, failure_domain="all-the-same") for n in client.nodes.values()]
    strict = MeshClient({"nodes": nodes}, {"tokens": client.writers}, http=client.http)
    path = tmp_path / "plaintext"
    path.write_bytes(b"strict")
    with pytest.raises(INNERnetError, match="only 1 provided"):
        strict.upload_file(path, require_diverse_domains=True, capability_version=2)
