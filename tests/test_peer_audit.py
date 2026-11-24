"""Peer verification tests against the existing local-node HTTP test network."""
from __future__ import annotations

import json
import time

import httpx
import pytest

from innernet2.audit import AuditError, audit_node, audit_registry
from innernet2.crypto import canonical, digest
from innernet2.node import create_app


def test_pinned_node_identity_signed_offer_and_fragment(mesh):
    client, _tmp, _apps = mesh
    node = client.nodes["node-01"]
    raw = b"INNERnet public sample bytes"
    locator = client.put_fragment("node-01", raw)
    result = audit_node(node, client.http, sample_sha256=locator["sha256"])
    assert result["identity_verified"]
    assert result["offer_signature_verified"]
    assert result["public_sample_verified"]
    assert result["public_sample_bytes"] == len(raw)
    assert not any("write.token" in str(v) for v in result.values())


def test_wrong_pinned_identity_rejected(mesh):
    client, _tmp, _apps = mesh
    node = dict(client.nodes["node-01"])
    node["public_key"] = client.nodes["node-02"]["public_key"]
    with pytest.raises(AuditError, match="identity endpoint"):
        audit_node(node, client.http)


def test_public_sample_hash_rejected_if_missing(mesh):
    client, _tmp, _apps = mesh
    with pytest.raises(httpx.HTTPStatusError):
        audit_node(client.nodes["node-01"], client.http, sample_sha256="a" * 64)


def test_signed_offer_tampering_rejected(mesh):
    client, _tmp, apps = mesh
    orig_client = client.http
    def tamper(request):
        if request.url.path == "/v2/offer":
            obj = apps["127.0.0.1:9600"].get("/v2/offer").json()
            obj["capacity_bytes"] = 10**18
            return httpx.Response(200, json=obj)
        api = apps[request.url.netloc.decode() if isinstance(request.url.netloc, bytes) else request.url.netloc]
        r = api.request(request.method, request.url.path)
        return httpx.Response(r.status_code, content=r.content, headers=dict(r.headers))
    with httpx.Client(transport=httpx.MockTransport(tamper)) as altered:
        with pytest.raises(AuditError, match="signature"):
            audit_node(client.nodes["node-01"], altered)


def test_stale_offer_rejected_after_signature_success(mesh):
    client, _tmp, apps = mesh
    node = client.nodes["node-01"]
    orig = apps["127.0.0.1:9600"].get("/v2/offer").json()
    with pytest.raises(AuditError, match="expired"):
        audit_node(node, client.http, now=orig["expires_at_unix"] + 11)


def test_registry_checks_all_nine_existing_nodes(mesh):
    client, _tmp, _apps = mesh
    result = audit_registry({"nodes": list(client.nodes.values())}, client.http)
    assert result["checked"] == 9
    assert result["passed"] == 9
    assert result["failed"] == 0
    assert result["repeated_hostnames"] == ["127.0.0.1"]


def test_duplicate_peers_and_unreachable_reports(mesh):
    client, _tmp, _apps = mesh
    peers = list(client.nodes.values())
    result = audit_registry({"nodes": [peers[0], peers[0], {
        "id": "node-other", "url": "https://does-not-matter.invalid",
        "public_key": peers[1]["public_key"]}]}, client.http)
    assert result["checked"] == 3
    assert result["passed"] == 1
    assert result["failed"] == 2
    assert "duplicate" in result["nodes"][1]["reason"]
