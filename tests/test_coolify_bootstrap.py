"""Tests for persistent Coolify node identity and safe configuration checks."""
import json
from pathlib import Path

import pytest

from deploy.coolify_node import bootstrap


def test_bootstrap_idempotent(tmp_path, monkeypatch):
    node = tmp_path / "node"
    monkeypatch.setenv("INN_NODE_DATA", str(node))
    monkeypatch.setenv("INN_NODE_ID", "node-contabo-01")
    monkeypatch.setenv("INN_PUBLIC_URL", "https://node1.example.org")
    monkeypatch.setenv("INN_CAPACITY_BYTES", "268435456")
    assert bootstrap() == node
    key = (node / "node.key").read_bytes()
    assert bootstrap() == node
    assert (node / "node.key").read_bytes() == key
    assert json.loads((node / "config.json").read_text())["public_url"] == "https://node1.example.org"


def test_bootstrap_rejects_change_of_identity(tmp_path, monkeypatch):
    monkeypatch.setenv("INN_NODE_DATA", str(tmp_path / "node"))
    monkeypatch.setenv("INN_PUBLIC_URL", "https://node1.example.org")
    bootstrap()
    monkeypatch.setenv("INN_PUBLIC_URL", "https://node2.example.org")
    with pytest.raises(RuntimeError, match="changed"):
        bootstrap()


def test_bootstrap_rejects_http_public_url(tmp_path, monkeypatch):
    monkeypatch.setenv("INN_NODE_DATA", str(tmp_path / "node"))
    monkeypatch.setenv("INN_PUBLIC_URL", "http://node1.example.org")
    with pytest.raises(ValueError, match="HTTPS"):
        bootstrap()
