"""Safe single-server lab: immutable identities and simulated group controls."""
import json
from pathlib import Path

import pytest

from deploy import lab_mesh, lab_control


def test_lab_groups_are_disjoint_and_complete():
    a = lab_control.group_nodes("group-a")
    b = lab_control.group_nodes("group-b")
    c = lab_control.group_nodes("group-c")
    assert len(a) == len(b) == len(c) == 3
    assert not (a & b or b & c or a & c)
    assert (a | b | c) == lab_control.group_nodes("all")


def test_bad_fault_injection_target_rejected():
    for target in ["group-d", "node-00", "node-10", "../../node-01", "*"]:
        with pytest.raises(ValueError):
            lab_control.group_nodes(target)


def test_lab_keys_persist_reinitialization(tmp_path, monkeypatch):
    base = tmp_path / "mesh"
    monkeypatch.setattr(lab_mesh, "BASE", base)
    lab_mesh.init_lab()
    peers = json.loads((base / "peers.json").read_text())
    first_private_key = (base / "node-01" / "node.key").read_bytes()
    assert len(peers["nodes"]) == 9
    assert [node["failure_domain"] for node in peers["nodes"]] == [
        *(["simulated-group-a"]*3), *(["simulated-group-b"]*3), *(["simulated-group-c"]*3)
    ]
    lab_mesh.init_lab()
    assert (base / "node-01" / "node.key").read_bytes() == first_private_key
    assert (base / "writers.json").stat().st_mode & 0o077 == 0


def test_fault_injection_changes_file_atomically(tmp_path, monkeypatch):
    base = tmp_path / "mesh"
    base.mkdir()
    (base / "writers.json").write_text('{"tokens":{}}')
    monkeypatch.setattr(lab_control, "BASE", base)
    state = lab_control.set_offline("group-a", True)
    assert state["set_offline"] == ["node-01", "node-02", "node-03"]
    lab_control.set_offline("node-03", False)
    assert json.loads((base / "offline.json").read_text())["offline"] == ["node-01", "node-02"]
    lab_control.set_offline("all", False)
    assert json.loads((base / "offline.json").read_text())["offline"] == []


def test_compose_exposes_only_loopback():
    cfg = Path(__file__).resolve().parents[1] / "compose.lab.coolify.yaml"
    content = cfg.read_text()
    assert content.count('"127.0.0.1:194') == 9
    assert "no-new-privileges:true" in content
    assert "innernet_lab_data" in content
    assert "9400:9400" not in content
