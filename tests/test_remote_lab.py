"""v0.3.2 Mac/SSH lab configuration and security regression tests."""
from __future__ import annotations

import json
import re
import stat
from pathlib import Path

import pytest

from innernet2 import remote_lab


def bundle():
    peers = {"nodes": [{"id": f"node-{i:02d}",
                         "url": f"http://127.0.0.1:{19400+i}",
                         "public_key": f"{i:064x}",
                         "failure_domain": f"simulated-group-{'abc'[(i-1)//3]}"}
                        for i in range(1, 10)]}
    writers = {"tokens": {f"node-{i:02d}": f"unit-test-token-for-node-{i:02d}-secret-123"
                          for i in range(1, 10)}}
    return peers, writers


def test_local_configuration_rewrites_ports_and_preserves_keys():
    peers, writers = bundle()
    public, private = remote_lab.local_configuration(peers, writers)
    assert public["nodes"][0]["url"] == "http://127.0.0.1:29401"
    assert public["nodes"][-1]["url"] == "http://127.0.0.1:29409"
    assert private["endpoints"]["node-05"] == "http://127.0.0.1:29405"
    assert public["nodes"][0]["public_key"] == peers["nodes"][0]["public_key"]
    assert private["tokens"] == writers["tokens"]
    assert "tokens" not in public


@pytest.mark.parametrize("index,field,value", [
    (0, "id", "node-99"), (1, "url", "https://example.com"),
    (2, "public_key", "ABCD"), (3, "failure_domain", "outside-contabo")
])
def test_malformed_lab_bundle_rejected(index, field, value):
    peers, writers = bundle()
    peers["nodes"][index][field] = value
    with pytest.raises(remote_lab.RemoteLabError):
        remote_lab.local_configuration(peers, writers)


def test_missing_writer_token_rejected():
    peers, writers = bundle()
    writers["tokens"].pop("node-04")
    with pytest.raises(remote_lab.RemoteLabError):
        remote_lab.local_configuration(peers, writers)


def test_duplicate_node_key_rejected():
    peers, writers = bundle()
    peers["nodes"][1]["public_key"] = peers["nodes"][0]["public_key"]
    with pytest.raises(remote_lab.RemoteLabError):
        remote_lab.local_configuration(peers, writers)


@pytest.mark.parametrize("value", ["-oProxyCommand=bad", "root@host;touch /tmp/hack", "root@foo bar", "root@", "$(id)"])
def test_disallow_unsafe_ssh_targets(value):
    with pytest.raises(ValueError):
        remote_lab.safe_ssh_target(value)


def test_tunnel_binds_all_ports_to_local_loopback():
    args = remote_lab.tunnel_args({"ssh": "root@contabo.example", "local_base": 29400})
    assert args.count("-L") == 9
    assert len([v for v in args if re.fullmatch(r"127\.0\.0\.1:2940[1-9]:127\.0\.0\.1:1940[1-9]", v)]) == 9
    assert "ExitOnForwardFailure=yes" in args
    assert "0.0.0.0:" not in " ".join(args)
    assert args[-1] == "root@contabo.example"


def test_secure_write_creates_private_non_world_readable_file(tmp_path):
    folder = remote_lab.ensure_private_directory(tmp_path / "private")
    destination = folder / "writers.json"
    remote_lab.secure_write(destination, b"secret-value")
    assert destination.read_bytes() == b"secret-value"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert stat.S_IMODE(folder.stat().st_mode) == 0o700
    with pytest.raises(FileExistsError):
        remote_lab.secure_write(destination, b"different")
    assert destination.read_bytes() == b"secret-value"
    remote_lab.secure_write(destination, b"new-secret", replace=True)
    assert destination.read_bytes() == b"new-secret"


def test_secure_write_rejects_symlinks(tmp_path):
    secret = tmp_path / "important.txt"
    secret.write_text("unchanged")
    link = tmp_path / "writers.json"
    link.symlink_to(secret)
    with pytest.raises(remote_lab.RemoteLabError):
        remote_lab.secure_write(link, b"bad", replace=True)
    assert secret.read_text() == "unchanged"


def test_private_directory_rejects_symlink(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "shortcut"
    link.symlink_to(real)
    with pytest.raises(remote_lab.RemoteLabError):
        remote_lab.ensure_private_directory(link)


def test_prepare_imports_secret_only_after_checking_host_loopback(tmp_path, monkeypatch):
    peers, writers = bundle()
    ports = "\n".join(f"{19400+i}/tcp -> 127.0.0.1:{19400+i}" for i in range(1, 10)).encode()
    container = "lab-muqgdcslj3muoss1viam2t4l-20261122T145857"
    calls = []

    def fake_ssh(target, args, **kwargs):
        calls.append(args)
        if args[:2] == ["docker", "port"]:
            return ports
        if args[-1] == "/var/lib/innernet-lab/mesh/peers.json":
            return json.dumps(peers).encode()
        if args[-1] == "/var/lib/innernet-lab/mesh/writers.json":
            return json.dumps(writers).encode()
        raise AssertionError(args)

    monkeypatch.setattr(remote_lab, "ssh_command", fake_ssh)
    result = remote_lab.prepare("root@contabo.example", tmp_path / "private", container)
    assert result["prepared"]
    assert (tmp_path / "private" / "writers.json").stat().st_mode & 0o077 == 0
    assert "unit-test-token" not in json.dumps(result)
    assert len(calls) == 3
    assert remote_lab.read_config(tmp_path / "private")["container"] == container

    # Must not silently accept changed remote identities, even with valid tokens.
    peers["nodes"][0]["public_key"] = f"{333:064x}"
    with pytest.raises(remote_lab.RemoteLabError, match="signing keys changed"):
        remote_lab.prepare("root@contabo.example", tmp_path / "private", container)


def test_prepare_rejects_publicly_bound_lab_ports(tmp_path, monkeypatch):
    container = "lab-muqgdcslj3muoss1viam2t4l-20261122T145857"
    def fake_ssh(target, args, **kwargs):
        if args[:2] == ["docker", "port"]:
            return b"19401/tcp -> 0.0.0.0:19401\n"
        raise AssertionError("must not request tokens when the lab is publicly bound")
    monkeypatch.setattr(remote_lab, "ssh_command", fake_ssh)
    with pytest.raises(remote_lab.RemoteLabError, match="Contabo 127.0.0.1"):
        remote_lab.prepare("root@contabo.example", tmp_path / "private", container)


def test_invalid_or_readable_config_is_rejected(tmp_path):
    private = remote_lab.ensure_private_directory(tmp_path / "private")
    configuration = private / "config.json"
    configuration.write_text(json.dumps({"ssh":"root@contabo.example", "container":"lab-abc-20261122T145857"}))
    configuration.chmod(0o644)
    with pytest.raises(remote_lab.RemoteLabError):
        remote_lab.read_config(private)


def test_container_name_validation():
    assert remote_lab.CONTAINER_RE.fullmatch("lab-muqgdcslj3muoss1viam2t4l-20261122T145857")
    assert not remote_lab.CONTAINER_RE.fullmatch("node-pu3wwohcwsfuvz8std0txppn-20261122T144117")
