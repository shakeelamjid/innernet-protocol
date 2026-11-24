"""Opt-in native UDP sidecar cannot silently alter legacy deployment files."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_native_udp_compose_is_isolated_and_localhost_default():
    compose = (ROOT / 'compose.native-udp.optin.yaml').read_text()
    assert '127.0.0.1' in compose
    assert 'INN_NATIVE_BIND_IP' in compose
    assert 'INN_NATIVE_CLIENT_PUB' in compose
    assert 'restart: "no"' in compose
    assert 'cap_drop:' in compose
    assert 'read_only: true' in compose
    assert 'no-new-privileges:true' in compose
    assert '29410/udp' in compose


def test_no_existing_compose_wires_native_port_or_shares_state():
    for file in ('compose.coolify.yaml', 'compose.lab.coolify.yaml',
                 'compose.ssh-tunnel.coolify.yaml'):
        body = (ROOT / file).read_text()
        assert '29410' not in body
        assert 'native_alpha_identity' not in body
