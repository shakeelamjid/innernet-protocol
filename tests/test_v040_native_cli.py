"""v0.4.0 standalone CLI and CLI authorization boundaries."""
from __future__ import annotations

import json
import os
import select
from pathlib import Path
import socket
import subprocess
import sys
import time

from innernet2.native_udp import generate_identity_file, load_identity, pub_bytes


def cli(*args, timeout=10):
    return subprocess.run([sys.executable, '-m', 'innernet2.native_udp', *map(str, args)],
                          capture_output=True, text=True, timeout=timeout)


def test_new_identity_and_public_only_cli(tmp_path):
    private = tmp_path / 'private.key'
    made = cli('init-identity', '--file', private)
    assert made.returncode == 0
    new_id = json.loads(made.stdout)['public_ed25519']
    assert len(new_id) == 64 and private.stat().st_mode & 0o777 == 0o600
    displayed = cli('show-identity', '--file', private)
    assert json.loads(displayed.stdout)['public_ed25519'] == new_id
    assert new_id != private.read_bytes().hex()
    assert cli('init-identity', '--file', private).returncode != 0


def test_public_listener_requires_explicit_ack(tmp_path):
    private = tmp_path / 'server.key'
    client = tmp_path / 'client.key'
    generate_identity_file(private)
    client_pub = generate_identity_file(client)
    p = cli('serve', '--identity', private, '--allow-client', client_pub,
            '--bind', '0.0.0.0', '--port', 29410, '--max-seconds', 0.1)
    assert p.returncode != 0
    assert 'requires explicit' in p.stderr


def test_cross_process_localhost_native_udp(tmp_path):
    server = tmp_path / 'server.key'
    client = tmp_path / 'client.key'
    server_public = generate_identity_file(server)
    client_public = generate_identity_file(client)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserver:
        reserver.bind(('127.0.0.1', 0))
        port = reserver.getsockname()[1]
    listener = subprocess.Popen([sys.executable, '-u', '-m', 'innernet2.native_udp',
                                 'serve', '--identity', str(server), '--allow-client', client_public,
                                 '--bind', '127.0.0.1', '--port', str(port), '--max-seconds', '4'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        ready, _, _ = select.select([listener.stdout], [], [], 5)
        assert ready, "native UDP test listener did not announce readiness within 5 seconds"
        line = listener.stdout.readline()
        assert json.loads(line)['ready'] is True
        p = cli('probe', '--identity', client, '--server-key', server_public,
                '--host', '127.0.0.1', '--port', port, '--samples', 20)
        assert p.returncode == 0, p.stderr
        report = json.loads(p.stdout)
        assert report['status'] == 'PASS'
        assert report['authenticated_receipts'] == 20
        assert report['unacknowledged_messages'] == 0
        assert 'NOT SSH' in report['transport']
    finally:
        listener.terminate()
        listener.communicate(timeout=4)
