"""Focused RC4 mitigations and cross-implementation rejection tests."""
import hashlib
import json
import secrets
import shutil
import struct
import subprocess
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from innernet2.native_udp import NativeResponder, pub_bytes, ephemeral_pub, hello_packet
from innernet2.universal_v1 import inspect, UniversalError


def test_unconfirmed_udp_hellos_cannot_lock_out_identity():
    client, server = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    mk = lambda: hello_packet(client, pub_bytes(server), secrets.token_bytes(16),
        ephemeral_pub(X25519PrivateKey.generate()), secrets.token_bytes(16))
    captured = [mk() for _ in range(32)]
    responder = NativeResponder(server,{pub_bytes(client)})
    for index, packet in enumerate(captured):
        assert responder.process(packet, ('127.0.0.1', 41000+index))
    restarted = NativeResponder(server,{pub_bytes(client)})
    for index, packet in enumerate(captured):
        assert restarted.process(packet, ('127.0.0.9', 42000+index))
    assert restarted.process(mk(), ('127.0.0.1', 43000)) is not None


@pytest.mark.parametrize('mode', ['nulls', 'negative_zero'])
def test_go_and_python_reject_bad_json_scalar_types(tmp_path,mode):
    if shutil.which('go') is None: pytest.skip('Go not installed')
    header = {'attributes':{},'content_type':'text/plain','created_at':0,'final':None,
        'kind':'file','name':'a','sequence':None,'sha256':hashlib.sha256(b'').hexdigest(),
        'size':0,'stream_id':None,'version':'UV10-1'}
    if mode=='nulls': header['size']=None
    raw=json.dumps(header,sort_keys=True,separators=(',',':')).encode()
    if mode=='negative_zero': raw=raw.replace(b'"created_at":0',b'"created_at":-0')
    f=tmp_path/'bad.uv10'; f.write_bytes(b'UV10'+struct.pack('>I',len(raw))+raw)
    with pytest.raises(UniversalError): inspect(f)
    result=subprocess.run(['go','run','./uv10verify',str(f)],
        cwd=Path(__file__).resolve().parents[1]/'interop/go',capture_output=True,timeout=60)
    assert result.returncode != 0, result.stdout.decode(errors='replace')
