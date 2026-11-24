"""Cross-language UV10 conformance: independent Go validator and Python packer."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import pytest
from innernet2.universal_v1 import pack, inspect

ROOT=Path(__file__).resolve().parents[1]


def test_fixed_python_vector(tmp_path):
    vector=json.loads((ROOT/'docs/UV10_TEST_VECTOR.json').read_text())
    raw=bytes.fromhex(vector['fixture_hex'])
    assert hashlib.sha256(raw).hexdigest()==vector['fixture_sha256']
    path=tmp_path/'fixture.uv10';path.write_bytes(raw)
    assert inspect(path)==vector['header']
    src=tmp_path/'text';src.write_text('SYNTHETIC:INNERnet-v1-interop\n',encoding='utf-8')
    result=tmp_path/'packed.uv10'
    pack(src,result,kind='message',content_type='text/plain',name='vector.txt',now=1700000000)
    assert result.read_bytes()==raw


def test_independent_go_verifies_python_vector_and_detects_corruption(tmp_path):
    if shutil.which('go') is None:
        pytest.skip('Go compiler not installed; checked separately in CI')
    vector=json.loads((ROOT/'docs/UV10_TEST_VECTOR.json').read_text())
    p=tmp_path/'good.uv10';p.write_bytes(bytes.fromhex(vector['fixture_hex']))
    def run(path):
        return subprocess.run(['go','run','./uv10verify',str(path)],
            cwd=ROOT/'interop/go',capture_output=True,text=True,timeout=60)
    valid=run(p)
    assert valid.returncode==0,valid.stderr
    assert json.loads(valid.stdout)['status']=='PASS'
    bad=bytearray(p.read_bytes());bad[-1]^=1
    corrupt=tmp_path/'corrupt.uv10';corrupt.write_bytes(bad)
    rejected=run(corrupt)
    assert rejected.returncode!=0
    assert 'SHA-256' in rejected.stderr
