"""Implementation-aligned adversarial conformance vectors for the RC5 candidate.

These tests are NOT an independent ST81/OB80/R90 implementation or external audit.
"""
import hashlib
import json
import struct
import subprocess
import shutil
from pathlib import Path
import pytest
from innernet2.bulk_v080 import ID_DOMAIN
from innernet2.universal_v1 import inspect, unpack, UniversalError
from innernet2.version import RELEASE_VERSION, PROFILES

ROOT=Path(__file__).resolve().parents[1]

def _uv10(tmp_path, kind, body):
    header={"attributes":{},"content_type":"text/plain" if kind=="message" else "application/json",
            "created_at":1,"final":None,"kind":kind,"name":"message.txt",
            "sequence":None,"sha256":hashlib.sha256(body).hexdigest(),
            "size":len(body),"stream_id":None,"version":"UV10-1"}
    raw=json.dumps(header,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
    target=tmp_path/f'{kind}-{len(body)}.uv10'
    target.write_bytes(b'UV10'+struct.pack('>I',len(raw))+raw+body)
    return target

@pytest.mark.parametrize('kind,body',[
    ('message',b'\xff'),
    ('event',b'{"incomplete":}'),
    ('event',b'{"not_json":NaN}'),
    ('event',b'{"x":Infinity}'),
])
def test_invalid_payload_semantics_rejected_by_python_and_go(tmp_path,kind,body):
    path=_uv10(tmp_path,kind,body)
    assert inspect(path)['sha256']==hashlib.sha256(body).hexdigest()
    output=tmp_path/'output'
    with pytest.raises(UniversalError):unpack(path,output)
    assert not output.exists()
    if shutil.which('go'):
        result=subprocess.run(['go','run','./uv10verify',str(path)],
              cwd=ROOT/'interop/go',capture_output=True,text=True,timeout=45)
        assert result.returncode!=0, result.stdout


def test_ob80_scoped_id_formula_stable():
    sender=bytes(range(32))
    eph=bytes(range(32,64))
    digest=hashlib.sha256(ID_DOMAIN+sender+eph).digest()[:16].hex()
    assert digest=='a6b6f3cf089b6a9ef9b82dcc76cefa37'


def test_version_and_profiles_are_distinct_from_old_wire_tags():
    assert RELEASE_VERSION == '1.0.0'
    assert {'ST81','OB80-2','R90-ROUTE-1','UV10-1','IN41'}.issubset(set(PROFILES))
