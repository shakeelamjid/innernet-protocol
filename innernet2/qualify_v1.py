"""Bounded v1.0 RC5 research qualification; no VPS, SSH or server mutation."""
from __future__ import annotations
from .version import RELEASE_VERSION
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from .universal_v1 import pack, unpack, inspect
from .transit_v100 import run_demo

FOCUSED=[
    'tests/test_v1_universal.py', 'tests/test_v1_interop.py',
    'tests/test_rc3_audit_regressions.py',
    'tests/test_rc4_st81_handshake.py',
    'tests/test_rc4_parser_and_udp.py',
    'tests/test_v080_v090_v100.py', 'tests/test_v100_vectors.py',
    'tests/test_v110_range_and_public.py', 'tests/test_v110_release_hardening.py',
    'tests/test_v070_wan_ttl_regression.py',
    'tests/test_rc5_release_security.py',
    'tests/test_rc5_independent_audit.py',
    'tests/test_rc5_in41_freshness.py',
    'tests/test_rc5_v3_separation.py',
    'tests/test_rc5_final_adversarial.py',
    'tests/test_rc5_dev4_reaudit.py',
    'tests/test_rc5_final_spec_vectors.py',
]


def _tests(paths: list[str], timeout: int=120) -> dict:
    try:
        p=subprocess.run([sys.executable,'-m','pytest','-q',*paths],
                         capture_output=True,text=True,timeout=timeout)
        return {'status':'PASS' if p.returncode==0 else 'FAIL',
                'exit_code':p.returncode,'summary':(p.stdout+'\n'+p.stderr)[-1000:]}
    except subprocess.TimeoutExpired:
        return {'status':'UNCONFIRMED','reason':f'test execution exceeded {timeout}s'}


def main(argv=None):
    ap=argparse.ArgumentParser(description='INNERnet RC5 local universal protocol candidate qualification')
    ap.add_argument('--mib',type=int,default=10,help='1..100 MiB local bulk transfer')
    ap.add_argument('--window',type=int,default=32)
    ap.add_argument('--full-suite',action='store_true',help='optional entire inherited test suite with timeout')
    ap.add_argument('--report',type=Path,help='output JSON report path, no overwrite')
    args=ap.parse_args(argv)
    if not 1<=args.mib<=100 or not 1<=args.window<=64:
        ap.error('--mib 1..100, --window 1..64')
    report={'version':RELEASE_VERSION,'category':'v1.0.0 scoped core implementation; externally unaudited',
            'utc':dt.datetime.now(dt.timezone.utc).isoformat(),
            'independent_host_gate':'NOT TESTED','independent_crypto_audit':'NOT COMPLETED',
            'independent_ST81_OB80_stack':'NOT IMPLEMENTED',
            'public_mqtt_note':'third-party MQTT transport is not an INNERnet node'}
    print('>>> UV10 application envelope and integration regression',flush=True)
    report['focused']=_tests(FOCUSED)
    print(report['focused']['summary'],flush=True)
    if report['focused']['status']!='PASS':
        report['status']='FAIL'
    else:
        print('>>> Local universal message roundtrip, no server changes',flush=True)
        with tempfile.TemporaryDirectory(prefix='inn-v1-local-') as td:
            root=Path(td);src=root/'message.txt';src.write_bytes(b'SYNTHETIC:INNERnet/UV10-1 sample')
            pack(src,root/'message.uv10',kind='message',content_type='text/plain',name='sample.txt')
            head=unpack(root/'message.uv10',root/'decoded.txt')
            assert (root/'decoded.txt').read_bytes()==src.read_bytes()
            report['uv10']={'status':'PASS','kind':head['kind'],'sha256':head['sha256']}
        print(json.dumps(report['uv10'],indent=2),flush=True)
        print('>>> ST81/OB80-2/R90 multi-node synthetic transfer and failover',flush=True)
        try:
            report['local_bulk']=run_demo(args.mib,window=args.window)
            print(json.dumps({k:v for k,v in report['local_bulk'].items()
                              if k in ('status','v080_bulk','v090_signed_fallback_routes','v090_failed_primary_fallback','v100_recipient_sha256','v110_fetch')},indent=2),flush=True)
        except Exception as exc:
            report['local_bulk']={'status':'FAIL','error':f'{type(exc).__name__}: {exc}'}
        report['status']='PASS' if report['local_bulk']['status']=='PASS' else 'FAIL'
    if args.full_suite:
        print('>>> Optional full inherited suite; separate gate, timeout limited',flush=True)
        report['full_suite']=_tests([],timeout=180)
        print(report['full_suite'].get('summary',report['full_suite'].get('reason','')),flush=True)
    print('>>> Release gates',flush=True)
    report['release_gates']={
        'candidate_local':'PASS' if report['status']=='PASS' else 'FAIL',
        'stable_1_0':'BLOCKED: independent-host resilience, full-stack interoperability and independent security review',
    }
    print(json.dumps(report['release_gates'],indent=2),flush=True)
    path=args.report or (Path.home()/'Downloads'/('innernet_v1_candidate_'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.json'))
    if path.exists() or path.is_symlink():
        raise SystemExit('Refusing to overwrite report file')
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(report,indent=2)+'\n')
    print('REPORT_SAVED:',path,flush=True)
    print('INNERnet_V1_CANDIDATE_LOCAL_'+report['status'],flush=True)
    if report['status']!='PASS':raise SystemExit(1)

if __name__=='__main__':main()
