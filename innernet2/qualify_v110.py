"""One-command v0.11 synthetic research qualification; no server provisioning.

Runs targeted regressions, local read-request comparison, 100 MiB local
multi-node relay/failover and optional anonymous third-party public MQTT probe.
The public MQTT service is NOT an INNERnet node. No SSH, VPS or passwords.
"""
from __future__ import annotations
from .version import RELEASE_VERSION
import argparse
import datetime as dt
import json
from pathlib import Path
import subprocess
import sys
import time

from .transit_v100 import run_demo
from .public_mqtt_v110 import relay_probe

FOCUSED=[
    'tests/test_v080_v090_v100.py',
    'tests/test_v100_vectors.py',
    'tests/test_v110_range_and_public.py',
    'tests/test_v110_release_hardening.py',
]


def _tests(*,full: bool=False) -> dict:
    cmd=[sys.executable,'-m','pytest','-q',*([] if full else FOCUSED)]
    try:
        result=subprocess.run(cmd,text=True,capture_output=True,timeout=180)
        output=(result.stdout+'\n'+result.stderr).strip()
        return {'status':'PASS' if result.returncode==0 else 'FAIL',
                'scope':'full inherited suite' if full else 'focused v0.8-v0.11 regression',
                'process_exit':result.returncode,'output_tail':output[-2500:]}
    except subprocess.TimeoutExpired:
        return {'status':'UNCONFIRMED','scope':'full inherited suite' if full else 'focused regression',
                'reason':'Test process exceeded the bounded 180-second qualification limit'}


def main(argv=None) -> None:
    parser=argparse.ArgumentParser(description='INNERnet v0.11 consolidated synthetic tests (local by default)')
    parser.add_argument('--mib',type=int,default=100,help='local bulk demonstration 1..100 MiB')
    parser.add_argument('--window',type=int,default=32,help='1..64 requests per pipeline')
    parser.add_argument('--benchmark-mib',type=int,default=8,help='local legacy-vs-range read comparison 1..100 MiB')
    parser.add_argument('--include-public-mqtt',action='store_true',
                        help='opt in to tiny synthetic ciphertext via anonymous TLS public MQTT broker')
    parser.add_argument('--full-suite',action='store_true',
                        help='attempt entire inherited suite with test timeout; may stall in old network tests')
    parser.add_argument('--report',type=Path,default=None,
                        help='optional path for JSON report; no overwrite allowed')
    args=parser.parse_args(argv)
    if not 1<=args.mib<=100 or not 1<=args.window<=64 or not 1<=args.benchmark_mib<=100:
        parser.error('mib and benchmark-mib must be 1..100; window 1..64')
    report={'release':RELEASE_VERSION,'synthetic_only':True,'created_utc':dt.datetime.now(dt.timezone.utc).isoformat(),
            'limitations':'local relay and 3rd-party MQTT only; not independent ST80 hosting, WAN bandwidth verification or security audit'}
    print('INNERnet 0.11 consolidated local qualification — no SSH or VPS changes',flush=True)
    print('>>> Focused regression suite',flush=True)
    report['focused_suite']=_tests()
    print(report['focused_suite']['output_tail'][-850:],flush=True)
    if report['focused_suite']['status']!='PASS':
        report['status']='FAIL'
    else:
        print('>>> Local range-vs-legacy retrieval benchmark',flush=True)
        try:
            from .benchmark_v110 import run as bench_run
            report['local_benchmark']=bench_run(args.benchmark_mib,args.window)
            print(json.dumps(report['local_benchmark'],indent=2),flush=True)
        except Exception as exc:
            report['local_benchmark']={'status':'FAIL','error':f'{type(exc).__name__}: {exc}'}
        if report['local_benchmark']['status']=='PASS':
            print('>>> Full local multi-node relay, restart, recovery and SHA-256 demo',flush=True)
            try:
                report['local_bulk']=run_demo(args.mib,window=args.window)
                print(json.dumps(report['local_bulk'],indent=2),flush=True)
            except Exception as exc:
                report['local_bulk']={'status':'FAIL','error':f'{type(exc).__name__}: {exc}'}
        report['status']='PASS' if report.get('local_bulk',{}).get('status')=='PASS' else 'FAIL'
    if args.full_suite:
        print('>>> Full inherited suite (separate result; legacy network tests may stall)',flush=True)
        report['full_suite']=_tests(full=True)
        print(report['full_suite'].get('output_tail',report['full_suite'].get('reason','')),flush=True)
    if args.include_public_mqtt:
        print('>>> Password-free public broker experiment (tiny IE60 synthetic ciphertext)',flush=True)
        try:
            report['public_mqtt']=relay_probe('test.mosquitto.org',8886,timeout=8,tls=True)
        except (OSError,ValueError,TimeoutError) as exc:
            report['public_mqtt']={'status':'UNAVAILABLE','error':f'{type(exc).__name__}: {exc}',
                                   'note':'Not an ST80 node and not a core local qualification failure'}
        print(json.dumps(report['public_mqtt'],indent=2),flush=True)
    path=args.report or (Path.home()/'Downloads'/('innernet_v011_qualification_'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.json'))
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists() or path.is_symlink():
        raise SystemExit('Refusing to overwrite existing qualification report: '+str(path))
    path.write_text(json.dumps(report,indent=2)+'\n')
    print('QUALIFICATION_REPORT_SAVED:',path,flush=True)
    print('INNERnet_V011_LOCAL_QUALIFICATION_'+report['status'],flush=True)
    if report['status']!='PASS':raise SystemExit(1)

if __name__=='__main__':main()
