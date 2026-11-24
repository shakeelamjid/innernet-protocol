"""Verify the release manifest records every distributed source and the exact hashes."""
from pathlib import Path
import hashlib
root=Path(__file__).resolve().parents[1]
def included(path):
    relative=path.relative_to(root)
    return (path.is_file() and str(relative)!='RELEASE_MANIFEST.sha256'
        and not any(x in {'__pycache__','.venv','.git','.pytest_cache'} for x in relative.parts)
        and not any(part.endswith('.egg-info') for part in relative.parts)
        and path.name != '.DS_Store' and path.suffix not in {'.pyc','.pyo'} and not path.name.endswith('.tmp'))
actual={str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest()
        for f in root.rglob('*') if included(f)}
expected={}
for line in (root/'RELEASE_MANIFEST.sha256').read_text().splitlines():
    digest,separator,name=line.partition('  ')
    if not separator or name in expected:raise SystemExit('FAIL: invalid or duplicate manifest entry')
    expected[name]=digest
missing=set(actual)-set(expected)
extra=set(expected)-set(actual)
bad={name for name in set(actual)&set(expected) if actual[name]!=expected[name]}
if missing or extra or bad:
    raise SystemExit(f'FAIL: missing={sorted(missing)} extra={sorted(extra)} hash_mismatch={sorted(bad)}')
print(f'RELEASE_MANIFEST_PASS: {len(actual)} release files verified')
