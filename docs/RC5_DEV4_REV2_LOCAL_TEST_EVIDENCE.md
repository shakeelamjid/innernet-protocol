# RC5 dev4 revision 2 local validation (not GitHub CI)

Date: 2026-11-24. Tested build: `1.0.0rc5.dev4`, local revision 2 (source hash identified by accompanying ZIP and manifest).

- Command: `python -m pytest -vv tests/ --disable-warnings`
- Result: **363 passed**, `71.85s`, exit code 0. Local host: Linux; Python `Python 3.13.5`.
- Log: `EVIDENCE_RC5_DEV4_REV2_PYTEST_VERBOSE.txt` (SHA-256 `3121daf4b7a233e302d101e5c8734866ea6f769d02d3ec8501f4547f56c07673`).
- Focused re-audit: `17 passed` in a separate execution.
- Go build: `go build -o /tmp/innernet-uv10-dev4-review ./uv10verify` from `interop/go` succeeded; installed `go version go1.23.2 linux/amd64`.
- `python -m compileall -q innernet2 deploy tests` succeeded.
- This does **not** establish Mac testing, CI on Python 3.11/3.12, a reproducible secure build, or independent security certification. Earlier GitHub success run `45420388922` corresponds to **dev3**, not this dev4 revision.
