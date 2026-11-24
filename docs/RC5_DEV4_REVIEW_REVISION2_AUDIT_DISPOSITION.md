# INNERnet RC5 dev4 — Review revision 2: responses to Claude static re-audit

Date: 2026-11-24. Reported release string: `1.0.0rc5.dev4`. Artifact label **RC5 dev4 review revision 2** distinguishes this changed source archive from the earlier dev4 preview of the same internal release string. This is **not stable v1.0** and is **not deployed**; deployed/GitHub baseline remains dev3 unless independently changed by the operator.

## What changed after the Claude dev4 re-audit

| Issue | Fix and evidence | Status |
|---|---|---|
| **D4-1** (capability persistence before placement checks) | `MeshClient.upload_file` now completes validation and node/domain selection **before** minting new HTTP-v3 capabilities or invoking the durable persistence callback. Preflight failure cannot orphan fresh keys. Adds `test_d4_1_failed_placement_does_not_mint_or_persist`. | Addressed locally |
| **D4-2** (weak callback ordering assertion) | `test_ar01_callback_before_first_remote_write` now enforces `persist` as the first event **for each upload**, with exactly one callback, subsequent real PUTs, and distinct capabilities on retries. | Addressed locally |
| **D4-3 / AR-02** (JSON float overflow) | `stream_v080.Session.read` now rejects non-finite float values arising from `1e400`, `-1e400`, `1e309` as `StreamError`; finite floats still accepted. The core spec contains an explicit overflow rule. No wire format change. | Addressed locally |
| **N-2** (database migration evidence) | Tests now recreate a **populated** `user_version=0` database with deliberately reset counters, then check that the one-time migration reconstructs usage and preserves every chunk. | Regression added |
| **N-6** (stale documentation) | Top-level `CHANGELOG` gains dev3/dev4 entries. Live module descriptions and `remote_lab` argument parser identify RC5/dev4, with IN40/IN41 clearly separated as experimental wire names. Migration doc identifies dev4 and states HTTP-v3 root single-use requirement. `qualify_v1.FOCUSED` includes the dev4 re-audit and core spec-vector tests. | Addressed locally |
| **dev3 evidence hash** | `docs/EVIDENCE_RC5_DEV3_LOCAL_PYTEST_LOG.txt` preserves the old `346 passed in 94.08s` summary; `docs/RC5_DEV3_LOCAL_TEST_EVIDENCE.md` publishes its SHA-256 and notes that it does **not** authenticate the original Git commit or independent execution. | Published with provenance limitation |

## Scope and limitations

The ST81/OB80-2/R90/UV10 candidate core remains unchanged on the wire. HTTP-v3 (`inn3_`/`inna_`) is **experimental** and outside that frozen core. The underlying v3 primitive is not misuse-resistant: encryption roots **MUST NOT** be reused across different objects, including through low-level functions. API-level single-use prevention is provided in `MeshClient.upload_file`, but external low-level callers require their own root lifecycle discipline. For future stable HTTP storage interoperability, a new versioned per-object key scheme (e.g. `inn4_`) is required; never retrofit a different decryption scheme under the `inn3_` name.

- **R90-ROUTE-1** still accepts older valid signed plans until their expiry (up to 24h); route revocation and metadata/availability protection require R90-ROUTE-2 with monotonic publisher watermark (not implemented).
- **Public ST81** is not guaranteed available against distributed or IPv6 /128 pre-auth flooding. Restrict public listeners using firewall/source allowlists. IPv6 /64 grouping/stateless cookies remain recommended.
- **ChunkStore** still opens a connection and brief write lock per authenticated request; the heavy full-data backfill is now once-only. Expired objects require maintenance-driven pruning.
- **IN41** clock jump replay is still a hypothesis, not verified or resolved.
- **Mailbox** synthetic time zero sign-state edge case remains informational; no real-clock exploit is established.

## Release gates

Before dev4 can replace a production node: run **GitHub Actions against this exact revision's commit** (Python 3.11, Python 3.12, Go and Docker jobs), Mac regression tests, and a copy-based SQLite schema migration plus v3 capability persistence/recovery rehearsal. Repeat a native-WAN smoke test with the exact changed build. None of the previously reported successful dev3 runs applies automatically to this changed dev4 revision.

Before calling INNERnet **stable v1.0**: obtain an independent human cryptographic/security assessment, independently implemented ST81/OB80-2/R90 interoperability against published vectors, and a provider-wide outage exercise rather than just a stopped test primary. A clean CI run and archived evidence tied to the release commit are also necessary. Earlier Railway verification used SSH relaying, not native independent-provider ingress.

## Evidence semantics

A static AI review is not a security certification. Local passing regressions provide behavioral evidence only for the paths tested; they cannot prove full protocol safety. Retain the full pytest log, Go build result, release manifest, and ZIP hash alongside this revision. Nothing here authorizes overwriting the current working dev3 deployment.
