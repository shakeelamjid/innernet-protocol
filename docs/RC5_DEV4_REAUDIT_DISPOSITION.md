# INNERnet RC5 dev4 — AI-assisted re-audit disposition

**Date:** 2026-11-24  **Build:** `1.0.0rc5.dev4`  **Status:** Security-fix preview, NOT stable v1.0.

This candidate was made from the exact `INNERnet_Complete_GitHub_Repo_RC5_dev3_Final_Hardening_Review.zip` source. It has **not** been published to GitHub, deployed on Contabo, run on Railway, or certified by a human auditor. Earlier successful test outcomes are for **dev3**, not evidence that dev4 passes on a public network.

## Confirmed findings and code changes

- **AR-01 (High conditional, HTTP-v3):** The existing v3 AEAD key depends on `root` and nonce on chunk index, not on `object_id`; new objects reusing a root repeat key/nonce. The `MeshClient.upload_file` method now **always generates fresh credentials internally**, removing the `capability_pair` API injection point and invoking an optional `persist_capabilities(reader, admin)` callback before the first remote shard write. CLI and both remote lab upload paths use the callback. Existing `inn2_` / `inn3_` wire formats and ciphertexts are unchanged. Direct use of low-level primitives remains root-single-use-only; this fix is API-level prevention, not a new misuse-resistant cryptographic construction. Previously reused roots cannot be repaired cryptographically; re-upload with fresh keys.
- **AR-02 (Low for current Python deployment):** Authenticated ST81 JSON frames now reject duplicate object keys, NaN/Infinity, integers outside signed 64-bit, and deep nesting (>64), mapping invalid JSON to `StreamError`. No wire version bump is needed because compliant Python writers already emitted canonical finite JSON.
- **N-2 (Low–Medium DoS amplifier):** `ChunkStore` counters are backfilled once, transactionally, when a DB moves from `user_version=0` to 1, not on every connection. Existing counter state is reconstructed under the SQLite write lock.
- **N-3 (Low):** The recipient Ed25519 identity is compared to the signed recipient before checkpoint allocation, even in `resume_dir` mode.
- **N-4 (Low):** An already-rejected mailbox message cannot be reported as successfully consumed.
- **N-6 (Low release documentation):** Added a current top-level release warning, changed two stale live-version reports, and clarified that historical 346-test logs and disjoint test runs describe distinct executions. Retained historical sections as historical records; no evidence was invented.

## Findings acknowledged but not fixed by this narrow preview

- **AR-03 (Low–Medium):** R90-ROUTE-1 plans remain replayable within signed TTL. Rejecting previously valid plans would require a new R90-ROUTE-2 with sequence and crash-safe publisher watermark. Preserve legacy acceptance only with clear policy. Avoid pretending old plans offer revocation.
- **N-1 (Medium if publicly exposed):** Distributed pre-auth connection churn can still starve legitimate ST81 sockets; restrict listeners with firewall/source allowlists. Full anti-DoS cookies and IPv6 /64 fairness are a separate public-deployment hardening task.
- **N-5 (Low):** Expired storage objects require `maintenance --prune-expired`; the service does not automatically remove them. Operator runbook required for bounded quotas.
- **N-7 (Info):** IN41 journal clock rollback after future time jump remains an untested hypothesis.
- **Independent audit, full-stack interoperability and provider-wide outage:** Not established by local tests or the earlier SSH-relayed Railway demo.

## Migration and security constraints

1. `MeshClient.upload_file(..., capability_pair=...)` callers **must** switch to `persist_capabilities(reader, admin)`. This is intentionally source-breaking for callers of unsafe pre-minted pair reuse, without changing the HTTP-v3 wire.
2. The callback must make both secrets durable in independent owner-private stores before returning. Exceptions propagate and stop before remote PUTs. Callbackless uploads still mint fresh capabilities but risk orphaning the directory-admin secret if the process crashes before the result is saved.
3. If earlier callers intentionally reused a v3 root across distinct plaintexts, confidentiality of affected objects might have been compromised; rotate by re-uploading new objects and revoke old access operationally where possible.
4. Keep `1.0.0rc5.dev3` deployment running unchanged until the dev4 candidate has passed Mac/Linux CI, migration rehearsals, and separate security review. No automatic deployment or forced database migration is performed by this archive.

**Release verdict:** Not stable v1.0. Fixes and regression tests are provided as a new RC5 security preview, not independent professional certification.
