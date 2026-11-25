# Changelog

## 1.0.0 — pre-tag hardening (2026-11-25, unreleased)

These changes apply to the still-untagged `v1.0.0` core source. They must pass CI on the exact `main` commit before the tag is created (see RELEASE_GATES.md).


- **R90-ROUTE-2 (new profile, additive):** route plans may now carry a mandatory monotonic `sequence` field. A client that verifies with the new `routing_v090.SequenceStore` rejects any plan whose sequence is `<=` the highest already seen from that pinned publisher, giving client-side anti-rollback/replay protection. `R90-ROUTE-1` is retained unchanged for read/forward compatibility and still has **no** anti-rollback (as documented); asking for a `SequenceStore` while handed a ROUTE-1 plan is now an explicit error rather than silent non-protection. See `docs/MIGRATION_ROUTE2.md`.
- **HTTP-v3 chunk key binding (SECURITY.md #1 closed in code):** `crypto.encrypt_chunk`/`decrypt_chunk` now derive the ChaCha20-Poly1305 key from `HKDF(root, "data/aead/v2/" + object_id)` instead of from `root` alone. Reusing a read root across different objects can no longer reuse key+nonce material; it would require a 128-bit object-ID collision. This changes the `inn3_` low-level chunk wire bytes — experimental profile only, excluded from the ST81/OB80-2/R90/UV10 core. `TEST_VECTORS_v0.2.json` regenerated accordingly. OB80-2 core objects are unaffected (they already bind the object ID into the key schedule salt).
- **Test fix:** `tests/test_v038_delivery_quality.py` now launches the probe subprocess with `sys.executable` instead of a bare `python`, so the suite passes inside a virtualenv.
- Release manifest regenerated.

## 1.0.0 — scoped protocol core software release (2026-11-24)

- Release-supported core: ST81 mutual authentication, OB80-2 recipient-encrypted object transfer, R90-ROUTE-1 signed routing with bounded failover, UV10-1 application container format.
- Free use and redistribution under Apache-2.0.
- Includes the prior RC5 dev4 Revision 2 security fixes and associated tests, including fresh per-upload credentials and strict ST81 JSON.
- Explicit exclusions: HTTP v2/v3 storage and IN40/IN41/IN50/IE60/IO70/mailbox research profiles; full protocol interoperability with independent implementations; R90 plan revocation/rollback protection; open/public ingress DoS guarantees.
- This is a scoped software release, **not a security certification**, production SLA or a declaration that all deployment scenarios are safe.

# Changelog

## 1.0.0rc5.dev4 — clean candidate packaging (2026-11-24)

- Preserved the tested dev4 Revision 2 protocol/runtime source; no cryptographic wire-format change from that reviewed source.
- Consolidated candidate documentation into an accurate root README, SECURITY.md, concise active docs, and explicit release gates.
- Removed legacy alpha release-note and benchmark-report files from the *distribution snapshot*; previous commits and original uploaded archives preserve their history.
- Kept all deployment, CI, benchmarks source, interop, tests, and protocol modules.
- Release manifest regenerated to reflect this source distribution.

**Status remains release candidate.** Green GitHub Actions for the exact cleaned commit and additional external evidence are still required before stable tagging.

## Previous development history

RC5 dev4 Rev2 addresses high-level HTTP-v3 capability reuse by minting fresh per-upload credentials and ordering optional durable persistence ahead of remote writes. It also strengthens ST81 parsing and one-time SQLite backfill behavior. See `docs/RC5_DEV4_REVIEW_REVISION2_AUDIT_DISPOSITION.md` and project Git history for earlier milestones and previous alpha releases.
