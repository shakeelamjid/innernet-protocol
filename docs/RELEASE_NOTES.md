# INNERnet v1.0.0 — release notes

**Release type:** scoped ST81 / OB80-2 / R90-ROUTE-1 / UV10-1 software release.
**Source license:** Apache License 2.0. **No protocol royalties.**
**Independent security certification:** none. **Full independent protocol interoperability:** not yet demonstrated.

## Included
- ST81 Ed25519-pinned authenticated TCP key-confirmed sessions.
- OB80-2 sender-bound, recipient-encrypted chunks with integrity and transfer resume.
- R90-ROUTE-1 signed, pinned routing with per-peer failover.
- UV10-1 typed file/message/event application containers.
- Integrated tests and a separate Go verifier for UV10 framing.

## Not included in the stable core
- HTTP v2/v3 mesh storage, native UDP IN40/IN41, mailbox and related optional experimental profiles.
- Payment, x402, provider marketplace or compute rental.
- Full multi-implementation wire interoperability, R90 route rollback protection, universal public-Internet DDoS resistance, provider outage guarantees or external cryptographic certification.

For deployment restrictions, compatibility details and residual risks, see `docs/STABLE_CORE_SCOPE_AND_LIMITATIONS.md`, `SECURITY.md`, and `docs/RC5_CORE_PROTOCOL_SPEC.md`.

The release asset must match the tagged commit; the publisher aborts if exact-commit GitHub CI fails.
