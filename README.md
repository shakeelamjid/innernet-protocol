# INNERnet Protocol

**INNERnet v1.0.0 — scoped core release source (ST81 / OB80-2 / R90-ROUTE-1 / UV10-1).** The core implementation has passed local automated testing; **it has not received an independent professional cryptographic audit or full-stack independent interoperability certification.** The current GitHub CI status for the v1.0.0 commit must be checked before relying on this release.

INNERnet is an open recipient-encrypted object transport and recovery protocol. The scoped candidate core is **ST81 authenticated TCP**, **OB80-2 recipient-encrypted objects**, **R90 signed routes/failover**, and **UV10-1 typed application containers**.

**License:** [Apache License 2.0](LICENSE) — free to use, modify, redistribute, and implement, including commercially, subject to license conditions. Running third-party infrastructure may incur charges. There are no obligatory INNERnet protocol royalties.

**Known boundaries:** Do not use this implementation as proof of independent security certification. R90-ROUTE-1 accepts previously signed plans until expiry (no anti-rollback); do not expose ST81 listeners without firewall/network filtering; HTTP-v3 and native UDP/mailbox profiles remain experimental. Read [supported scope](docs/STABLE_CORE_SCOPE_AND_LIMITATIONS.md) and [security policy](SECURITY.md).

**Repository:** https://github.com/shakeelamjid/innernet-protocol
**Project website (planned):** https://innernetcorp.com
**License:** See [LICENSE](LICENSE).

## Quick start: local synthetic test

Requires Python 3.11–3.12 for the CI matrix (Python 3.13 also passed a local full suite) and a supported platform.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test]'
python -m pytest -q
python -m innernet2.transit_v100 demo --mib 1 --window 16
```

The demo uses only disposable synthetic data and loopback listeners. No server or public port is required. For typed UV10 framing, see [the candidate quickstart](docs/V1_CANDIDATE_QUICKSTART.md). **UV10 by itself is plaintext; only sealing within OB80 provides recipient encryption.**

## Architecture and boundaries

| Layer | Purpose | Current scope |
|---|---|---|
| **ST81** | Mutually pinned authenticated TCP sessions with key confirmation | Candidate core |
| **OB80-2** | Sender-bound, recipient-encrypted chunked objects | Candidate core |
| **R90-ROUTE-1** | Publisher-signed routes and retry across pinned replicas | Candidate core; no route rollback prevention |
| **UV10-1** | Typed application framing for messages, events and files | Candidate core; plaintext unless sealed |
| HTTP-v2/v3, IN40/41, mailbox and related profiles | Additional research transports/storage | **Experimental**; not part of a stable core claim |

Read [Core protocol specification](docs/RC5_CORE_PROTOCOL_SPEC.md), [architecture](docs/ARCHITECTURE.md), [security limits](SECURITY.md), and [release gates](docs/RELEASE_GATES.md) before integrating.

**Next phase (draft, not implemented):** [IRM-1 Resource Market](docs/IRM1_RESOURCE_MARKET_SPEC.md) — paid storage, relaying and compute from registered providers over x402, with a non-custodial 1% network fee. Not part of v1.0.0. Providers: [innernet-provider CLI](docs/IRM1_PROVIDER_CLI.md) (draft, testnet).

## Validation record

The preceding dev4 Revision 2 candidate passed **363 local tests** and the Go UV10 build. This clean public GitHub package contains documentation/publishing updates, not protocol algorithm changes. **Its exact `main` commit must still pass GitHub Actions before you create the `v1.0.0` tag.** A green CI run on dev3 is not evidence for this commit. Previously reported native-WAN and two-provider experiments belong to dev3.

No independent full ST81/OB80-2/R90 implementation, independent human cryptographic audit, or actual entire-provider outage test is claimed.

## Deployment

Existing Contabo/Coolify infrastructure should **remain on the already-tested dev3 build** until this exact `main` commit passes CI, compatibility/SQLite migration qualification, and isolated native-WAN testing. Updating GitHub source does **not** require changing the deployed container. Do not deploy this archive directly to production.

See [release migration plan](docs/MIGRATION_FROM_DEV3.md) and [Coolify deployment notes](deploy/COOLIFY_GUIDE.md).

## Security

Custom cryptography and transport code is experimental. Restrict network access; use synthetic test data; do not place real secrets in the repository or publicly accessible tests. Responsible disclosure: [SECURITY.md](SECURITY.md).

## Publishing via GitHub website (single `main` branch)

See [GitHub website publishing instructions](docs/GITHUB_WEB_UPLOAD.md). The repository uses only `main`; the `v1.0.0` Git tag is **not a branch**. The `compose.*.yaml` files intentionally remain in the repository root because they use root-relative Docker build contexts. See [deployment overview](deploy/README.md).

This package is intended for a **fresh repository with clean Git history**. Its source has received a pattern-based secret scan, but this cannot establish that every configuration is safe for production.
