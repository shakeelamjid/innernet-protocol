# Security policy and known limits

**Status: research release candidate, not independently audited or certified. Not recommended for sensitive or irreplaceable real-world data.**

## Candidate core

ST81 uses mutually pinned Ed25519 identities, fresh X25519 exchange, transcript binding, AEAD frames, and key-confirmation. OB80-2 seals object chunks to an explicitly pinned recipient and checks original sender, ciphertext hashes, AEAD, and whole-object integrity. R90 routes are signed by an independently pinned publisher. UV10 is an application data container and contains **plaintext until protected by OB80**.

## Known risks and unsupported guarantees

1. **HTTP-v3 `inn3_` chunk encryption (as of 1.0.1).** `encrypt_chunk`/`decrypt_chunk` now bind the AEAD key to the object ID (`HKDF(root, "data/aead/v2/"+object_id)`), so reusing a root across different objects no longer reuses chunk key+nonce material. `encrypt_metadata` is **not** yet object-bound: low-level callers that reuse a root across objects with the same metadata `sequence` can still reuse metadata key+nonce — use `MeshClient.upload_file`, which generates a fresh root per upload, and do not reuse roots. HTTP-v3 is experimental and excluded from the candidate core.
2. **R90-ROUTE-1 does not support route revocation or anti-rollback.** A valid older route can be accepted until expiry. Signed plans are availability/metadata hints, not revocable authorization grants.
3. **Unrestricted public ST81 listeners remain susceptible to resource-exhaustion/flooding.** Use provider and host firewalls/source-IP restrictions and isolated test nodes; do not claim DDoS resilience.
4. **Long-term recipient key compromise may reveal historical OB80 payloads.** There is no independently established E2EE ratchet/key transparency.
5. **HTTP-v3 capability persistence is optional in API.** Use durable, private callback persistence before any remote I/O to avoid orphaning data on abrupt exit.
6. **Expired OB80 objects require maintenance pruning**; expiry alone does not free quota automatically.
7. **Sender/recipient identities, sizes, routing and timing metadata are observable** to relevant relays. Sender/recipient pinning cannot prove third-party host independence or availability.
8. Tests do not substitute for an independent human cryptographic audit, a full independent ST81/OB80-2/R90 implementation, or a complete independent-provider outage qualification.

### Public exposure

Keep experimental storage write APIs private; use read-only gateway roles and isolated credentials; do not publish operational seed files, passwords, tokens, checkpoints, database files, or encrypted customer workloads. Avoid wildcard DNS and unrestricted transport listener ports. The repository's CI is not a production security assessment.

### Vulnerability reporting

Use GitHub's private vulnerability reporting feature, if enabled, for security issues: https://github.com/shakeelamjid/innernet-protocol/security . Do not include secrets, sensitive user data, or working exploits in public issues.

See [core specification](docs/RC5_CORE_PROTOCOL_SPEC.md) and [release gates](docs/RELEASE_GATES.md).
