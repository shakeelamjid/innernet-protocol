# v1.0.0 supported scope and limitations

INNERnet v1.0.0 is a **scoped software release**, not an externally certified security product.

## Supported protocol surfaces

| Surface | Release support | Notes |
|---|---|---|
| ST81 | Yes | Pinned Ed25519, ephemeral X25519, AEAD confirmation; no ST80 downgrade |
| OB80-2 | Yes | Recipient pinning, signed manifest, encryption/integrity, resumable ciphertext transfer |
| R90-ROUTE-1 | Yes, with limitations | Signed publisher and pinned node identities, client-side failover; no anti-rollback or discovery |
| UV10-1 | Yes, for framing | Validated type and content; plaintext unless sealed inside OB80 |
| HTTP-v2/v3 | Experimental | HTTP-v3 low-level root reuse is unsafe; do not reuse capability roots |
| Native UDP / mailbox | Experimental | Opt-in demos, not part of core compatibility/security pledge |
| Provider marketplace / x402 / compute rental | Not implemented | Future application-layer services, never required to use protocol |

## Security deployment guidance

Do not expose unrestricted ST81 service listeners to the public Internet: deploy behind firewall allowlists, reverse proxies or equivalent safeguards as appropriate. Always pin node, sender, recipient, and route publisher identities independently. R90 route delivery is not revocable during a ROUTE-1 validity period: use trusted delivery channels and short route validity where needed. Do not assume host/provider outage recovery from one-process failover. No confidential-computing or untrusted server-execution guarantees are provided.

The project has been AI source-reviewed and functionally tested; no independent human cryptographic audit, independently written full implementation, or production SLA exists as of this release. Report security issues privately using SECURITY.md.

## Compatibility and changes

Core protocol wire profile identifiers stay ST81, OB80-2, R90-ROUTE-1 and UV10-1. An incompatible wire change requires a new profile ID and migration notes. The application library is available under Apache-2.0, free to implement and use; operators may charge separately for hosted capacity.
