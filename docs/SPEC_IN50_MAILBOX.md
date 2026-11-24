> **HISTORICAL LEGACY PROFILE — NOT THE RC5 CORE WIRE SPEC.** See [RC5 core specification](RC5_CORE_PROTOCOL_SPEC.md) and [experimental profiles](RC5_EXPERIMENTAL_PROFILES_AND_MIGRATION.md).

# IN50 mailbox application profile — v0.5.0-alpha (experimental)

## Scope

Adds `path_id=2` to the existing IN40/INL2 authenticated native UDP transport. **The original IN40 handshake, INL2 ciphertext format, v0.4.0 path 0, v0.4.2 path 1, and v0.2 object store are unchanged.** No version negotiation is implemented. Legacy nodes reject path 2 as unsupported; use explicit client and server capability configuration. **Never send real-user or business data with this research implementation.**

## Trust and cryptography

Handshake: mutually allowlisted Ed25519 static identities, ephemeral X25519 handshake as defined by v0.4.0. `path_id=2` records are encrypted/authenticated inside INL2; the mailbox does not add E2EE from sender to recipient. The **mailbox server can read the payload** and stores it *unencrypted* in SQLite. Trusting the server is mandatory for confidentiality. No audited forward secrecy or key rotation across identity compromise is claimed.

## Request/response formats

All integers network (big-endian) byte order. Client requests are INL2 path 2 payloads.

Request: `IM50` (4 bytes) | verb ASCII (1) | request ID (16) | body (0..1131). Request ID correlates replies; message ID is separately stable across retries and process restarts.

Response: `IR50` (4) | matching request ID (16) | status ASCII (1) | body.

| Verb | Request body | Response | Meaning |
|---|---|---|---|
| `S` | recipient Ed25519 (32) + message ID (16) + TTL seconds u32 (4) + content (1..960) | `D` + message ID (16) + SHA-256(content) (32) + `N` (new) / `I` (idempotent) | SQLite commit finished; **not delivered to recipient** |
| `F` | empty | `M` + sender pub (32) + message ID (16) + content; `N` empty | Read next unconsumed, non-expired record for **authenticated caller** |
| `A` | sender pub (32) + message ID (16) | `A` + message ID; or `E` | Authenticated recipient has acknowledged/marked consumed in SQLite; not proof of human reading |
| `Q` | message ID (16) | `Q` + `S/C/U/X` | Status for **authenticated original sender** only (stored, consumed, unknown, expired) |
| `P` | empty | `P` + `IN50` | Availability probe |

Authenticated malformed commands are rejected or return scoped errors. Unknown peers get no handshake response. Pinned server signature and session AEAD are mandatory for every response. All mailbox requests are idempotent (fresh-session replay uses the same stable message ID; fetch is non-destructive; consume can repeat).

## Local durability and idempotency

The server uses SQLite WAL, `synchronous=FULL`, explicit `BEGIN IMMEDIATE`/`COMMIT`, `PRIMARY KEY(sender_pub, message_id)`, and content+recipient digest conflict detection. A `D` response is emitted **after commit**. This confirms a write to a single local SQLite journal, **not** guaranteed hardware-power-loss durability, independent backup, recipient acceptance, or cross-provider replication. Expiry and maximum row count cause bounded rejection. Pruning old records also discards their deduplication history. Client queue uses a separate local plaintext SQLite file and marks entries `STORED` only after verifying a server's authenticated matching receipt. A send can be retried using a fresh authenticated UDP session after timeouts or server restart.

## Routing/discovery

The *operator-signed static bootstrap directory* (`IN50-STATIC-1`) maps recipient Ed25519 public keys to node IDs, each with host/port and a **pinned** server Ed25519 key. Canonical JSON (sorted keys, compact separators, ASCII) is signed using Ed25519 over domain `INNERnet/v0.5.0-alpha/static-directory\0`. A user must pin the directory operator key out of band. Directory signing provides authenticity and expiration checks, **not** revocation, independent proof of failure domains, a DHT, automatic cross-node forwarding, provider marketplace, NAT traversal, fallback routing, or ownership proof. This release tests **two localhost node processes**, not separate infrastructure providers.

## Explicit non-goals

- Production chat, generic end-to-end confidential messages, security audit, user identity provisioning or group messaging.
- Universal networking, true decentralized routing/consensus, DHT, independent provider verification, WAN-qualified service, NAT traversal, QUIC, VPN/TUN.
- Server-to-server relays, replicated inbox, exactly-once end-user effects, cross-node transactions, offline delivery guarantees, arbitrary file transfer over mailbox, censorship resistance or metered payments.
- Durable storage across operator compromise, hardware failure, stolen disk, or complete machine failure.
