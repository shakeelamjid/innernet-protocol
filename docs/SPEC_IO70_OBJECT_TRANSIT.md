# INNERnet IO70 — Experimental Bounded Encrypted Object Transfer (Draft 1)

**Status:** Research-only, synthetic data; NOT a complete production object/streaming protocol.

## Compatibility, layering, and scope

IO70 payloads are the *plaintext* of existing signed IE60 recipient ciphertext envelopes,
transferred in existing IM50 `STORE/FETCH/ACK` application requests (path 2) inside existing
INL2 authenticated IPv4 UDP packets. **IN40, INL2, IM50 and IE60 wire formats remain unchanged.**
The server never needs to parse IO70 or possess the recipient's X25519 secret.

Each object contains between 1 byte and 1,048,576 bytes of **SYNTHETIC:**-prefixed
content. The v0.7.0 research implementation uses 661-byte maximum plaintext *data*
chunks; each is encrypted separately to the recipient and signed by the sender using IE60.
This design is intentionally inefficient for multi-megabyte production transfer. It is a
bounded milestone toward a genuine universal transit layer, not bulk streaming.

## IO70 record (inside IE60 decrypted plaintext)

| Byte offset | Length | Value |
| --- | ---: | --- |
| 0 | 15 | `53 59 4e 54 48 45 54 49 43 3a 49 4f 37 30 01` (`SYNTHETIC:IO70`, then version 0x01) |
| 15 | 16 | high-entropy object transfer ID |
| 31 | 4 | chunk index, unsigned big-endian, starting at zero |
| 35 | 4 | total chunk count, unsigned big-endian |
| 39 | 4 | total object bytes, unsigned big-endian |
| 43 | 32 | SHA-256 digest of complete original object |
| 75 | 1–661 | data bytes (exact size per index) |

The total number of chunks MUST equal `ceil(total_object_bytes / 661)` and MUST NOT exceed
1,587. A chunk's length MUST equal `min(661, total_object_bytes - index*661)`.
All records for a transfer MUST carry identical metadata, sender identity and recipient
identity. A recipient MUST reject conflicting duplicate chunks.

The corresponding 16-byte IM50 message ID is:
`SHA256(ASCII("INNERnet/IO70/chunk-id") || 0x00 || transfer_id || uint32be(index))[0:16]`.
Each message ID is bound into the signed IE60 envelope, so envelope and IO70 frame are
cryptographically associated. A recipient MUST verify sender IE60 signature, recipient,
message ID, IE60 validity period, chunk schema, and eventual whole-object SHA-256.

## Receipt and recovery semantics

- **STORE**: relay committed this IE60 ciphertext to its SQLite journal. This DOES NOT mean
  the recipient has downloaded the chunk, verified the complete object, or decrypted it.
- **ACK/CONSUMED**: recipient stored an authenticated plaintext chunk in its local SQLite
  checkpoint. This DOES NOT mean that the whole object was reconstructed successfully.
- **COMPLETE**: recipient has all indexed chunks in the local checkpoint; a separate
  SHA-256 assembly verification is REQUIRED before exposing the reconstructed output.
- Sender may retry IM50 STORE with the same signed envelope and message ID after uncertain
  acknowledgement. Existing mailbox SQLite deduplication handles repeated submissions.
- Recipient persists the validated chunk locally *before* sending the server ACK; repeated
  FETCHes following uncertain ACKs are accepted only if chunk data is identical.
- Client reuses an authenticated IN40/INL2 session for no more than 100 sequential mailbox
  RPCs or 50 seconds, then performs a new pinned X25519 handshake. A failed RPC retries
  a byte-identical ciphertext before one fresh-session retry with the same request ID.

## Trust/security boundaries

Server stores IE60 ciphertext only when `--require-e2ee` is enabled; it still knows
sender identity, recipient identity, timing, encrypted payload size and number of chunks.
Object plaintext lives on sender and recipient devices, including their locally secured
SQLite checkpoint. Signed routes are operator-published and **not** decentralized
consensus. There is no independent cryptographic audit, group identity recovery,
autonomous inter-node forwarding, NAT traversal, multi-node replication, live media
streaming, programmable congestion control, durable remote sharding or WAN IO70 test yet.

## Explicit denial-of-service limits

- Maximum object: 1 MiB. Maximum chunks: 1,587. Maximum plaintext data chunk: 661 B.
- Existing mailbox journal capacity defaults to 2,000 stored records. Operators must
  plan space/expiry and avoid mixing many complete large objects in one test mailbox.
- No automatic skip over corrupted inbox head items; invalid envelopes fail closed.
- Network protocol has no advertised exactly-once delivery guarantee.
- No raw real-world customer content: require `SYNTHETIC:` test-data prefix.

See `docs/TEST_VECTORS_IO70.json` for deterministic plaintext/chunk-ID conformance values.

## Performance caveat

The first IO70 implementation uses **sequential request/receipt** exchanges even
though it reuses session handshakes. At ~150 ms WAN RTT this can make a 1 MiB
transfer take many minutes, especially including recipient fetch + ACK. The
existing receiver's time-limited operation must be considered for WAN tests.
Future IO71+ work needs a bounded selective-ack pipeline, congestion control,
larger authenticated frames or an alternative stream transport. The measured
8.914-second localhost run is **not** a WAN performance expectation.
