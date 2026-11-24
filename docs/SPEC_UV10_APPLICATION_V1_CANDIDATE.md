# INNERnet UV10-1 — Universal application container candidate specification

Status: **draft wire-level application profile** (`1.0.0-rc1` research candidate).
This document specifies the new application container, **not** a frozen or
independently audited full INNERnet protocol. Normative terms MUST, MUST NOT,
SHOULD apply only within this draft profile.

## Placement

```
Application: message | file | event | finite stream segment
         -> UV10-1 plaintext application container (local 0600 staging)
         -> OB80 signed, recipient-only encrypted object (<=128 MiB)
         -> ST80 authenticated/pinned TCP session
         -> R90 statically configured, signed routing and explicit forwarding
         -> separately authenticated recipient verifies and decrypts
```

Legacy IN40 native UDP small-message transport, IE60 mailbox, and optional PM11
third-party MQTT ciphertext relay remain distinct **experimental** profiles.
UV10 introduces no automatic routing, indefinite realtime streams, group
messaging, transparent VPN, QUIC, account-free secure hosting, or NAT traversal.

## Container framing

All lengths are unsigned, big-endian. The container is:

```
4 bytes  ASCII "UV10"
4 bytes  uint32 length H (2..4096)
H bytes  canonical compact UTF-8 JSON header (sorted keys, ASCII escaping)
N bytes  payload, N = header.size
```

No suffix or additional fields are permitted. The entire file MUST NOT exceed
128 MiB, the OB80 maximum. Header MUST have exactly these fields:

- `version`: `UV10-1`
- `kind`: `message`, `file`, `event` or `stream-segment`
- `content_type`: lowercase `type/subtype` media type, bounded, ASCII
- `name`: safe display basename, 1..100 characters, no slashes, backslash,
  colon, NUL, dot-prefix or parent-directory syntax. The recipient MUST choose
  the actual output path; do not trust a supplied display name as a path.
- `size`: integer payload byte length, nonnegative
- `sha256`: lowercase, 64-character hex SHA-256 digest of the payload
- `created_at`: nonnegative integer Unix UTC timestamp
- `attributes`: object with <=16 ASCII keys (<=40 chars), string values
  (<=160 chars), intended for nonsecurity application labels
- `stream_id`: 16-byte lowercase hex for stream segments, otherwise JSON null
- `sequence`: integer 0..8191 for segments, otherwise null
- `final`: JSON boolean for segments, otherwise null

The header MUST be encoded using canonical sorted-key compact JSON with
ASCII escaping and NaN forbidden. Readers MUST check declared payload length,
exact end-of-file, canonical header, payload digest, and all resource limits.

`message` MUST be UTF-8 bytes and <=65,536 bytes. `event` MUST contain a JSON
value and be <=65,536 bytes. Files are arbitrary bytes. A stream is a finite
series of segments sharing a stream ID and media type, with unique contiguous
indexes starting at zero and **exactly one final marker on the last segment**.
A receiver assembling a stream MUST reject gaps, duplicates, mixed types,
missing final and output-size-limit violations. There is no live playback or
latency contract. The finite segment set is an application-level convention.

## Trust and delivery

A UV10 checksum alone offers **no source authentication**. Recipients MUST
validate the enclosing OB80 sender-signed manifest, explicitly pin the sender
identity when known, authenticate recipient-side chunk AEAD tags, verify the
sealed whole-object digest, and use a signed R90 route with a pinned publisher.
Relay storage commitments do not mean the recipient consumed the object.

**UV10 staging files are plaintext**. Writers use mode 0600 and never silently
overwrite output. A local attacker with access to staging or a compromised
endpoint can read it; filesystem permission guarantees are OS-dependent.

## Compatibility and extensions

- Unknown `version`, `kind`, extra or absent required fields: **reject**.
- Unknown ST80 capability: ignore only when optional; never downgrade away
  pinned identity verification or recipient encryption.
- `get-range-v1` is an optional v0.11 read optimization. Fallback to legacy
  `get` is permitted because both paths validate identical OB80 ciphertext.
- Compatible future extensions MUST use a different version identifier and
  ship both positive and negative test vectors.
- A stable v1.0 requires independent full-stack ST80/OB80 implementation and
  adversarial cryptographic review. This draft does not satisfy those gates.

## Conformance vectors

`docs/UV10_TEST_VECTOR.json` contains exact deterministic application bytes,
header and SHA-256. Python encoder/decoder and independent Go verifier check
these bytes. The Go example **does not implement OB80, ST80 or R90**.
