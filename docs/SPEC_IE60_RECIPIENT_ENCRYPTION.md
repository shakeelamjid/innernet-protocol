# IE60: Experimental recipient-only mailbox encryption profile

**Status:** v0.6.0-alpha research specification, not an Internet standard or cryptographic audit. Only bounded `SYNTHETIC:` payloads may be used.

## Scope / compatibility

- Outer native datagrams remain **IN40 / INL2** (unchanged). Mailbox requests remain **IM50** path 2 (unchanged). An `IM50 STORE` can now carry an opaque `IE60` ciphertext envelope as its payload.
- Clients use the sender's Ed25519 identity for authenticated transport and an independent Ed25519 signature on the message envelope. Recipients hold a separate X25519 key used to decrypt IE60 messages.
- A signed recipient key bundle can be exchanged out of band. **The sender MUST pin/verify the recipient's Ed25519 identity against a trustworthy channel.** The signed bundle does not prove who owns an identity in the real world.
- The strict-mode mailbox `--require-e2ee` rejects plaintext STORE requests. The old `serve` mode keeps v0.5.0 plaintext behavior for compatibility; the new `compose.mailbox.secure.optin.yaml` enables strict mode by default.

## Public recipient bundle

A JSON object with exactly `payload` and `signature_ed25519` fields. `payload` has exactly `version: IE60-KEY-1`, `identity_ed25519`, `encryption_x25519`, `created_at`, `expires_at`. Public keys are 32-byte hexadecimal. Timestamps are integer Unix UTC seconds. Lifetime is 60 seconds–7 days. The Ed25519 signature covers:

`b"INNERnet/IE60/recipient-bundle\\x00" + canonical_JSON(payload)`

Canonical JSON is ASCII, sorted keys, no whitespace separators, `allow_nan=False`. Verify the signature against the **already pinned** recipient Ed25519 key and reject expired or future-dated bundles.

## Binary envelope

| Offset | Length | Field |
|---:|---:|---|
| 0 | 4 | Magic ASCII `IE60` |
| 4 | 32 | Sender's Ed25519 public key |
| 36 | 32 | Recipient's Ed25519 public key |
| 68 | 16 | Sender-generated stable mailbox message ID |
| 84 | 32 | Ephemeral X25519 public key |
| 116 | 12 | Random ChaCha20-Poly1305 nonce |
| 128 | 8 | `created_at` uint64, big endian |
| 136 | 8 | `expires_at` uint64, big endian |
| 144 | variable | ChaCha20-Poly1305 ciphertext (includes 16-byte tag) |
| last 64 | 64 | Ed25519 sender signature |

Sender computes X25519 `ephemeral_private.exchange(recipient_bundle_x25519)` and derives a 32-byte AEAD key with HKDF-SHA256, `salt=SHA256(header[0:144])`, `info=b"INNERnet/IE60/X25519-HKDF-SHA256\\x00"`. ChaCha20-Poly1305 authenticates the entire 144-byte header as AAD. Sender signs `b"INNERnet/IE60/envelope\\x00" + header + ciphertext` with the sender's Ed25519 private key.

The encrypted payload is **at most 960 bytes** (`MAX_BODY`), with a maximum plaintext of **736 bytes**. This release additionally requires the plaintext begin with `SYNTHETIC:`. The server checks signature, sender/recipient/message ID equality to the authenticated outer STORE parameters, and that the requested store TTL does not extend the signed envelope lifetime. A duplicate ID with different ciphertext is rejected. The recipient verifies the sender signature, identity and message ID, expiry, then decrypts with their private X25519 key.

## Threat model / limitations

- The mailbox database and optional client outbox store **ciphertext** in strict-mode workflows; the server does not receive plaintext message bodies. The server still sees sender/recipient public identities, message IDs, timing, sizes, expiry, online presence and contact relationships.
- **No post-compromise forward secrecy for messages encrypted to the long-lived recipient X25519 key.** An adversary who archives ciphertext and later steals that key can decrypt old messages. Key rotation, deletion guarantees, group encryption, key transparency, deniable authentication, and multi-device support are absent.
- This layer does not secure endpoint devices, prevent traffic analysis, guarantee availability, authenticate physical person identities, or ensure correct independent routing. It does not claim to be a reviewed HPKE or double-ratchet implementation.
- Public E2EE keys and signed static mailbox routes are managed manually. A malicious directory signer can misroute or deny messages; misrouting does not itself reveal plaintext without the recipient key, but impacts availability and metadata.
- A `STORED` receipt indicates SQLite commit on a *single node*; `CONSUMED` indicates recipient application acknowledgement. Neither provides distributed quorum durability or proof of human reading.
- Operators MUST use synthetic data. No production security audit and no true multi-provider deployment verification have been performed.
