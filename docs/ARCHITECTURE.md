# Architecture overview

**Release candidate core:** ST81 / OB80-2 / R90-ROUTE-1 / UV10-1. These are separate interoperating profiles, not an externally certified universal networking layer.

```
Original sender                         Pinned storage peers                   Recipient
  UV10 pack (plaintext)                   Primary / Replica                     Local output
         |                                    ^                                    ^
  OB80-2 sign + seal ---- ST81 --------->   |                                    |
    sender / recipient pins         ciphertext-only chunks                 |
         |                                    |                 R90 signed plan     |
         +----- copy to replica ------------> | ----- signed route + pin ---------> |
                                                                              verify/decrypt
```

- **Trust roots:** explicit Ed25519 server and sender pins, recipient bundle identity pin, signed R90 publisher key.
- **Data confidentiality:** OB80-2 recipient encryption (X25519 + ChaCha20-Poly1305). Intermediate nodes should see only ciphertext, object metadata and traffic patterns.
- **Durability:** placement and copies are operator-provided. Signed routes and receipts do not guarantee storage availability or independent failure domains.
- **Application formats:** UV10-1 is typed framing; it is **not** encrypted by itself.
- **Side profiles:** HTTP-v2/v3 storage and the IN40/IN41/IN50/IE60/IO70 experimental suite are outside the scoped core release claim.

For normative bytes/limits/verification, use [RC5 core specification](RC5_CORE_PROTOCOL_SPEC.md). For unsupported security guarantees, see [SECURITY.md](../SECURITY.md).
