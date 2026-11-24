# Independent Go UV10 verifier

This small independent implementation parses UV10 application framing, validates
resource limits and checks the SHA-256 payload digest without importing Python.
It **does not** implement ST80/OB80 decryption, signatures, trust or networking.

```sh
go run ./interop/go/uv10verify /path/to/staging.uv10
```

The input UV10 file contains **plaintext**. Only an OB80 ciphertext transport
protects application bytes in transit and on untrusted relay storage.

A passing check establishes format-level interoperability only; it does not
qualify the entire protocol as independently interoperable.
