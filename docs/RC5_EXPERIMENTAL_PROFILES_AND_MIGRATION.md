# RC5 experimental profiles and migration / operations runbook

**Release:** `1.0.0` scoped core only. All profiles documented here remain **experimental and not included in the v1.0.0 supported core**; this is NOT production approval of these profiles. This document supersedes prior preview defaults. Keep the earlier validated server running until candidate qualification and a rollback rehearsal pass. Do not blindly switch storage, UDP listeners or client keys in place.

## v3 read/admin capabilities and recovery

**Default for NEW mesh uploads is v3**. `inn3_` contains a 32-byte encryption root and administrator's **public** Ed25519 key; `inna_` contains the independently generated random administrator **private seed**. Read token holders can fetch/restore content but MUST NOT sign discovery updates. Administrator secret alone cannot decrypt content. Any v3 repair/record re-publication requires the matching separate administrator capability and configured node write credentials; authorization is checked before fragment upload. New files created via CLI `put` require distinct, new `--cap-out` and `--admin-out` paths; the CLI securely saves both before sending data, to avoid unrecoverable orphaned objects. Operator workflows must copy/back up both **separately**, using encrypted offline backups and permissions 0600, directory 0700. Never log either token. Example:

```
innernet put FILE --peers PEERS.json --writers WRITERS.json --cap-out reader.txt --admin-out owner.txt
innernet get --peers PEERS.json --cap-file reader.txt --out recovered.bin
```

Existing legacy `inn2_` reader tokens also derive record signing authority; this is an intrinsic design limitation. They cannot safely become read-only through an in-place flag. Legacy read/restore remains supported for compatibility, but new v2 uploads must explicitly use `--capability-version 2 --legacy-full-authority`. Migrating an existing v2 object to v3 requires decrypting via v2 and **re-uploading a new object** under a fresh v3 root and admin secret. Verify restore and preserve the original backup until the new v3 object is independently checked. Older clients cannot parse `inn3_` and must be upgraded before receiving it. Do not delete original v2 ciphertext or records until independent recovery is proven.

### HTTP-v3 encryption root: single use is mandatory

`inn3_` and `inna_` remain experimental, **outside the frozen ST81/OB80-2/R90/UV10 core**. For this legacy v3 wire format, each read/encryption root **MUST be used for exactly one new object**. `MeshClient.upload_file` enforces this in its normal API by minting a fresh pair per upload and persisting through a callback after local placement preflight. Direct low-level `encrypt_chunk`/`encrypt_metadata` callers remain responsible for never reusing a root across distinct objects or metadata. If a root was previously reused with different plaintext, treat confidentiality as potentially compromised and re-upload under new credentials. The legacy format cannot be made misuse-resistant by changing authenticated associated data; a future new version identifier such as `inn4_` must bind per-object/salted keys without silently changing existing ciphertext.

## IN40 vs IN41 UDP (experimental)

Legacy IN40 is explicitly **replayable across process restart** and should not be publicly exposed as a secure modern default. IN41 introduces a distinct signed hello with eight-byte big-endian Unix timestamp and ±90-second window, version-separated signing domain and a durable SQLite replay journal with synchronous commits. The journal MUST be configured for IN41, and a journal-configured responder rejects IN40 rather than downgrading. `IN41C` = 5-byte magic + session id16 + ephemeral X25519 key32 + client Ed25519 key32 + pinned target server Ed25519 key32 + nonce16 + timestamp8 + signature64 = **205 bytes**. Signature covers `INNERnet/native-udp/IN41/handshake` + all pre-signature bytes. Reply `IN41S` (5) + session id16 + server ephemeral X25519 key32 + server Ed25519 key32 + signature64 = **149 bytes**. Server signature covers `INNERnet/native-udp/IN41/server-proof` + whole hello + reply prefix. X25519 secret expansion and INL2 AEAD follow `native_udp.py`; neither the journal nor nonce cache proves independence from a compromised allowlisted key.

For isolated research testing, use server CLI `python -m innernet2.native_udp serve --identity SERVER_KEY --allow-client CLIENT_HEX --bind 127.0.0.1 --fresh-replay-db PRIVATE_0700_DIR/journal.sqlite`, and client CLI `python -m innernet2.native_udp probe --identity CLIENT_KEY --server-key SERVER_HEX --host 127.0.0.1 --wire-version 41`. All clients of an IN41-only listener must opt into IN41. Do not share/reuse journals across server identities. Journal deletion or restoration from an old snapshot weakens replay history; do not treat either as a normal clean-up operation. Clocks must be approximately synchronized. IN40 and the native mailbox are still separate experimental transports; they do not transparently upgrade themselves to IN41.

## IN50 mailbox and IE60/IO70 envelopes (experimental)

Mailbox transport occurs inside authenticated INL2 path 2. Strict IE60 end-to-end ciphertext mode is the secure CLI default; legacy plaintext must be deliberately requested and is not suited to untrusted server operation. Wire requests `IM50` (4) + ASCII verb (1) + correlation ID (16) + verb-specific body; response `IR50` (4) + correlation ID16 + ASCII result code1 + body. Standard verbs: S store, F fetch, A consume, R recipient-authenticated reject, Q status, P capability probe. P returns `IN50;cursor-v1;reject-v1`. F accepts empty body for first message or a 48-byte `(sender Ed25519 key32 || message ID16)` cursor. Cursor is recipient-scoped, carries forward through bounded expiry history, and cannot be used to query another user's cursor state. R accepts sender32+message ID16 and only rejects records belonging to the **authenticated recipient**. A and R return `A` or `R` on success; no payload is decrypted by mailbox operator in strict IE60 mode. `Q` includes `R` for rejected when applicable.

To avoid inbox flooding, sender, recipient and pending per-(sender,recipient) quotas apply. `fetch-decrypted` scans by negotiated cursors and can skip undecryptable messages. Destructive rejection is **explicit opt-in** via `--reject-undecryptable` because old-key and rotated-key ciphertext might still be needed. The CLI can resume a scan from the returned `--after` cursor. Without rejection, bad messages are skipped but not deleted. Do not assume deletion from a local client is a proof of malicious sender intent. Old mailbox servers lack cursor/reject negotiation; clients must not assume those features exist. Existing plaintext mailbox databases require a supervised migration or purge after backups; strict mode does not magically encrypt old rows.

## Compatibility table

| Item | New | Legacy accepted | Migration / downgrade rule |
|---|---|---|---|
| ST81 TCP | Challenge, mutual AEAD confirmation | ST80 not accepted | Upgrade both ends together; no fallback |
| OB80-2 | Sender-scoped object ID | OB80-1 read/allowlisted replica path | Do not create new OB80-1 except explicit legacy-forwarding exception |
| V3 HTTP mesh | `inn3_` read + `inna_` admin | `inn2_` full-authority | Re-upload to migrate; preserve both backups |
| IN41 UDP | Signed freshness + persisted journal | IN40 only in separate legacy listener | Server with journal rejects IN40; explicit client selection |
| IN50 mailbox | Cursor-v1 and reject-v1 advertised via P | Empty F and prior verbs | Feature probe required for cursor/reject |
| UV10 | `UV10-1` fixed framing | No unknown extensions | Unknown version and malformed headers rejected |

## Safe deployment sequence / rollback

1. Preserve existing RC5-dev1 server and database volume snapshots. Verify backup *restorability* independently; don't overwrite source volumes or admin secrets.
2. Run full Python+Go tests and a separate-host protocol test against the **exact Git commit** intended to deploy. Record git SHA, binary/image SHA-256, test logs and configuration.
3. Verify all intended recipients' Ed25519 keys out of band. Pin sender identities and R90 publisher keys; no self-declared recipient-bundle trust.
4. For v3 uploads, separately archive both `inn3_` and `inna_` tokens and verify restore plus one authorized repair after restart. Attempting repair with only the reader must fail **before any write**.
5. If enabling IN41, start a separate private-only experimental listener with a private persistent journal; upgrade clients explicitly and verify both success and replay rejection *after restart*. Firewall old IN40 exposure and do not silently downgrade.
6. Qualify actual WAN ST81 authentication, range-fetch, forwarding and failover, simulate whole-host loss on different physical/cloud providers, measure integrity and resource use. The existing single-VPS multi-container demo does **not** count.
7. Rollback: stop new writes; restore matched program version and matching DB backup to an isolated environment. Do not mix new schema and old binaries without a documented migration test. Preserve the original v3 admin token and IN41 journal across restarts. Only reopen production traffic when integrity and identity pins are revalidated.

**Open external gates:** a professional independent cryptographic/security assessment, second independent ST81/OB80/R90 implementation passing common vectors, independent-provider whole-host outage test, and verified CI builds on supported platforms. These cannot be asserted as completed by this local source patch.
