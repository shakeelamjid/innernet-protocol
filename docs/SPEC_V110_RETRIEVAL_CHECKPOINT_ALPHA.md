# v0.11-alpha protocol extension notes

## ST80 range read (capability `get-range-v1`)

A caller must be authenticated as an allowed sender, recipient or configured relay for the signed OB80 object. The `ping` response advertises `get-range-v1`. The request is a usual encrypted ST80 request header with `cmd=get_range`, the signed 16-byte hex `ident`, integer `start` and integer `count`, with `1 <= count <= 4` and `start+count <= signed chunks`.

The response has the same `rid` and status semantics as ST80, plus `start`, `count`, and a binary payload containing precisely the concatenation of individual OB80 ciphertext chunks. The client splits using the signed manifest's sizes: `min(65536, size - i*65536) + 16`. All chunks remain AEAD-encrypted to the recipient; each ciphertext hash remains signed in the manifest. A missing chunk, invalid range or unauthorized caller is rejected. At most four chunks are returned to stay under the ST80 400000-byte frame bound.

Clients can use legacy `get` if `get-range-v1` is not advertised. The on-wire session handshake and AEAD framing remain unchanged. `streaming-fetch-v1` and `quota-v1` are server information capabilities, not new RPCs.

## Recipient checkpoint (local-only, not wire-visible)

`BulkClient.fetch(...,resume_dir=<existing chmod 0700 directory>)` writes ciphertext received from pinned nodes into a per-object SQLite database and tracks immutable chunk indexes. It stores the signed manifest and ciphertext only, not the recipient's X25519 private key or plaintext object. Upon next connection, it requests only missing indexes, using bounded contiguous ranges; when complete it reconstructs to a separate 0600 temporary file and publishes exclusively after all per-chunk and whole-object digest checks. Success removes the owned checkpoint. Failure leaves encrypted cached chunks for a later retry.

The local directory and disk remain part of the trust boundary. Manipulated checkpoints are rechecked during reconstruction. This mechanism is opt-in: ordinary retrieval uses bounded-memory streaming and does not create a durable ciphertext checkpoint.

## Node resource controls (local policy, not new wire framing)

The server can cap active TCP handlers, stored ciphertext payload bytes, and number of signed object records. Quotas are enforced transactionally and idempotent retransmissions do not consume additional quota. Expired records are deleted only through explicit local maintenance; no remote untrusted RPC is provided for deletion. SQLite database overhead/WAL and filesystem free space are not fully bounded by the payload quota.
