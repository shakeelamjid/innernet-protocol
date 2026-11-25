# R90-ROUTE-2 migration note

`R90-ROUTE-2` is a new, **additive** route-plan profile that adds anti-rollback.
`R90-ROUTE-1` is unchanged and still accepted for read/forward compatibility.

## What changed

ROUTE-2 payloads carry one extra field, `sequence` (unsigned 64-bit integer),
inside the signed payload. The signed field set becomes:

```
{version, sequence, issued_at, expires_at, nodes, routes}
```

Everything else — node/route bounds, expiry window (60..86400 s), future-issuance
tolerance (<=300 s), canonical-JSON signing domain `INNERnet/R90/signed-route-plan\0`,
pinned-publisher verification — is identical to ROUTE-1.

## Publisher

```python
from innernet2 import routing_v090 as r90
payload = {"version": r90.VERSION2, "sequence": 7, "issued_at": now,
           "expires_at": now + 3600, "nodes": [...], "routes": [...]}
signed = r90.sign_plan(payload, publisher_private_key)
```

Increment `sequence` every time you publish a new plan for the same publisher
identity. Never reuse or decrease it.

## Client (anti-rollback enforcement)

```python
store = r90.SequenceStore("~/.innernet/route-seq.json")   # owner-only (0600/0700)
payload = r90.verify_plan(signed, pinned_publisher, sequence_store=store)
# or:
peers = r90.recipient_peers(signed, pinned_publisher, recipient, sequence_store=store)
```

With a `SequenceStore`, a plan whose `sequence` is `<=` the highest already
recorded for that pinned publisher is rejected (`BulkError`). This stops an
attacker who controls the delivery channel from replaying an older but
still-unexpired plan to pin you to retired/compromised nodes.

## Important boundaries

- Anti-rollback is only as strong as the **independent pinning** of the publisher
  key and the integrity of the client-side `SequenceStore` file. It is per-client
  local state, not global consensus: a fresh client with an empty store accepts
  whatever valid sequence it first sees, then only moves forward.
- Passing a `SequenceStore` together with a legacy `ROUTE-1` plan raises
  `BulkError` by design — ROUTE-1 cannot provide rollback protection, so silent
  acceptance would be misleading.
- ROUTE-2 does **not** add revocation. A plan is still valid until its
  `expires_at`; keep validity windows short where that matters.
