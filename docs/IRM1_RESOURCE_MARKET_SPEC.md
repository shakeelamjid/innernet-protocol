# IRM-1: INNERnet Resource Market (draft)

**Status:** Draft for review. Not implemented. Not part of v1.0.0. Nothing here is a compatibility promise until it ships with test vectors and passes CI.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Purpose

IRM-1 lets anyone rent out **storage**, **bandwidth** (relaying) or **compute** to INNERnet users, and get paid per use in stablecoins over x402. It adds four pieces on top of the v1.0.0 core:

| Profile | What it adds | Builds on |
|---|---|---|
| `REG-1` | Signed provider registry published by innernetcorp.com | R90 signing and anti-rollback |
| `PAY-1` | x402 payments with a non-custodial 1% network fee | x402 v2 |
| `STO-1` | Paid storage of OB80-2 pieces, with proof-of-storage challenges | OB80-2, ST81 |
| `RLY-1` | Paid relaying between peers that cannot connect directly | ST81 |
| `CMP-1` | Paid compute: deterministic jobs, verified by replication or hardware attestation | OB80-2, UV10 |

### 1.1 Principles

1. **The protocol stays free.** Using your own servers, or any server you trust, needs no registry, no payment and no fee. IRM-1 only applies when a client chooses a *registered* provider.
2. **No custody.** INNERnet never receives, holds or forwards a provider's money. The 1% fee is split on-chain at the moment of payment (section 4.3).
3. **No token.** Payments are in existing stablecoins (USDC first). IRM-1 creates no coin, share or governance right.
4. **Fail closed.** A client that cannot verify the registry, a price, a proof or a payment requirement MUST NOT pay.
5. **Honest limits.** Each service states what the provider can and cannot see (sections 5.6, 6.5, 7.6).

### 1.2 Non-goals for IRM-1

- Anonymity. Providers and the registry see which client keys use which services.
- A blockchain of our own, consensus, staking or slashing.
- Running arbitrary non-deterministic programs (servers, browsers, long-lived processes).
- Guaranteeing availability. Clients get durability by replicating across providers (R90), not from any single provider's promise.

## 2. Roles

| Role | Who | Holds |
|---|---|---|
| **Client** | Anyone storing, relaying or computing | Its INNERnet identity keys and a pinned registry key |
| **Provider** | Anyone renting out capacity | Its ST81 identity key, service endpoints, a payout split contract |
| **Registry** | innernetcorp.com | The registry signing key; publishes the signed provider list |
| **Facilitator** | Any x402 facilitator the provider chooses | Verifies and settles x402 payments on-chain |
| **Fee wallet** | The INNERnet project | Receives the 1% fee directly from split contracts |

A provider's identity **is** its ST81 Ed25519 key. The registry never issues identities; it only lists keys it has checked.

## 3. REG-1: signed provider registry

### 3.1 Distribution

The registry publishes one document at `https://innernetcorp.com/registry/v1/providers.json` and mirrors it in the protocol repository releases. Every client build ships with the registry's public key(s) pinned. Clients:

- MUST verify the signature against a pinned key before using any entry.
- MUST keep a per-registry-key `SequenceStore` (as in R90-ROUTE-2) and reject any document whose `sequence` is less than or equal to the highest already accepted.
- MUST reject documents past `expires_at`. Validity windows SHOULD be 24 h or less, so delisting takes effect within a day even without rollback protection.
- MAY fetch the document over any channel (HTTPS, a mirror, a peer). Trust comes from the signature, not the transport.

### 3.2 Document format

Canonical JSON, signed exactly like R90 plans, with its own domain string `INNERnet/REG-1/provider-registry\0`.

```json
{
  "payload": {
    "version": "REG-1",
    "sequence": 1842,
    "issued_at": 1764067200,
    "expires_at": 1764153600,
    "fee_bps": 100,
    "fee_payto": { "eip155:8453": "0x...fee wallet..." },
    "providers": [
      {
        "id": "<ST81 Ed25519 public key, hex>",
        "name": "example-provider",
        "region": "eu-central",
        "endpoints": [{ "host": "node1.example.net", "port": 9443 }],
        "services": ["STO-1", "RLY-1"],
        "payto": { "eip155:8453": "0x...split contract..." },
        "prices": {
          "STO-1": { "asset": "USDC", "unit": "GiB-day", "amount": "0.0010" },
          "RLY-1": { "asset": "USDC", "unit": "GiB", "amount": "0.0050" }
        },
        "limits": { "STO-1": { "max_object_mib": 128, "max_days": 365 } },
        "listed_at": 1763980800,
        "reputation": { "proof_pass_rate_30d": "0.998", "uptime_30d": "0.995" }
      }
    ]
  },
  "registry_key": "<hex>",
  "signature": "<hex>"
}
```

Rules:

- Amounts are decimal strings, never floats.
- `fee_bps` is basis points (100 = 1%). The registry reads it from its `INNERNET_FEE_BPS` environment variable at publish time.
- `fee_payto` maps a CAIP-2 network id to the fee wallet. Base mainnet is `eip155:8453`; Base Sepolia testnet is `eip155:84532`. The registry reads it from `INNERNET_FEE_PAYTO_<NETWORK>` environment variables (for example `INNERNET_FEE_PAYTO_BASE`).
- A provider MUST NOT appear unless every `payto` entry passed the split-contract check in section 4.3.
- `reputation` values are informational, measured by the registry's own probes (section 3.4). Clients MAY ignore them.

### 3.3 Joining

1. The provider installs the `innernet-provider` command-line tool (see `docs/IRM1_PROVIDER_CLI.md`) and runs `innernet-provider init`, which generates (or reuses) its Ed25519 provider key and asks step by step what to offer.
2. It deploys its payout split contract (section 4.3) and posts a **self-signed descriptor** (the provider entry above, minus `listed_at` and `reputation`, signed with its own key) to `POST https://innernetcorp.com/registry/v1/apply`.
3. The registry checks, in order: the descriptor signature; that each endpoint answers an ST81 handshake with that key; that each `payto` is a valid split contract (section 4.3); and that the provider passes a probation run of real challenges for each listed service (section 3.4).
4. Only then does the entry appear in the next signed document.

Joining is free. The registry MAY require contact details for abuse handling; those are stored off the signed document.

### 3.4 Probing and delisting

The registry continuously acts as an ordinary paying client against every listed provider: it stores test objects, issues storage challenges, relays test traffic and submits canary compute jobs. A provider is delisted automatically when, over a rolling 7-day window, it fails more than 2% of storage challenges, is unreachable more than 5% of the time, or returns a wrong compute result even once. Thresholds are registry configuration, published in the repository.

### 3.5 Registry key rotation

The registry signs with one active key and pins one offline backup key in every client build. A rotation is a document signed by **both** the old key and the backup key, naming the new key. Clients that see a valid rotation replace the old key and keep the backup. If the active key is compromised, the backup alone MAY sign a rotation; clients MUST then require it to carry a `sequence` higher than any seen.

### 3.6 Provider portal (web dashboard)

Every provider has a page on the portal at `https://innernetcorp.com/providers/<provider id>`. The public part shows the listing state and the signed registry entry. The private part, the dashboard, is reached only after login.

**Login.** The provider key is the root of trust. `innernet-provider login` signs a one-time challenge (`REG-1-LOGIN`, domain `INNERnet/REG-1/provider-login\x00`, bound to the challenge, the provider id, the registry host and an expiry of at most 5 minutes). The registry answers with a one-time link, valid for 10 minutes, where the provider registers a WebAuthn passkey. After that the provider logs in to the web with the passkey alone. A passkey grants dashboard access only; it can never sign a descriptor, a ticket or anything else the protocol relies on.

**What the dashboard shows.**

| Panel | Contents | Source |
|---|---|---|
| Status | `applied`, `testing`, `listed`, `suspended`, `removed`, with the reason and the time of the last check | Registry |
| Health | Reachability, challenge pass rate, relay throughput and compute canary results over 24 h, 7 d and 30 d, against the delisting thresholds of section 3.4 | Registry probes |
| Activity | Active storage leases (count, GiB held), relayed GiB, compute jobs run, per service and per day | Service tickets (section 4.1) and probes |
| Earnings | Gross paid by clients, the 1% network fee and the provider's net, per service, per day and per month, in USDC | On-chain transfer events of the provider's split contract |
| Splits | Every settlement with its transaction hash, the provider share, the fee share and a link to the block explorer | On-chain |
| Settings | Prices, capacity limits and services, edited in the browser and applied after the provider confirms with `innernet-provider apply` (the web never holds the provider key, so it cannot sign a descriptor) | Registry |
| Access | Passkeys (add, rename, revoke), active web sessions (revoke), team members (see below), audit log of every login and change | Registry |

Earnings and splits are read from the chain, not reported by the registry, so the provider can check every number independently. The registry never holds provider or client funds.

**Managing access from the web (later milestone).** The owner can invite team members by e-mail with a role: `viewer` (read-only), `operator` (also edits settings drafts and receives alerts) or `owner`. Only the provider key can change the payout contract or sign a new descriptor; no web role can. Losing every passkey is recovered by running `innernet-provider login` again from a machine that holds the key or its backup.

**Alerts.** The dashboard can e-mail or send webhook alerts when the listing state changes, health approaches a delisting threshold, or a payout contract is found invalid.

## 4. PAY-1: payments and the network fee

### 4.1 Transport

Paid requests use x402 v2 over HTTPS on a provider's payment endpoint (`/irm/v1/...`). The flow is the standard one: the provider answers a request with HTTP 402 and its payment requirements; the client signs a payment authorization and retries; the provider's facilitator verifies and settles; the provider serves the request.

IRM-1 traffic itself (pieces, relay frames, job inputs) still moves over ST81. The HTTPS payment call returns a short-lived **service ticket** that the client presents on the ST81 session:

```json
{ "provider": "<id>", "client": "<client key hex>", "service": "STO-1",
  "lease": "<lease id>", "units": "10.0", "unit": "GiB-day",
  "payment_tx": "<settlement tx hash>", "expires_at": 1764070800 }
```

The ticket is signed by the provider's ST81 key, so the client can later prove what it paid for.

### 4.2 Assets and networks

- First network: **USDC on Base** (`eip155:8453`), with **Base Sepolia** (`eip155:84532`) for all development and the public test phase.
- USDT and other networks MAY be added once a facilitator supports them for x402. Each addition needs its own split-contract check.

### 4.3 The 1% fee: split contracts

x402 v2 pays exactly one `payTo` per request. To take a network fee without INNERnet ever holding funds, a registered provider's `payTo` MUST be a **split contract** with these properties:

1. Two recipients only: the provider's payout address and the registry's `fee_payto` for that network.
2. The fee recipient's share is at least `fee_bps`.
3. **Immutable**: no owner, no admin, no upgrade path, no way to change recipients or shares after deployment.
4. Anyone can trigger distribution, so funds never depend on INNERnet acting.
5. The contract's code matches a published, audited implementation whose code hash the registry checks.

The registry verifies all five on-chain before listing, and re-checks on every publish. Because payment goes to the split contract and the contract pays both parties, the client makes **one** standard x402 payment and INNERnet never takes custody.

Traffic that does not use a registered provider carries no fee.

### 4.4 Pricing

Providers set their own prices in the descriptor. Clients MUST compare the price in the 402 payment requirements with the price in the signed registry entry and MUST refuse to pay if the 402 asks for more.

### 4.5 Refunds and disputes

IRM-1 has no escrow, so it has no automatic refunds. Exposure is kept small by design: storage is paid per epoch (section 5.3), relaying in small prepaid blocks (section 6.3), and compute only for results that verify (section 7.4). A provider that takes payment and fails to deliver loses reputation and, past the thresholds in section 3.4, its listing.

## 5. STO-1: paid storage

### 5.1 What is stored

Providers store OB80-2 ciphertext pieces exactly as v1.0.0 storage nodes do. They never receive keys and cannot read content.

### 5.2 Leases

A client opens a lease for a set of objects, a duration and a price. The client SHOULD place each object on at least **3** independent providers in different regions and list them in an R90 route plan, so losing one provider loses nothing.

### 5.3 Pay per epoch

Rent is paid per **epoch** (default: 1 day) rather than up front. At the start of each epoch the client:

1. issues a proof-of-storage challenge (section 5.4) for that lease;
2. if the proof verifies, pays that epoch's rent over x402;
3. if the proof fails or times out, does not pay, marks the provider failed, and re-replicates the affected pieces to another provider.

A provider MAY delete a lease's pieces after **3** consecutive unpaid epochs. Its descriptor states this grace period.

### 5.4 Proof of storage

The v1.0.0 manifest lists a hash per 64 KiB ciphertext chunk, which would force a provider to send a whole chunk to prove it still has it. STO-1 therefore adds a per-chunk **Merkle tree** over 1 KiB blocks:

- At upload, the client computes the Merkle root of each ciphertext chunk and keeps the list of roots (32 bytes per chunk), signed inside its lease record.
- The tree follows RFC 6962 (leaf = SHA-256(0x00 ‖ "STO-1" ‖ block), node = SHA-256(0x01 ‖ "STO-1" ‖ left ‖ right), split at the largest power of two below n). The stored root is SHA-256(0x02 ‖ "STO-1" ‖ uint32_be(n) ‖ tree root), so it also commits to the block count. Reference code: `innernet2/irm_storage.py`; vectors: `docs/TEST_VECTORS_IRM1_DRAFT.json`.
- A challenge names a lease, a random chunk and a random block index, chosen by the client from a CSPRNG.
- The provider answers with the 1 KiB block and its Merkle path (about 6 hashes).
- The client verifies the path against its stored root. A correct answer costs the provider almost nothing and proves it can read that block now.

Challenging a few random blocks per epoch gives high confidence that a provider has not dropped a meaningful fraction of the data. This is a classic proof-of-retrievability style check; it does **not** use zero-knowledge proofs. Zero-knowledge storage proofs, which would let a third party check a provider without the client's roots, remain a research item (section 10).

### 5.5 Provider obligations

Providers MUST keep pieces bit-exact, answer challenges within the advertised timeout (default 10 s), and MUST NOT share client metadata beyond what the protocol requires.

### 5.6 What the provider can see

The provider sees ciphertext sizes, object counts, the client's key, the client's IP address and access timing. It cannot see content or file names.

## 6. RLY-1: paid bandwidth (relaying)

### 6.1 Purpose

Some peers cannot accept inbound connections (home networks, mobile, strict firewalls). A relay provider accepts ST81 sessions from both sides and forwards frames between them.

### 6.2 End-to-end protection

Relayed traffic MUST stay end-to-end protected between the two real peers. The relay forwards an inner ST81 session inside its own outer session; it never holds the inner session keys. A new relay framing profile is required for this and is part of RLY-1's implementation work.

### 6.3 Metering

The client buys relay credit in small prepaid blocks (default: 100 MiB) over x402 and receives a signed service ticket. The relay counts forwarded bytes against the ticket and stops when it is used up. Small blocks cap what a dishonest relay can take.

### 6.4 Measuring honesty

Both peers count bytes sent and received. If the relay drops traffic, the shortfall shows up as retries and a low delivered-to-paid ratio, which the client reports to the registry's reputation probe. The registry also runs its own relay tests (section 3.4).

### 6.5 What the relay can see

The relay sees both peers' keys and IP addresses, traffic volume and timing. It cannot see content.

## 7. CMP-1: paid compute

### 7.1 Scope

CMP-1 runs **deterministic, sandboxed jobs**: WebAssembly modules (WASI) with no network access, no clock and no randomness except a seed in the job. Same module + same inputs + same seed MUST give the same output bytes. This is what makes results checkable.

Out of scope for IRM-1: GPUs, long-running services, interactive sessions, anything needing network access.

### 7.2 Job format

A job is a UV10 container holding: the module hash, input object hashes (OB80-2 objects or plain public data), resource limits (memory, instruction budget, wall time) and the result recipient key. Outputs are sealed as an OB80-2 object to the client.

### 7.3 Verification modes

Each job picks one:

| Mode | How a wrong result is caught | Cost |
|---|---|---|
| `replicate-k` (default) | Run on *k* independent providers (default 2; 3 for anything important). Accept only when the output hashes match. On disagreement, run on a further provider and treat the minority as faulty. | *k* times the price |
| `spot-check` | Run on one provider; the client or registry re-runs a random fraction (default 10%) itself. | About 1.1 times the price; cheating is caught statistically, not every time |
| `attested` | Run inside a hardware enclave (for example Intel TDX or AMD SEV-SNP). The provider returns a hardware attestation that binds the module hash, inputs and output. | Needs enclave-capable hardware; trust moves to the chip vendor |

### 7.4 Payment

Compute is paid **after** the result verifies: the client pays each provider whose output matched. A provider that returns a mismatching result is not paid, and one proven wrong is delisted (section 3.4).

### 7.5 Limits

Each job states an instruction budget and wall-time limit, and price is per unit of budget. A provider MUST stop a job that hits its budget and return a signed "budget exceeded" result, which is paid.

### 7.6 What the provider can see

**In `replicate-k` and `spot-check` modes, providers see the job's inputs and outputs in plain form while running it.** Encryption protects data in storage and in transit, not while a normal server computes on it. Only `attested` mode keeps inputs hidden from the provider's operator, and then only as far as the enclave hardware is trustworthy. Clients MUST NOT send confidential data to non-attested compute.

## 8. Security and abuse

- **Fake or copy-cat providers (Sybils):** one operator can register many keys. Replication across *different* providers and regions, together with registry probing, limits the damage; it does not prevent it. Clients SHOULD spread replicas across operators that list different contact details and networks.
- **Price bait:** clients refuse any 402 asking more than the signed registry price (section 4.4).
- **Registry compromise:** handled by key rotation (section 3.5) and short validity windows. A compromised registry can list bad providers but cannot read data, redirect fees already split on-chain, or forge payments.
- **Illegal content:** providers store ciphertext they cannot inspect. Each provider is responsible for the law where it operates; the registry SHOULD publish an abuse contact and a takedown process that operates on keys and lease ids.
- **Payment replay:** x402 authorizations are single-use and time-limited; service tickets carry the settlement transaction hash and an expiry.

## 9. Candidate future services (not part of IRM-1)

These fit the same registry, payment and fee model. Each needs a way for a client to check the work before it can be listed.

| Code | Service | What the provider does | How it is checked | Unit |
|---|---|---|---|---|
| MBX-1 | Mailbox | Holds encrypted messages for recipients who are offline and hands them over when they connect (builds on the existing experimental mailbox profile) | Sender receipts and recipient pick-up acknowledgements; storage challenges as in STO-1 | 1,000 messages |
| WIT-1 | Witness | Co-signs "I saw this manifest root or route sequence at time T", which makes rollback and equivocation by a publisher visible | Signatures are public and cross-checked between witnesses | 1,000 signatures |
| GW-1 | Public gateway | Serves objects the owner chose to make public over plain HTTPS, so people without INNERnet software can read them | Registry probes fetch known objects and compare hashes | GiB served |
| ARC-1 | Cold archive | Cheaper long-term storage with slow retrieval (hours) | STO-1 challenges with a longer answer window | GiB-month |

## 10. Research items (not part of IRM-1)

- Zero-knowledge proofs of storage that third parties can verify without the client's Merkle roots.
- Encrypted-data compute (homomorphic encryption, multi-party computation) for small, high-value jobs.
- Wallet- or token-gated access to objects.
- Payment channels or batched settlement for very small relay payments.

## 11. Legal and regulatory notes (not legal advice)

The design is non-custodial on purpose: INNERnet does not receive or hold client or provider funds, and the fee is split on-chain by an immutable contract. Even so, operating a registry that takes a fee on payments may fall under virtual-asset rules where the operator is based, including Pakistan's Virtual Assets Act 2026 and the PVARA licensing regime. Get qualified legal advice before the fee goes live on mainnet. Donations to the project are separate from IRM-1 and buy nothing.

## 12. Delivery plan

| Milestone | Contents | Network |
|---|---|---|
| M1 | REG-1 registry service, `innernet-provider` CLI, provider portal (status, health, earnings, splits, passkey login), STO-1 with Merkle challenges, PAY-1 with split contract, client support | Base Sepolia only |
| M2 | RLY-1 relay framing and metering | Base Sepolia |
| M3 | CMP-1 `replicate-k` and `spot-check`; team access management in the portal | Base Sepolia |
| M4 | Split-contract audit; mainnet launch of STO-1 and RLY-1 | Base mainnet |
| M5 | CMP-1 `attested` mode | Base mainnet |

Each milestone needs test vectors, CI coverage and an update to `docs/RELEASE_GATES.md` before it is called stable. The independent cryptographic audit of the v1.0.0 core remains a prerequisite for recommending any of this for real data.

## 13. Registry service environment variables

| Variable | Meaning | Example |
|---|---|---|
| `INNERNET_FEE_BPS` | Network fee in basis points | `100` (1%) |
| `INNERNET_FEE_PAYTO_BASE` | Fee wallet on Base mainnet | `0x…` |
| `INNERNET_FEE_PAYTO_BASE_SEPOLIA` | Fee wallet on Base Sepolia | `0x…` |
| `INNERNET_REGISTRY_KEY_FILE` | Path to the active registry signing key (mounted secret, never an env value) | `/run/secrets/registry_ed25519` |
| `INNERNET_SPLIT_CODEHASH` | Accepted split-contract code hash(es), comma separated | `0x…` |

Private keys MUST be mounted as files or secrets, never placed in environment variable values or the repository.

## 14. Open questions

1. Which audited split-contract implementation to adopt, or whether to write and audit a minimal one.
2. Default epoch length for storage (1 day proposed) versus facilitator fees per payment.
3. Whether the registry's probe results should be published as open data.
4. Region and jurisdiction labels: self-declared or measured.
