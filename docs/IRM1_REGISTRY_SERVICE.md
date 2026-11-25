# Registry service and provider dashboard (IRM-1 draft, testnet)

The registry is one small Python service (`innernet2.registry_service`). It:

- accepts signed provider forms from `innernet-provider apply` (`POST /registry/v1/apply`);
- checks each provider's reachability every 5 minutes and suspends listed providers that drop below 95% over 7 days;
- reads USDC payments to each provider's payout contract straight from the chain (Base Sepolia first);
- publishes the signed REG-1 registry document (`GET /registry/v1/registry.json`) that clients verify against the pinned registry key;
- serves the provider dashboard at `/registry/dashboard`, with passkey login, plus a public page per provider at `/registry/providers/<id>`.

It never holds funds or provider keys. Payments go from client to the provider's split contract on-chain; the registry only reads them.

## Endpoints

| Method and path | Who calls it | What it does |
|---|---|---|
| `POST /registry/v1/apply` | CLI `apply` | Verify the signed descriptor; accept only networks that have a fee wallet; check the payout address is a contract; store as `testing` |
| `GET /registry/v1/providers/<id>/status` | CLI `status`, public page | State, reason, 7-day reachability, 30-day earnings (public chain data) |
| `GET /registry/v1/providers/<id>` | Public page | The provider's published entry |
| `GET /registry/v1/login/challenge?provider=<id>` and `POST /registry/v1/login` | CLI `login` | Proves the provider key; returns a one-time link (10 minutes) to add a passkey |
| `GET /registry/v1/registry.json` | Clients | Signed REG-1 document with every listed provider |
| `GET /registry/v1/registry-key` | Anyone | The registry public key, for pinning |
| `/registry/api/...` | Dashboard | Passkey enrolment and login (WebAuthn), dashboard data, passkey and session management |

Browser API calls need the `X-Innernet: 1` header and a same-origin `Origin`; session cookies are `__Host-`, `HttpOnly`, `Secure`, `SameSite=Strict`, 12 hours. The one-time link carries its token in the URL fragment, so it never reaches server logs or `Referer` headers, and the page removes it from the address bar at once.

## States

| State | Meaning | How it changes |
|---|---|---|
| `testing` | Applied; reachability is being checked | Operator approves after review (`admin approve`). Automatic approval follows when the provider service and storage challenges ship |
| `listed` | In the signed registry document | Automatically `suspended` below 95% reachability over 7 days (after at least 24 checks) |
| `suspended` | Hidden from clients | Operator approves again once fixed |
| `removed` | Permanently out | A new application needs a new provider key |

Re-applying with the same address and payout contract keeps a listed provider listed (price changes). Changing the address or payout sends it back to `testing`.

## Deploy on Coolify

1. **New resource → Application**, from the `innernet-protocol` GitHub repository, branch `main`.
2. **Build pack:** Dockerfile. **Dockerfile location:** `/deploy/Dockerfile.registry`.
3. **Domain:** `https://innernetcorp.com:8080/registry` (port before path). Coolify routes that path to this app; the website keeps the rest of `innernetcorp.com`. The app works whether or not the proxy strips the `/registry` prefix.
4. **Persistent storage:** a volume mounted at `/var/lib/innernet-registry`. It holds the database and the registry signing key. Back it up.
5. **Health check:** path `/registry/healthz`, port 8080.
6. **Environment variables:**

| Variable | Value | Notes |
|---|---|---|
| `INNERNET_FEE_PAYTO_BASE_SEPOLIA` | your fee wallet's public address | Required: providers can only apply on networks with a fee wallet |
| `INNERNET_RPC_BASE_SEPOLIA` | `https://sepolia.base.org` | Public RPC is rate-limited; a provider such as Alchemy or QuickNode is better once traffic grows |
| `INNERNET_FEE_BPS` | `100` | 1% |
| `INNERNET_REGISTRY_ORIGIN` | `https://innernetcorp.com` | Must match the address bar exactly, or passkeys fail |
| `INNERNET_REGISTRY_RP_ID` | `innernetcorp.com` | Passkeys are bound to this domain |
| `INNERNET_SPLIT_CODEHASH` | leave empty for now | Once the split contract is chosen: its code hash, so only real split contracts are accepted |
| `INNERNET_FEE_PAYTO_BASE`, `INNERNET_RPC_BASE` | **do not set yet** | Mainnet stays off until the split contract is audited and you have legal advice |

Never put a private key or seed phrase in these variables. The registry signing key is created on first start inside the volume (`registry_ed25519`, mode 0600).

7. **Deploy.** The log prints `registry public key (pin this in clients): …`. Keep that value; client builds pin it. It is also at `https://innernetcorp.com/registry/v1/registry-key`.
8. Redeploy the website too: it now redirects `/providers/<id>` and `/dashboard` to the registry and links the dashboard in the footer.

## Operator commands

Run in the registry container (Coolify → the app → Terminal):

```sh
python -m innernet2.registry_service.admin list
python -m innernet2.registry_service.admin approve <provider id>
python -m innernet2.registry_service.admin suspend <provider id> "reason shown to the provider"
python -m innernet2.registry_service.admin remove  <provider id> "reason shown to the provider"
```

## Not yet built

- Storage challenges, relay tests and compute canaries (they need the provider service on the provider's machine); until then, probes are TCP reachability only and listing is approved by hand.
- Split-contract verification by code hash (needs the chosen contract).
- Team access with roles (IRM-1 section 3.6, milestone M3).
- Alerts by e-mail or webhook.
