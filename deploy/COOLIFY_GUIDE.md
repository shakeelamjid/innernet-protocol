# INNERnet — Optional Experimental Coolify Deployment Pilot

**Purpose:** Run *one* isolated INNERnet storage-node process with a separate **read-only public gateway**. It is not a working VPN, not a storage marketplace, and not a full decentralized network. The original network client needs **at least nine nodes** for default 4-of-6 data plus 2-of-3 metadata. Do not store private or valuable customer data in this pilot.

## 0. Update the existing GitHub repository

This bundle is the **complete source tree**, not only Docker additions.
Use [GitHub Desktop publishing instructions](../docs/GITHUB_DESKTOP_UPDATE.md) when updating the public source repository. Publishing the source is not a production deployment.
The main repository must contain `innernet2/`, `tests/`, `deploy/`,
`compose.coolify.yaml`, `Dockerfile`, `pyproject.toml`, and `.github/` at its root.
Never commit node secrets or Docker volumes.

## 1. Point a test domain

Choose a test hostname, for example `node1.innernetcorp.com` (only if you control the DNS), and create an **A** record to your Contabo IPv4 address. Set an appropriate **AAAA** record only if IPv6 actually works. Configure HTTPS through Coolify's proxy. Do not expose port 9400 on the public firewall.

## 2. Create Coolify resource

- In Coolify choose your target project > **+ New**.
- Select Git repository (private via deploy key or GitHub App; public via HTTPS URL).
- Repository: `shakeelamjid/innernet-protocol`, `main` (the only maintained branch).
- Build strategy: **Docker Compose**.
- Base Directory: `/` (repository root).
- Docker Compose Location: `/compose.coolify.yaml`.
- **Keep Raw Compose OFF**.
- Add Environment Variables in Coolify:
  - `INN_PUBLIC_URL=https://node1.innernetcorp.com` (replace with your actual HTTPS hostname).
  - `INN_NODE_ID=node-contabo-01` (optional; immutable per node identity).
  - `INN_CAPACITY_BYTES=268435456` (optional; 256 MiB initial maximum).
- Under **Domains**, add an HTTPS domain to service **gateway**, internal port **8080**. **Do NOT assign a domain to node**.
- Deploy. Check both node and gateway become healthy. The compose stack exposes no host ports via `ports:`.

**Note:** The gateway configuration is built into its own image, so no repository-preservation runtime bind mount is necessary.

## 3. Confirm it responds

In a browser:

- `https://node1.innernetcorp.com/` -> `INNERnet research node online...`
- `https://node1.innernetcorp.com/.well-known/innernet-node` -> JSON showing node_id, public_key and `public_read: true`
- `https://node1.innernetcorp.com/v2/offer` -> signed pilot offer and capacity

From a terminal:

```sh
curl -fsS https://node1.innernetcorp.com/.well-known/innernet-node
curl -i -X PUT https://node1.innernetcorp.com/v2/fragments/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

The second command must be rejected with **405 Method Not Allowed**. The public gateway must never accept writes in this pilot.

## 4. Test actual read/write without publicly exposing writes

Coolify > node service > Terminal (inside the `node` container):

```sh
python -m deploy.smoke_node
```

This sends a synthetic fragment through the private write API, then downloads and verifies it through the private node. The output contains a SHA-256 digest. You can then GET it from the public HTTPS gateway:

```sh
curl -fsS 'https://node1.innernetcorp.com/v2/fragments/<fragment_sha256>' -o recovered-fragment.bin
```

Its content contains random bytes, so do not expect clean text. The smoke test does not demonstrate an entire file reconstruction or cross-provider redundancy.

## 5. Operational safety

- The experimental `node` service **must stay private** (no publicly routed domain or published host port).
- The public `gateway` allows only GET/HEAD on specific routes, with basic traffic limits.
- Never publish `write.token` or `node.key`; both are stored in the Docker named volume.
- **Do not delete the persistent volume** across redeployments, or the node's identity, signed proofs, and stored fragments disappear.
- Back up the node volume with appropriate access controls. Avoid placing secrets in backups exposed to the web.
- Set host firewall rules so Coolify management is reachable only by administrators; keep packages patched and monitor disk usage.
- This is a laboratory pilot, **not production-safe**. Its write authentication remains one long-lived bearer token, there is no admission/payment/lease system, and it has not been audited.
- One Contabo VM running nine processes would still count as **one failure domain**. A real resilience test requires nodes spread over different providers/regions.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| Repository not visible | Private Git repo not configured via deploy key/GitHub App |
| 502 / No available server | Domain attached to wrong service/port; gateway must receive requests on 8080; inspect health checks |
| Node continuously restarts | Missing or invalid `INN_PUBLIC_URL`, volume permissions, or mismatched node identity/URL |
| Gateway fails to build | Confirm `deploy/Dockerfile.gateway` and `deploy/nginx.conf` are in the Git repository |
| Public PUT succeeds | Stop deployment; public write access has been exposed, check domain routing/proxy configuration |
| Read endpoint 404 | Node has no fragment with that digest; run the internal smoke test |

Coolify references: https://coolify.io/docs/docs/applications/builds/docker-compose and https://coolify.io/docs/applications/configuration/health-checks
