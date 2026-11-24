# Deployment templates (optional)

**The INNERnet core protocol does not require Coolify or the Contabo host.**

The repository intentionally retains its Compose entrypoints at the root. Their `build.context: .`, Dockerfile paths, and CI commands resolve relative to that location; moving the YAML files without a coordinated path change would break working deployments and validation.

| Root file | Purpose | Stability |
|---|---|---|
| `Dockerfile` | HTTP storage node image | Experimental HTTP profile |
| `compose.coolify.yaml` | Private HTTP node behind public read-only gateway | Experimental; no public write access |
| `compose.lab.coolify.yaml` | Single-VPS synthetic lab | Research only |
| `compose.ssh-tunnel.coolify.yaml` | SSH-tunnel research setup | Research only |
| `compose.native-udp.optin.yaml` | Native UDP sidecar | Experimental; opt-in |
| `compose.mailbox.optin.yaml` | Legacy mailbox pilot | Experimental; insecure/plaintext option; never publish as production |
| `compose.mailbox.secure.optin.yaml` | Secure mailbox trial | Experimental; opt-in |

The `deploy/` folder contains container Dockerfiles, Nginx gateway configuration, and Python lab/operator utilities. See [the Coolify pilot guide](COOLIFY_GUIDE.md) and the [core security scope](../docs/STABLE_CORE_SCOPE_AND_LIMITATIONS.md).

**Do not commit private node keys, bearer tokens, live `.env` files or production databases.** Do not change the live Contabo deployment merely because the public source repository is updated.
