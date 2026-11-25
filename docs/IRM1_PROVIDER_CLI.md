# innernet-provider: provider command-line tool (IRM-1 draft, testnet)

`innernet-provider` lets anyone with a computer or server offer storage, bandwidth or compute to the INNERnet resource market. It works the same on Linux, macOS and Windows, from a terminal. No real money moves yet: payments run on Base Sepolia (testnet) until the M4 milestone.

## Install

Linux and macOS:

```sh
curl -fsSL https://raw.githubusercontent.com/shakeelamjid/innernet-protocol/main/provider/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/shakeelamjid/innernet-protocol/main/provider/install.ps1 | iex
```

The installers find the newest `provider-v*` release through the GitHub API, or, when that is unavailable or rate-limited, from `provider/LATEST` in the repository (update that file with every release). They download the build for your system and refuse to install if its SHA-256 does not match `SHA256SUMS` in the same release. Signed releases (so a compromised GitHub account cannot ship a bad binary) are planned. You can also build from source with Go 1.23+: `cd provider && go build -o innernet-provider .`

## Set up, step by step

```sh
innernet-provider init                                 # asks name, region, address, what to offer, prices
innernet-provider backup ~/innernet-provider-backup.json
innernet-provider wallet set 0x...                     # your payout contract, created at innernetcorp.com/registry/payout
innernet-provider apply                                # sends the signed form to the registry
innernet-provider status                               # applied, testing, listed; health; earnings
innernet-provider login                                # one-time link to the web dashboard
```

On servers, `init` can run without questions:

```sh
innernet-provider init --yes --name lahore-box-1 --region asia-south --host node1.example.com \
  --storage-gib 200 --relay-gib 500 --compute --cpus 4 --memory-mib 2048
```

What can be offered:

| Service | Code | Price unit | Limits asked |
|---|---|---|---|
| Storage | STO-1 | USDC per GiB per day | GiB offered |
| Bandwidth (relaying) | RLY-1 | USDC per GiB relayed | GiB per month |
| Compute (sandboxed, no network or file access) | CMP-1 | USDC per billion instructions | CPUs and memory per job |

The machine must be reachable from the internet on the port you give. Home computers behind a router will be able to join once relay mode ships.

## Files

Everything lives in `~/.innernet/provider` (`%USERPROFILE%\.innernet\provider` on Windows), or in `INNERNET_HOME` if set. The folder is private to your user (0700).

| File | Contents | Share? |
|---|---|---|
| `identity.key` | Your provider secret key (0600). It is your identity on the network. | **Never** |
| `PROVIDER-DETAILS.txt` | Provider id, address, what you offer, prices, next steps | Yes, it holds no secret |
| `config.json` | Your answers to `init` | Not needed |
| `descriptor.json` | The signed form last sent with `apply` | Yes |

## Identity, backup and logging in again

There are two separate things:

1. **The provider key** (`identity.key`). It signs your registry form and proves who you are. `innernet-provider backup FILE` writes a copy encrypted with a passphrase of at least 12 characters (PBKDF2-HMAC-SHA256 with 600,000 rounds, then AES-256-GCM). Keep that file offline. On a new machine, `innernet-provider restore FILE` brings back the same provider id. Without the key or the backup and its passphrase, the provider id cannot be recovered; you would register again as a new provider.
2. **The web dashboard login** (passkey). `innernet-provider login` signs a one-time challenge with the provider key and prints a link valid for 10 minutes. There you add a passkey (fingerprint, face, phone or security key). After that you log in to the dashboard with the passkey alone, from any device. If you lose every passkey, run `login` again from a machine with the key.

The dashboard shows status, health, activity per service, earnings, the 2.5% network fee and every on-chain split. It can never sign for you: changes to prices or services are confirmed with `innernet-provider apply`. Details: IRM-1 spec, section 3.6.

## Environment variables

| Variable | Meaning |
|---|---|
| `INNERNET_HOME` | Where the provider files live |
| `INNERNET_REGISTRY` | Registry URL (default `https://innernetcorp.com/registry/v1`) |
| `INNERNET_BACKUP_PASSPHRASE` | Passphrase for `backup` / `restore` without a prompt (automation only; it ends up in your shell history and process list) |

Never put the contents of `identity.key`, a wallet seed phrase or any private key in an environment variable, chat, GitHub or the dashboard.

## Status of this tool

Draft. The registry service is in `innernet2/registry_service` (see `docs/IRM1_REGISTRY_SERVICE.md`); until it is deployed, `apply` keeps your signed form and tells you so. The provider service daemon that actually serves storage, relay and compute arrives with M1 part 2.
