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

## Set up with one command

The installer starts setup by itself (`INNERNET_NO_START=1` installs only). You can also run `innernet-provider start` any time.

1. **Detection.** The tool creates this machine's provider key (it never leaves the machine), then finds out by itself: the public IP (as the registry sees it), whether the chosen port (9443 by default) is reachable from the internet (it listens, the registry connects back and must read a random nonce), free disk, CPUs, memory, region (from the time zone) and a name (from the host name).
2. **Choice.** Website (recommended) or terminal.

**Website.** The terminal prints a one-time code such as `K7QM-4XPA` and a link to `innernetcorp.com/registry/claim`. On the website the person enters the code, adds a passkey (this becomes their login), checks the detected values, picks services and prices, and creates the payout contract with their own wallet. The terminal then shows the final offer, including the payout contract, and asks for confirmation; the machine signs the descriptor and applies. The code is single-use, expires after 30 minutes, and is never the key: the website cannot sign anything, and a guessed code cannot change the payout without the person seeing it in their terminal.

**Terminal.** The same questions with detected values pre-filled. Agents and scripts:

```sh
innernet-provider start --yes --wallet 0xYourWallet [--port 9443]
```

Only the wallet is required. `start` looks up the payout contract for that wallet through the registry; if there is none yet, it prints a one-click link to create it and waits. A machine that is already set up re-applies with its saved settings.

After setup, keep the provider service running:

```sh
innernet-provider serve      # stores pieces, answers storage checks, issues payment receipts
innernet-provider status
innernet-provider login      # dashboard link for a new device
```

Run `serve` under a service manager so it survives restarts, for example a systemd unit with `ExecStart=/home/you/.local/bin/innernet-provider serve` and `Restart=always`.

Other commands: `init` (terminal questions only, also accepts every value as a flag), `payout 0xWALLET` (find or create the payout contract and save it), `wallet set 0xCONTRACT`, `apply [--dry-run]`, `show`, `backup FILE`, `restore FILE`, `version`.

### What `serve` does

`serve` speaks the STO-1 HTTP binding (IRM-1 spec section 5.9) on the configured port:

| Request | Purpose |
|---|---|
| `GET /sto/v1/info` | Public: provider id, prices, payout contract, free space |
| `PUT /sto/v1/leases/<lease>/objects/<object>/chunks/<n>` | Store one ciphertext chunk; replies with its STO-1 root |
| `GET …/chunks/<n>` | Return a chunk to the lease owner |
| `POST /sto/v1/leases/<lease>/challenge` | Prove possession: one 1 KiB block plus its Merkle path |
| `POST /sto/v1/leases/<lease>/pay` | Check a USDC payment to this provider's payout contract on-chain, return a signed PAY-1 ticket |
| `DELETE /sto/v1/leases/<lease>` | Remove a lease |

Every request is signed by the client's Ed25519 key over method, path, body hash, time and a random nonce; replays and requests more than 5 minutes off the clock are refused. The first client to write to a lease owns it. Every JSON reply is signed with the provider key, so both sides keep evidence. Each payment transaction can be credited once. `INNERNET_RPC` sets the JSON-RPC endpoint used to check payments (default `https://sepolia.base.org`).

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
| `INNERNET_RPC` | JSON-RPC endpoint `serve` uses to check payments |
| `INNERNET_NO_START` | Installer: install only, do not start setup |
| `INNERNET_BACKUP_PASSPHRASE` | Passphrase for `backup` / `restore` without a prompt (automation only; it ends up in your shell history and process list) |

Never put the contents of `identity.key`, a wallet seed phrase or any private key in an environment variable, chat, GitHub or the dashboard.

## Status of this tool

Draft. The registry service is in `innernet2/registry_service` (see `docs/IRM1_REGISTRY_SERVICE.md`); until it is deployed, `apply` keeps your signed form and tells you so. `serve` implements storage (STO-1). Relay (RLY-1) and compute (CMP-1) serving follow; until then those offers are listed but not served.
