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

1. **Detection.** The tool creates this machine's provider key (it never leaves the machine), then finds out by itself: the public IP (as the registry sees it), whether the chosen port (9443 by default) is reachable from the internet (it listens, the registry connects back and must read a random nonce), free disk, CPUs, memory, region (from the time zone), a name (from the host name), the time zone and the machine type (laptop when it has a battery, server when the public address is on the machine itself, otherwise desktop).
   When the port is not reachable it tries, in order:
   - **The firewall on this machine** (macOS application firewall, ufw, firewalld, Windows Defender Firewall): it adds one allow rule only after you agree, through the system's own admin prompt (sudo or macOS password, Windows "allow changes"), and prints how to remove it.
   - **The router**: it asks the router to forward the port with NAT-PMP or UPnP, keeping the same port outside and inside, then tests again. `serve` renews the mapping while it runs.
   - If the router's own internet address is shared by the internet provider (carrier-grade NAT, the 100.64.0.0/10 range or a private address), opening ports cannot help; it says so instead of pretending. Relay mode (an outgoing tunnel) is the planned answer.
2. **Choice.** Website (recommended) or terminal.

**Website.** The terminal prints a one-time code such as `K7QM-4XPA` and a link to `innernetcorp.com/registry/claim`. On the website the person enters the code, adds a passkey (this becomes their login), checks the detected values, picks services and prices, and creates the payout contract with their own wallet. The terminal then shows the final offer, including the payout contract, and asks for confirmation; the machine signs the descriptor and applies. The code is single-use, expires after 30 minutes, and is never the key: the website cannot sign anything, and a guessed code cannot change the payout without the person seeing it in their terminal.

**Terminal.** The same questions with detected values pre-filled. Agents and scripts:

```sh
innernet-provider start --yes --wallet 0xYourWallet [--port 9443]
```

Only the wallet is required. `start` looks up the payout contract for that wallet through the registry; if there is none yet, it prints a one-click link to create it and waits. A machine that is already set up re-applies with its saved settings.

At the end `start` offers to keep the provider running in the background (`--service` with `--yes`). Or any time:

```sh
innernet-provider service install    # systemd (Linux), launchd (macOS), Task Scheduler (Windows)
innernet-provider service status
innernet-provider status --watch     # one live screen: listing, service, online, address, hours, uptime, earnings
innernet-provider login              # dashboard link for a new device
```

On Linux a normal user gets a user unit plus lingering (so it keeps running after log-out); root gets a system unit. On macOS the launch agent runs while you are logged in; turn off sleep to stay reachable.

**Hours.** Every offer carries availability hours in the machine's time zone, written like `always` or `mon-fri 21:00-08:00, weekends 00:00-24:00`. Laptops default to `daily 09:00-23:00`. Checks only count inside your hours, so a machine is never marked down for being off when it said it would be. Clients use the hours to place files so that enough pieces are always online.

**While it runs**, `serve` checks in with the registry about once a minute with a signed presence record: where it can be reached right now (it notices network changes and follows them on its own), how (direct or through the router), and usage counters (stored bytes, leases, requests, checks and payments in the last 24 hours). The registry confirms a new address by fetching the provider's signed `/sto/v1/info` from it.

**Pause, leave, come back.**

| Command | Effect |
|---|---|
| `pause` | No new files; what you hold is still served and paid |
| `resume` | Take new files again, or cancel leaving |
| `leave` | Clients move their files away; then the machine can stop |
| `reinstate` | After a suspension (below 95% of promised hours) or 7 days unheard: a 24 hour trial, then listed again |

The same buttons are on the dashboard. Only the operator can reinstate a provider removed for abuse.

**Passkeys are logins; the machine key is the master.** A passkey lives on your device (iCloud Keychain, Google Password Manager, a security key); the registry only keeps its public half, so nobody can show it to you. `start` lists the passkeys that already exist for this machine. On the website, a device that still has one just confirms it; a device without one (new, or the passkey was lost) adds a new one, because the code from the terminal proves you hold the machine. `innernet-provider passkeys` lists them and `innernet-provider passkeys remove NAME` deletes a lost or stolen one, signed by the machine key; removing also logs out every web session.

`uninstall` removes the background service and the program; `uninstall --all` also deletes the key, settings and stored pieces after asking.

Output: colours, spinner and boxes on a terminal; plain text in a pipe or with `NO_COLOR` (or `INNERNET_PLAIN=1`); `status --json` for scripts.

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
| `INNERNET_GATEWAY` | Router address for NAT-PMP, when it cannot be found automatically |
| `INNERNET_NO_PORTMAP`, `INNERNET_NO_FIREWALL`, `INNERNET_NO_SERVICE`, `INNERNET_NO_PRESENCE` | Switch off router mapping, the firewall offer, the background service offer, or presence check-ins (tests, special setups) |
| `INNERNET_BACKUP_PASSPHRASE` | Passphrase for `backup` / `restore` without a prompt (automation only; it ends up in your shell history and process list) |

Never put the contents of `identity.key`, a wallet seed phrase or any private key in an environment variable, chat, GitHub or the dashboard.

## Status of this tool

Draft. The registry service is in `innernet2/registry_service` (see `docs/IRM1_REGISTRY_SERVICE.md`); until it is deployed, `apply` keeps your signed form and tells you so. `serve` implements storage (STO-1). Relay (RLY-1) and compute (CMP-1) serving follow; until then those offers are listed but not served.
