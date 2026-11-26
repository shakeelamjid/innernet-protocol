# innernet-provider: provider command-line tool (IRM-1 draft, testnet)

`innernet-provider` lets anyone with a computer or server offer storage, bandwidth or compute to the INNERnet resource market. It works the same on Linux, macOS and Windows, from a terminal. No real money moves yet: payments run on Base Sepolia (testnet) until the M4 milestone.

## Install

Linux and macOS:

```sh
curl -fsSL https://innernetcorp.com/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://innernetcorp.com/install.ps1 | iex
```

The installers find the newest `provider-v*` release through the GitHub API, or, when that is unavailable or rate-limited, from `provider/LATEST` in the repository (update that file with every release). They download the build for your system and refuse to install if its SHA-256 does not match `SHA256SUMS` in the same release. Signed releases (so a compromised GitHub account cannot ship a bad binary) are planned. You can also build from source with Go 1.23+: `cd provider && go build -o innernet-provider .`

## Set up with one command

The installer starts setup by itself (`INNERNET_NO_START=1` installs only). You can also run `innernet-provider start` any time.

1. **Detection.** The tool creates this machine's provider key (it never leaves the machine), then finds out by itself: the public IP (as the registry sees it), whether the chosen port (9443 by default) is reachable from the internet (it listens, the registry connects back and must read a random nonce), free disk, CPUs, memory, region (from the time zone), a name (from the host name), the time zone and the machine type (laptop when it has a battery, server when the public address is on the machine itself, otherwise desktop).
   When the port is not reachable it tries, in order:
   - **The firewall on this machine** (macOS application firewall, ufw, firewalld, Windows Defender Firewall): it adds one allow rule only after you agree, through the system's own admin prompt (sudo or macOS password, Windows "allow changes"), and prints how to remove it.
   - **The router**: it asks the router to forward the port with NAT-PMP or UPnP, keeping the same port outside and inside, then tests again. `serve` renews the mapping while it runs.
   - If the router's own internet address is shared by the internet provider (carrier-grade NAT, the 100.64.0.0/10 range or a private address), opening ports cannot help; it says so.
   - **An INNERnet relay over ST81**: the machine connects out to a relay and clients reach it through that connection, with an end-to-end ST81 session inside, pinned to your key. Works behind any router or ISP.
   - **The HTTPS tunnel**, when only web traffic gets out (some offices and hotels).
   `start --via relay` or `--via tunnel` skips the direct tests. After a network change, `serve` re-tests and switches to a relay by itself if needed.
   When the firewall and the router cannot open the port, `start` falls back to the HTTPS tunnel by itself (relays only with `--via relay`; no traffic goes through a relay otherwise). The setup page says why and offers **Test again**; in the waiting terminal `r` + Enter does the same. The setup page also says why VPN exit is off when it is.

   **Port keeper.** While serving, the machine checks its port every 10 minutes (`INNERNET_PORT_CHECK_SEC`), after every network change and whenever the registry reports it could not reach it. The registry dials the port back; if that fails, the machine asks the router again (NAT-PMP, UPnP) and tests once more, and falls back to the HTTPS tunnel if the port stays closed. On the tunnel it keeps trying, and goes back to the direct connection as soon as the registry reaches the port. Each switch restarts the service with the new path and is announced to the registry at once. A router without NAT-PMP/UPnP, an address shared by the internet provider (CGNAT) or a VPN cannot be opened from the machine; there the tunnel stays.
2. **Website.** Setup finishes on the website; the terminal asks nothing more (agents and power users: `--mode terminal` or `--yes`).

**Machine code.** Every machine has a code such as `K7QM-4XPA-2RHT-9WCN` that stays the same until you run `innernet-provider rekey`; `innernet-provider code` shows it. Enter it at `innernetcorp.com/registry/claim` from any browser: while `start` is waiting it opens the setup, otherwise it adds a passkey and opens your dashboard. Only its SHA-256 is sent to the registry, by the machine itself. Keep it private; it cannot change your listing or payout without your passkey.

**Website.** If the machine code cannot be registered, the terminal prints a one-time code such as `K7QM-4XPA` and a link to `innernetcorp.com/registry/claim`. On the website the person enters the code, adds a passkey (this becomes their login), checks the detected values, picks services and prices, creates the payout contract with their own wallet, chooses a key backup passphrase and whether the machine keeps serving after a restart, agrees to the terms and presses **Apply**, which asks for the passkey.

**What the passkey signs, and what the machine checks.** Apply builds one REG-1-SETUP object (`version`, `provider`, `offer`, `service`, optional `backup`, `nonce`, `issued_at`); the passkey signs SHA-256(`INNERnet/REG-1/setup-offer\0` ‖ canonical JSON). The registry checks the passkey too, then hands the machine the object and the WebAuthn assertion. The machine recomputes the hash, verifies the assertion itself (ES256, EdDSA or RS256) against the passkey's public key, refuses another machine's setup, one older than 2 hours, or one already applied, and only then signs the descriptor with its own key. It remembers the passkeys that confirmed a setup while its terminal was open (`passkeys.json`); changes that arrive later through the background service must be confirmed with one of those. `passkeys remove` also forgets the removed passkey here. Limit: a passkey's public key comes from the registry the first time; a registry compromised at that very moment could slip in its own.

**Key backup from the website.** The machine sends a fresh P-256 public key with its connect record (`seal_key`). The browser seals the passphrase to it (ECDH, HKDF-SHA256 with info `INNERnet/REG-1/setup-seal`, AES-256-GCM with additional data `INNERnet backup passphrase`), so the registry only carries ciphertext; the sealed passphrase is inside what the passkey signs, together with the key it was sealed to. The machine opens it and writes the encrypted backup to `~/.innernet/provider-backup.json` (a dated name if that exists). The backup file never leaves the machine.

**Live progress.** The machine reports each step (passkey checked, offer signed and sent, key backup, background service, registry) and the website shows them as they happen, then the listing state until the machine is listed. The terminal prints the same steps and exits by itself.

**Uninstall takes back what setup changed.** `innernet-provider uninstall` stops the service, removes the router mapping it asked for (NAT-PMP or UPnP) and removes the firewall rules it added (recorded in `firewall-rules.json`; the system asks for the admin password once per rule). A rule it cannot remove is listed with the command to remove it.

**Changing it later.** `start` on a machine that is set up shows its status, the machine code and the setup link, and exits (`start --again` starts over). Open the setup page (Dashboard → Change settings): the background service notices within seconds (`/v1/providers/{id}/setup-pending`), joins with fresh signed facts (`setup-fetch` intent, `/v1/connect/attach`), applies the passkey-confirmed change the same way and restarts with it. The code works while that terminal keeps waiting (the registry renews it on every check-in, up to 24 hours) and stops working 30 minutes after the terminal stops; running `start` again replaces it with a new code, and the website then says the old one was replaced. Someone who already has a passkey for the machine can sign in to the dashboard instead of entering a code. The code is never the key: the website cannot sign anything, and a guessed code cannot change the payout without the owner's passkey.

**VPN exit needs real reach.** A machine that clients reach only through the HTTPS tunnel cannot offer VPN exit (the tunnel carries signed requests, not VPN traffic); the setup page and the registry refuse it until the machine is reachable directly or through a relay.

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

**Transport.** `serve` answers ST81 (INNERnet's own encrypted session protocol) and HTTP on the same port; clients use ST81 first. `innernet-provider relay [--listen :9444]` runs a relay (see `deploy/Dockerfile.relay`).

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
| `passkeys.json` | Public keys of the passkeys allowed to confirm changes from the website | Yes, public keys only |
| `setup-nonces.json` | Setups already applied (refuses replays) | Not needed |
| `../provider-backup.json` | Encrypted key backup made from the website | Copy it somewhere safe |

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

**Updates.** Releases update installed machines by themselves. `start` checks first and restarts into the newest release before it does anything; `serve` checks every 6 hours and restarts into a new release (on Linux and macOS in place, so the background service keeps running). The program is downloaded from the GitHub release named in `provider/LATEST` and must match that release's `SHA256SUMS`, or nothing changes. `innernet-provider update` does it by hand, `update --check` only looks; `INNERNET_NO_UPDATE=1` turns automatic updates off. Development builds never update themselves.

For maintainers: a release is built and published by itself when `provider/LATEST` names a version that has no release yet, so bump it (e.g. `provider-v0.4.3`) in the same upload as the provider changes.

**Bandwidth: relay and VPN exit.** One monthly limit (`--relay-gib`, GiB) covers both. Relay carries sealed INNERnet traffic between INNERnet machines. VPN exit (`--vpn --vpn-consent`, price `--price-vpn` per GiB, `--vpn-all-ports` for every port except 25; default web only) lets clients' traffic reach the internet from your connection: it is off unless you switch it on and confirm you are allowed to offer internet exit where you operate and accept the abuse policy. Private networks (your own LAN and router) and port 25 are never reachable through it. Clients use it as a SOCKS5 proxy: `python -m innernet2.vpn --accept-terms <sha256>`.

**Compute: CPU and GPU by the hour.** Clients bring their own programs and models; you rent out the power. CPU time (`init --compute --cpus 2 --price-compute 0.02`, USDC per CPU-hour) runs clients' WebAssembly jobs with no access to your files or network. GPU time (`init --gpus 1 --price-gpu 0.25`, USDC per GPU-hour) runs clients' GPU programs (WebGPU) in Deno with no access to your files or network: `serve` uses a `deno` already installed (macOS: `brew install deno`) or downloads Deno for your system, checked against GitHub's published SHA-256. Clients pay credit in advance; each job is charged per second and comes back with a signed receipt. `start` shows your GPUs (model, memory, cores, and Metal/Vulkan/DirectX); a GPU shows "no driver" when its driver is missing. Your machine sees what it computes, including clients' programs and data.

**Terms.** Setup shows the provider terms and asks you to agree; your machine signs the version you agreed to into its listing. `innernet-provider terms` shows them; `terms accept` agrees to a new version (then `apply`). Scripts: `init --accept-terms` after reading them. Clients agree to the client terms with every payment.

**Holdback.** Clients may hold back up to 20 % of each storage payment until your next proof passes, and pay it with the next period's payment. If you lose their pieces, they keep it to repair their data elsewhere.

**Many clients at once.** Storage always goes first. CPU and GPU jobs share the CPUs, GPUs and memory you offer; you keep some memory for yourself (`--reserve-gib`, default 4, servers 1) and new work waits while you need it. Each client may run `--per-client` jobs at once (default 2); when the machine is full, clients are told at once and use another provider. Updates wait for running jobs to finish.
