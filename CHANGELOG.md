# Changelog

## Unreleased: IRM-1 resource market, draft M1a (after v1.0.0)

### Payout contracts enforced, phone wallets, real USDC by default

- Every listed machine must be paid through a payout contract created by the INNERNET factory. A plain wallet address, or a contract from elsewhere, is refused when applying, an admin cannot list it by hand, and a listed machine whose payout is not a valid split is suspended automatically (it returns once the payout is fixed and its checks are good). Approval waits when the chain cannot be checked, instead of letting the machine through. Verdicts are kept 6 hours.
- The refusal explains what to do: where to create the contract, that it is one transaction approved in the receiving wallet, and that the network fee (about $0.01 in ETH on Base) is paid by that wallet.
- Phone wallets: setup and payout pages offer "Use the wallet app on my phone". The page shows a WalletConnect QR code (a link on phones); the owner approves the connection and the transaction in their wallet app. No browser extension needed. Enabled with `INNERNET_WALLETCONNECT_PROJECT_ID`; the bundle is served from the registry (`static/walletconnect.js`).
- Real USDC is the default: the setup page, payout page and the provider program (`start --network`, `init --network`) choose Base; Base Sepolia stays available with `--network base-sepolia`. Browser wallets missing Base get it added. Website and API docs say real USDC on Base, in beta.
- Out of beta: no payment or credit limits by default. Optional limits come back with `INNERNET_MAX_PAYMENT_USDC` / `INNERNET_MAX_CREDIT_USDC` (the old `INNERNET_BETA_*` names are gone).
- Name: INNERNET in all visible text (signature domains and file formats are unchanged).
- `provider/LATEST` is `provider-v0.6.7`.

### Forgot your key, one logo everywhere, housekeeping

- Forgot your key: a machine can keep its encrypted key backup with the registry (setup page "Also keep the encrypted backup with INNERnet", or `innernet-provider backup`). The upload is signed by the machine (`backup-store` intent, target = SHA-256 of the file); the registry checks the format and that the file belongs to that machine, and cannot open it. `/registry/recover`: sign in, choose the machine, type the passphrase; the browser opens the backup itself (PBKDF2-SHA256 600000 + AES-GCM) and offers the backup file or the key. Links from the sign-in box, the lost-key card and the website footer.
- Website: "Log in" for providers in the header of every page (also on phones) and "Forgot your key?" in the footer; copy updated for website setup, the background service, home connections, mainnet beta and compute.
- New mark and favicon on every website and registry page; social preview image and Apple touch icon redone.
- Admin delete keeps the owner's account (passkeys, sign-in, other machines) when other machines are linked to it, and also removes the machine's account link and kept backup.
- `/v1/stats`: real (Base) and test (Base Sepolia) USDC totals are reported separately and never added.
- Python client: with no key given, the registry key seen first is pinned in `<home>/registry-key.pin` (trust on first use), so the `/build` example runs as written.
- Dashboard and setup page: an account without machines is told how to add one instead of showing an error.
- `provider/LATEST` is `provider-v0.6.6`.

### Owner accounts, shared payout, automatic states, admin at scale, Base mainnet beta

- Owner accounts: one sign-in, many machines. A machine joins an account when the signed-in owner enters its machine code (dashboard "Add a machine", or the claim page). Every page works per machine (`?m=<id>`). The dashboard opens with a table of all the account's machines (state, online, services, region, uptime, earnings) and shows the chosen machine below. A new passkey made with a machine code starts that machine's own account. Each machine still checks the owner's passkey itself before signing.
- One payout contract for many machines of one account (other accounts are refused). Before crediting a payment, a provider registers it with the registry (`tx-claim` intent); only the first machine may credit a transaction, and payments are attributed to that machine.
- Automatic states: a new machine is listed by itself after `INNERNET_AUTO_LIST_HOURS` (default 24) of checks at 95%+ with a valid payout contract; listed machines below 95% over 7 days are suspended; suspended machines that are back at 95%+ over 24 h get a 24 h trial and are listed again. An admin's suspend or remove holds the machine (`admin_lock`) until "Return to automatic".
- Admin page for many machines: summary tiles; tabs for waiting for approval, machines (search, filters, sorting, paging, select and approve/suspend/remove/return to automatic in bulk), owners, setups never applied, admins and a paged, searchable audit log; a details panel per machine.
- Base mainnet beta: public Base RPC endpoints by default (`INNERNET_RPC_BASE_SEPOLIA`, `INNERNET_RPC_BASE` override); providers check payments on their payout network's RPC. The setup page chooses the network; the payout page deploys and finds contracts on Base too (`?network=eip155:8453`). Limits published in `/v1/config` for mainnet (`INNERNET_BETA_MAX_PAYMENT_USDC` 10, `INNERNET_BETA_MAX_CREDIT_USDC` 50); the client refuses larger payments.
- Dashboard: activity shows free CPU/GPU slots and bandwidth used this month (new presence stat `bandwidth_used_bytes`); the offer card points to Change settings.
- `/build`: no inner scrollbars; tables stack on phones.
- `provider/LATEST` is `provider-v0.6.5`.

### Schedules, settings that remember, lost keys, live market, provider tester

- Change settings starts from what is applied: the last offer applied from the website (all fields), or the current listing.
- Schedule on the setup page: days of the week with times, days of the month, days off. Availability (REG-1) gains optional `monthdays` and `skip`; `weekly` becomes optional (one of the two is required). Uptime still counts only inside the promised hours. A warning when storage is offered with limited hours.
- Dashboard: "Retire this machine (key lost)": leaving, machine code removed, payout contract free; explains restoring from a backup instead.
- `/registry/v1/stats` (public, cached): totals, free capacity, prices, leaderboards (most reliable, cheapest per service), payments in 30 days. Public names only; no addresses, wallets or earnings.
- Website: live market on `/provide/`; new `/build/` page for app builders (what you can use, live prices and capacity, how an app uses INNERnet in seven parts, examples); `llms.txt`; `openapi.json`.
- `python -m innernet2.provider_test <provider|all>`: listed, online, signed answer, response time, 1 MiB storage round trip; with `--credit-tx` and `--wasm`, a paid CPU job with its receipt. `--json`.
- Provider: `code --json`; on Linux, setup reports when lingering is off (the service would stop at logout and not start after a reboot) with the one command that fixes it.
- `provider/LATEST` is `provider-v0.6.4`.

### Setup finishes on the website; the terminal asks nothing

- `start` goes straight to the website (no 1/2 question; `--mode terminal` or `--yes` for agents). Everything is chosen there, including the key backup passphrase and the background service, then **Apply** asks for the passkey. The terminal applies it and exits by itself; no more y/n prompts.
- The passkey signs the exact setup (REG-1-SETUP: offer, service, sealed backup, nonce, time). The machine verifies the WebAuthn assertion itself (ES256, EdDSA, RS256) before signing with its own key, refuses other machines' setups, old ones and replays, and remembers which passkeys may confirm later changes (`passkeys.json`; `passkeys remove` forgets one).
- The backup passphrase is sealed in the browser to a one-time key of the machine (P-256 ECDH, HKDF-SHA256, AES-256-GCM); the registry only carries ciphertext; the backup is written on the machine.
- The website shows each step live (passkey checked, offer signed, backup, service, registry) and then the listing state. New: `/api/setup/confirm`, `/api/setup/progress`, `/v1/connect/progress`.
- `start` on a machine that is already set up shows its status, machine code and setup link, then exits (`--again` to start over). Dashboard → Change settings: the running background service joins the setup (`setup-pending`, `setup-fetch` intent, `/v1/connect/attach`), applies the passkey-confirmed change and restarts with it.
- VPN exit is refused while the machine is reachable only through the HTTPS tunnel (it cannot carry VPN traffic).
- `uninstall --all` tells the registry the machine is leaving before it deletes the key; a payout contract held by a machine that left (or is gone) can be used by the reinstalled machine.
- The setup page tells the owner to confirm in the terminal when the machine still runs an older provider.
- Port keeper: while serving, the machine checks its port every 10 minutes, after network changes and when the registry could not reach it; it reopens the port on the router, falls back to the HTTPS tunnel by itself when it stays closed, and goes back to direct as soon as the port works. Relays are used only with `--via relay`. The setup page says why it is on the tunnel and has Test again (`/api/setup/reach`, `/v1/connect/facts`).
- `uninstall` removes the router mapping and the firewall rules that setup added (`firewall-rules.json`).
- The setup page says why VPN exit is off (HTTPS tunnel, or not reachable) and how to turn it on.
- Super-admin page `/registry/admin` (sign in with `INNERNET_ADMIN_USER` / `INNERNET_ADMIN_PASSWORD`, 16+ characters, rate limited; or an admin passkey): approve, suspend, remove or delete machines (frees their payout contract), delete passkeys, log out sessions, audit log.
- `provider/LATEST` is `provider-v0.6.3`.

### VPN exit (VPN-1) under Bandwidth; installs and updates from innernetcorp.com

- Bandwidth is one group with a shared monthly GiB limit: **Relay** (sealed INNERnet traffic) and **VPN exit** (clients' TCP connections reach the internet from the provider's connection), each priced per GiB. VPN exit is opt-in and needs the owner's consent ("allowed to offer internet exit where I operate; accept the abuse policy"); web only by default, or every port except 25.
- The exit refuses private, loopback, link-local, carrier-grade NAT, multicast and reserved destinations (no access to the owner's network, router or cloud metadata) and port 25; charges each MiB from the client's credit as it flows; stops at the credit or monthly limit; ends each connection with a signed usage receipt. Client terms must be agreed.
- `python -m innernet2.vpn`: local SOCKS5 proxy, one ST81 session per connection (direct or through a relay). `Provider.open_session()`.
- Provider and client terms: generic VPN exit sections and abuse policy (both fingerprints change: providers agree again, clients send the new fingerprint). Spec 6a.

- Install with `curl -fsSL https://innernetcorp.com/install.sh | sh` (Windows: `irm https://innernetcorp.com/install.ps1 | iex`). The registry serves `/registry/dl/latest` (newest published provider release) and forwards `/registry/dl/<tag>/<file>` and the installers to the release files; the installer and the provider still check every download against the release's SHA256SUMS.
- Providers check innernetcorp.com for updates, with GitHub as the fallback. Registry setting `INNERNET_RELEASE_REPO` names the release repository.
- `provider/LATEST` is `provider-v0.6.1`.

### GPU jobs on WebGPU (llama.cpp removed)

- GPU-1 is now GPU jobs, like CPU jobs: the client sends a JavaScript/TypeScript module that uses WebGPU, with its input; the provider runs it in Deno with no permissions (no files, network, environment or other programs), a time limit and a memory limit, and returns the output with a signed receipt, billed per GPU-hour by the second. Any WebGPU workload fits (AI via ONNX Runtime Web/Transformers.js/WebLLM, image processing, simulation, maths). `/gpu/v1/jobs`; large programs by URL and SHA-256.
- llama.cpp and GPU sessions (`/gpu/v1/sessions`) are removed. Deno comes from PATH (`brew install deno`) or is downloaded and checked against GitHub's SHA-256, in the background when the machine offers GPU.
- GPU detection: Intel and AMD GPUs count too (WebGPU runs on Metal, Vulkan and DirectX); only a card without a working driver is not offered. New `api` values `vulkan`, `directx`.
- Python client: `Provider.run_gpu_job` replaces `gpu_start`/`gpu_chat`/`gpu_end`.
- Tests run real WebGPU compute (a shader doubling numbers) and check that files, network, environment and programs are blocked.
- `provider/LATEST` is `provider-v0.6.0`.

### Machine code (permanent until rekey); setup codes that keep working

- Each machine has a machine code (16 characters, `XXXX-XXXX-XXXX-XXXX`) that stays the same until the owner runs `innernet-provider rekey`. `start` shows it; `innernet-provider code` shows it again. The machine registers only its SHA-256, in a request signed by the machine key (`pairing-set` intent), so only the machine can set or change it.
- On the claim page the machine code opens the machine's waiting setup, or, when the machine is not waiting, adds a passkey and opens the dashboard. It cannot sign or change anything by itself: listings and payouts are still signed and confirmed on the machine.
- `rekey` replaces the code; the old one stops working at once.

- The terminal waits up to 24 hours (it gave up after 31 minutes, which expired the code). The registry renews a code every time its terminal checks in, up to 24 hours after it was made, and expires it 30 minutes after the terminal stops.
- Running `start` again replaces every older code of that machine; the website says plainly whether a code is unknown, replaced by a newer one, expired, or already used.
- Signing in with the machine's passkey opens a waiting setup without any code; the claim page links to it.
- `provider/LATEST` is `provider-v0.5.2`.

### Terms for both sides; storage holdback

- Provider terms and client terms (drafts, to be reviewed by a lawyer), published at `/registry/terms` and `/registry/v1/terms`, each identified by the SHA-256 of its text.
- Providers agree on the setup page (or in the terminal); the machine signs the fingerprint into its listing (`terms` in the provider entry); the registry accepts only the current version. New `innernet-provider terms [accept]`, `init --accept-terms`.
- Clients agree with every payment: `terms` in storage payments and compute credit, signed by the client key; providers refuse payment without the current fingerprint (HTTP 412). `Client(accept_terms=…)`, `Client.client_terms()`.
- Storage holdback: clients hold back 20 % of each payment until the next proof passes and release it with the next payment; providers check the amounts and sign them into tickets; on repair the failed provider's held amount stays with the client (`held_kept`). Spec 4.5, 4.6.
- `provider/LATEST` is `provider-v0.5.1`.

### Compute by the hour: CPU jobs and GPU sessions, prepaid credit

- Providers sell raw power; clients bring the program or model. CPU is priced per CPU-hour (CMP-1 unit changed from instructions), GPU per GPU-hour; both charged per second.
- Credit: a USDC payment to the payout contract becomes a balance on the provider (`/cmp/v1/credit`, `/cmp/v1/balance`), used once; each job holds its maximum and settles to the real cost; signed PAY-1 usage receipts.
- CPU jobs (`/cmp/v1/jobs`): WebAssembly (WASI) in wazero with no files, network or environment, fixed clocks and seeded randomness, so results repeat exactly on any provider; memory and time limits; large modules by URL and SHA-256.
- GPU sessions (`/gpu/v1/sessions`): the client's own GGUF model, downloaded and checked by SHA-256, loaded with llama.cpp on 127.0.0.1; chat requests proxied; billed only while loaded; refunds on failure; cache of recent model files.
- Python client: `credit`, `balance`, `run_job`, `gpu_start`, `gpu_wait`, `gpu_chat`, `gpu_end`, with receipt checks.
- HTTPS tunnel forwards `/cmp/` and `/gpu/` with a longer wait; the provider answers tunnel requests in parallel.
- Setup page: a Compute group (CPU, GPU) and clear checkboxes. Spec 7.7.
- The provider now uses one external Go module, wazero (pure Go, no dependencies of its own).
- Sharing one machine: storage has its own pool; CPU jobs and GPU sessions are admitted against CPU, GPU and memory budgets with memory kept for the owner (`--reserve-gib`); fair queue (fewest running first, no backfilling), per-client cap (`--per-client`), bounded line, immediate 503 + Retry-After when full; new work waits while the owner needs the memory; idle GPU sessions end by themselves; updates drain running work first; live capacity in presence; the client prefers providers with free capacity and moves on when one is busy.
- Client: parallel ST81 sessions per provider instead of one request at a time across all providers.
- `provider/LATEST` is `provider-v0.5.0`.

### Provider updates itself; releases publish themselves

- `start` checks for a newer release first and restarts into it; `serve` checks every 6 hours and restarts into a new release (in place on Linux and macOS, so systemd and launchd keep tracking it; on Windows a new process takes over the port). Downloads must match the release's `SHA256SUMS`. New `update [--check]`; `INNERNET_NO_UPDATE=1` turns it off; development builds never update.
- The release workflow now runs on uploads to `main` that touch `provider/`: when `provider/LATEST` names a version with no release, it tests, builds all six systems and publishes the release. No manual release step.
- `provider/LATEST` is `provider-v0.4.2` (includes the GPU category).

### GPU category (GPU-1), wallet guidance

- `start` detects GPUs on macOS, Linux and Windows with the system's own tools (model, memory, cores, CUDA/Metal/ROCm), shows them in step 1 and reports them to the registry.
- New service **GPU-1**, priced per GPU-hour. The setup page shows the machine's GPUs, offers the best usable one with a count, and shows the market price for that model; the registry refuses a GPU offer the machine did not report. The signed descriptor carries `hardware.gpu_model` and `limits.GPU-1.max_gpus`. Market prices for GPU-1 are grouped by model. Listing only: GPU jobs are not specified yet (spec 7.7).
- Setup page: which wallet to connect (a Base wallet you control, not an exchange deposit address; no keys shared); a reachability line for the HTTPS tunnel.
- Terminal setup no longer says home PCs need a public address.

### ST81 in Go, storage over ST81, relay for machines behind routers, HTTPS fallback

- **ST81 in Go** (`provider/st81.go`): handshake, key pinning, key confirmation, AEAD framing and strict JSON exactly as `stream_v080.py`; conformance-tested against the Python reference in both directions and against the RFC 8439 ChaCha20-Poly1305 vector. ChaCha20-Poly1305 is the pure-Go code from Go's own source tree (`provider/internal/xcrypto`, BSD), so the provider still needs no external modules.
- **Storage over ST81 by default:** `serve` answers ST81 and HTTP on one port (silence means ST81). The client uses ST81 first, pinned to the provider key, reuses sessions, and falls back to HTTP; `INNERNET_TRANSPORT` forces one.
- **RLY-0 relay over ST81:** `innernet-provider relay`; providers attach with an outgoing ST81 session; clients open a stream and run a second, end-to-end ST81 session inside, so the relay sees only ciphertext and cannot impersonate a provider. `deploy/Dockerfile.relay`.
- **HTTPS tunnel fallback** through the registry (`/v1/tunnel/{id}/poll|reply`, `/t/{id}/…`), signed long-polls, path allow-list, size, concurrency and daily budget limits.
- Reachability ladder in `start`: direct → firewall → router → ST81 relay → HTTPS tunnel; `--via relay|tunnel`. After a network change `serve` switches to a relay by itself. Presence carries the path (`relay` with `relay_key`, `tunnel`), and the client follows live presence (signed by the provider) to reach a provider wherever it is.
- The registry confirms relayed providers through the relay, end to end; probes do the same. Its reachability test now speaks first, so it works with the ST81/HTTP port.
- Spec: 3.4b (relay and tunnel), 5.9a (STO-1 over ST81); core spec notes the Go ST81 implementation.
- Tests: Go↔Python ST81 interop, Go relay end to end, client over ST81 with HTTP fallback and impostor refusal, and a full run with a real registry, relay, three relayed providers and one tunnelled provider storing and reading a 4-of-6 file.

### Passkeys: set up again on the same device, lost passkeys

- Website setup on a device that already holds a passkey for the machine no longer fails ("This device already has a passkey"): the page confirms the existing passkey instead (`claim-login` flow; a passkey of another machine is refused). A device without one adds a new passkey as before.
- `start` lists the passkeys that already exist. New `innernet-provider passkeys [remove NAME]`, signed by the machine key (`passkey-list`, `passkey-remove` intents with a `target`); removing logs out every web session.

### Provider 0.3.0: background service, home networks, presence, hours, states, new terminal

- **Background service:** `service install|status|uninstall` (systemd user or system unit, launchd agent, Task Scheduler); offered at the end of `start` (`--service` with `--yes`).
- **Home networks:** when the port is not reachable, `start` offers one firewall rule on the machine (only after the system's own admin prompt), then asks the router to forward the port (NAT-PMP, UPnP IGD; same port outside and inside; renewed by `serve`), then tests again. Carrier-grade NAT is detected and explained. The running service answers the registry's reachability test (`/reach/<nonce>`), so `start` and `status` work while it runs.
- **Presence:** `serve` signs a `REG-1-PRESENCE` record every minute (address, path, usage counters) and follows network changes. The registry confirms new addresses through the provider's signed info, serves the record unchanged at `/v1/presence/{id}`, and probes the provider where it is.
- **Hours and machine type** in the signed offer (`availability`, `class`); probes and uptime count only promised hours.
- **States:** `pause`, `resume`, `leave`, `reinstate` from the terminal (signed `REG-1-INTENT`) or the dashboard; `gone` after 7 days unheard; 24 h trial and automatic re-listing; operator-only `removed`.
- **Market prices:** `/v1/market` (median and range per service and class). Dashboard data now includes presence, usage, market and hours.
- **Terminal:** branded banner, numbered steps with spinner and ✓/✗, offer and summary boxes, `status --watch` live screen and `status --json`; plain output in pipes or with `NO_COLOR`. Installers show a banner and a download progress bar. `uninstall [--all]`.
- Tests: Go tests for service files, NAT-PMP and UPnP against fake routers, gateway parsing, carrier-grade NAT; an end-to-end test with a real `serve` checking in, address confirmation, forged presence refused, pause/resume/leave/reinstate, status, market, and the gone → trial → listed path.

### Client: seal, mix, 4-of-6 shards

- **`innernet-client` now stores files as sealed, mixed shards** (record `IRM1-CLIENT-2`), replacing 3 full encrypted copies: cut into 64 KiB chunks → seal (OB80-2 chunk cipher) → mix 4 KiB cells with a keyed permutation → Reed-Solomon 6 shards, any 4 rebuild → 6 slots on at least 3 providers, at most 2 each, regions first. Storage overhead drops from 3× to 1.5×, losing any one provider still leaves 4 shards, and no provider holds a whole sealed chunk.
- Reads take 4 verified shards per chunk, skipping dead or tampered holders. Repair rebuilds missing shards from any 4 healthy ones (no decryption needed) and places them elsewhere. Checks and payments are per shard holder.
- `put` needs at least 3 working providers and removes partial uploads if placement fails. Records from the earlier draft (`IRM1-CLIENT-1`) are not read.
- Tests: end to end with 4 real Go providers (a provider holding 2 shards goes down, reads continue, both shards rebuilt elsewhere, then one more provider lost), tampered shard, fewer than 3 providers; placement and pipeline unit tests.
- Spec 5.7 and 5.10 updated.

### One-command onboarding, provider service, client (consolidated)

- **One command.** The installer now starts `innernet-provider start`: it creates the machine key, detects the public IP, tests that the port is reachable from the internet (registry dials back to the caller only and must read a random nonce), free disk, CPUs, memory, region (time zone) and name, then asks: website or terminal.
  - Website: signed `REG-1-CONNECT` record → one-time claim code (8 characters, 30 min, single use). New pages `/registry/claim` (code + passkey) and `/registry/setup` (detected values, services, prices, payout contract via the person's wallet). The machine shows the final offer, the person confirms, the machine signs and applies. The web never holds the key.
  - Terminal: same detection; `start --yes --wallet 0x…` for agents and scripts; looks up or waits for the payout contract.
- **`innernet-provider serve`**: STO-1 over HTTP (spec 5.9). Signed requests with nonce and replay cache, one owner per lease, quota, STO-1 Merkle proofs (Go port, identical to the Python reference), signed JSON replies, on-chain USDC payment checks with single use per transaction, PAY-1 tickets.
- **`innernet2/irm_client.py`** (`innernet-client`): put on 3 providers (region diversity), verified reads with failover, daily proofs, pay-after-proof per epoch with ticket verification, repair after 24 h from a healthy replica, registry rollback refusal.
- Registry: `whoami`, `reachability`, `connect`, `connect/status`, `connect/finish`, `split`, claim and setup APIs; dashboard sends machines without an application to setup.
- **Fix (v1.0.0 core):** `routing_v090.SequenceStore.check_and_update` wrote its state file with the process umask (often 0644); the next `SequenceStore()` then refused to load it as not owner-only. It now writes 0600. Regression test added.
- Tests: `tests/test_irm_end_to_end.py` (4 real Go providers + client + fake chain: placement, failover, a provider going down, no payment for failed replicas, repair onto the spare, tampered chunk detection, owner/replay/payment-reuse checks); registry tests for connect/claim/setup and live Go `start` runs in website and agent mode with a real reachability dial-back.
- Docs: spec 5.9 (HTTP binding) and 5.10 (client behaviour); CLI guide rewritten around `start` and `serve`; website guide rewritten around one command.

### Payout split contract, 2.5% fee, provider guide

- **Network fee is now 2.5%** (`fee_bps` 250) everywhere: registry default, contract tests, docs, CLI text and website.
- `contracts/INNERnetSplit.sol`: `INNERnetSplit` (one per provider; `release(token)` sends 97.5% to the provider, rounded down, and the rest to the fee wallet; anyone can call it; no owner; handles tokens with and without a `bool` return; refuses ETH) and `INNERnetSplitFactory` (fixes fee wallet and share, fee capped at 10%, one split per provider at a CREATE2 address, `isSplit` for the registry). Built with solc 0.8.28; `contracts/build.js` reproduces `contracts/build/contracts.json` byte for byte.
- Registry checks payouts against the factory: `isSplit(payTo)`, `feeRecipient()` and `feeBps()` (replaces the code-hash idea, which cannot work with per-split immutables). `admin approve` re-checks the payout. New `GET /registry/v1/config`.
- New page `/registry/payout`: providers connect their own browser wallet, create or find their payout contract, copy the `wallet set` command, and collect payments. Operator deploys the factory once from `/registry/payout#operator`. No keys reach the server.
- Spec: section 4.3 rewritten for the factory; new sections 5.7 (when a provider goes down: replicas, failover, repair, payment stops) and 5.8 (fair metering per service).
- Tests: `tests/test_split_contract.py` (local EVM: create, predict, release maths for several amounts, USDT-style token, ETH refused, constructor guards, registry RPC checks against real and look-alike factories); selector and bytecode sync between contracts, registry and page; reproducible-build check.

### Registry service and dashboard (M1b part 2)

- `innernet2/registry_service`: FastAPI + SQLite service. `apply`, `status`, CLI `login`, signed `registry.json`, `registry-key`. Accepts only networks with a configured fee wallet, checks payout addresses are contracts, rejects payout contracts shared between providers.
- Provider dashboard at `/registry/dashboard`: status, reachability (24 h / 7 d / 30 d), activity per service, 30-day and all-time earnings with the 1% fee, daily chart, every payment with its split and explorer link, offer, passkeys (add, rename, remove), signed-in devices (sign out), activity log. Public page per provider.
- Passkey login (WebAuthn, discoverable credentials) bootstrapped by `innernet-provider login`; one-time link token in the URL fragment; `__Host-` session cookies; CSRF header and Origin checks; strict CSP with nothing inline; per-IP rate limits.
- Payments read from USDC `Transfer` events on Base Sepolia (cursor per payout contract, 5 confirmations). Reachability probes with automatic suspension below 95% over 7 days. Operator commands (`list`, `approve`, `suspend`, `remove`).
- `deploy/Dockerfile.registry`, `docs/IRM1_REGISTRY_SERVICE.md` (Coolify path route `https://innernetcorp.com:8080/registry`). Signing key created on first start in the private volume.
- `tests/test_registry_service.py`: 10 tests, including a software passkey driving real WebAuthn verification, a fake chain, probe suspension, a signed document checked with `verify_registry`, and the Go CLI (`apply`, `status`, `login`) against a live server.
- Installers fall back to `provider/LATEST` when the GitHub API is unavailable or rate-limited.

### Provider CLI (M1b part 1)

- `provider/`: `innernet-provider`, a Go command-line tool with no third-party dependencies, for Linux, macOS and Windows. Commands: `init` (step by step, or `--yes` with flags), `show`, `wallet set`, `apply`, `status`, `login`, `backup`, `restore`, `version`.
- Provider key in `identity.key` (0600, folder 0700); shareable `PROVIDER-DETAILS.txt` holds no secret; encrypted backup with PBKDF2-HMAC-SHA256 (600,000 rounds) and AES-256-GCM.
- `innernet2/irm_registry.py`: `make_login_challenge` and `verify_login` (`REG-1-LOGIN`) for the dashboard passkey bootstrap.
- `tests/test_provider_cli.py`: the Python reference verifies descriptors and login records signed by Go and decrypts Go backups.
- `provider/install.sh`, `provider/install.ps1`: install from GitHub releases with SHA-256 check. `.github/workflows/provider-release.yml` builds six targets on `provider-v*` tags.
- IRM-1 spec: provider portal (section 3.6: status, health, activity, earnings, splits, passkeys, team access) and candidate future services (section 9: MBX-1 mailbox, WIT-1 witness, GW-1 gateway, ARC-1 archive).
- `docs/IRM1_PROVIDER_CLI.md`.

Draft only. Nothing below is part of the v1.0.0 core or a compatibility promise.

- `docs/IRM1_RESOURCE_MARKET_SPEC.md`: draft spec for paid storage, relaying and compute from registered providers over x402, with a non-custodial 1% network fee paid through immutable split contracts.
- `innernet2/irm_registry.py`: REG-1 signed provider registry (pinned keys, ≤24 h validity, anti-rollback via `SequenceStore`, fee-wallet rules), registry key rotation (backup key required), self-signed provider descriptors, quoted-price and payTo checks, PAY-1 signed service tickets. Offline only: no network, payment or chain access.
- `innernet2/irm_storage.py`: STO-1 proof of storage. RFC 6962-style Merkle tree over 1 KiB blocks of each ciphertext chunk; the stored root also commits to the block count. Challenge, answer and check helpers.
- `docs/TEST_VECTORS_IRM1_DRAFT.json` + `tools/create_irm1_vectors.py`: deterministic vectors from fixed synthetic keys.
- `interop/go/irm1verify`: independent Go (standard library only) verifier that re-derives the canonical JSON, all four signature types and the STO-1 root and inclusion proof from the vectors.
- `tests/test_irm1_draft.py`: 29 tests, including the Go cross-check accepting the vectors and rejecting four kinds of tampering.
- Not yet built (M1b): registry HTTP service, provider daemon, x402 payment flow, split-contract verification on Base Sepolia.

## 1.0.0 — pre-tag hardening (2026-11-25, unreleased)

These changes apply to the still-untagged `v1.0.0` core source. They must pass CI on the exact `main` commit before the tag is created (see RELEASE_GATES.md).


- **R90-ROUTE-2 (new profile, additive):** route plans may now carry a mandatory monotonic `sequence` field. A client that verifies with the new `routing_v090.SequenceStore` rejects any plan whose sequence is `<=` the highest already seen from that pinned publisher, giving client-side anti-rollback/replay protection. `R90-ROUTE-1` is retained unchanged for read/forward compatibility and still has **no** anti-rollback (as documented); asking for a `SequenceStore` while handed a ROUTE-1 plan is now an explicit error rather than silent non-protection. See `docs/MIGRATION_ROUTE2.md`.
- **HTTP-v3 chunk key binding (SECURITY.md #1 closed in code):** `crypto.encrypt_chunk`/`decrypt_chunk` now derive the ChaCha20-Poly1305 key from `HKDF(root, "data/aead/v2/" + object_id)` instead of from `root` alone. Reusing a read root across different objects can no longer reuse key+nonce material; it would require a 128-bit object-ID collision. This changes the `inn3_` low-level chunk wire bytes — experimental profile only, excluded from the ST81/OB80-2/R90/UV10 core. `TEST_VECTORS_v0.2.json` regenerated accordingly. OB80-2 core objects are unaffected (they already bind the object ID into the key schedule salt).
- **Test fix:** `tests/test_v038_delivery_quality.py` now launches the probe subprocess with `sys.executable` instead of a bare `python`, so the suite passes inside a virtualenv.
- **CI workflow added (`.github/workflows/ci.yml`):** the repository previously had no GitHub Actions workflow, so the "must pass CI before tag" gate could not actually run. The new workflow runs the manifest check, the Python suite on 3.11/3.12 (which also exercises the Go UV10 verifier), builds the UV10 Go binary, and builds all four Docker images. It establishes none of the still-open gates (independent audit, independent full implementation, provider-outage test).
- Release manifest regenerated.

## 1.0.0 — scoped protocol core software release (2026-11-24)

- Release-supported core: ST81 mutual authentication, OB80-2 recipient-encrypted object transfer, R90-ROUTE-1 signed routing with bounded failover, UV10-1 application container format.
- Free use and redistribution under Apache-2.0.
- Includes the prior RC5 dev4 Revision 2 security fixes and associated tests, including fresh per-upload credentials and strict ST81 JSON.
- Explicit exclusions: HTTP v2/v3 storage and IN40/IN41/IN50/IE60/IO70/mailbox research profiles; full protocol interoperability with independent implementations; R90 plan revocation/rollback protection; open/public ingress DoS guarantees.
- This is a scoped software release, **not a security certification**, production SLA or a declaration that all deployment scenarios are safe.

# Changelog

## 1.0.0rc5.dev4 — clean candidate packaging (2026-11-24)

- Preserved the tested dev4 Revision 2 protocol/runtime source; no cryptographic wire-format change from that reviewed source.
- Consolidated candidate documentation into an accurate root README, SECURITY.md, concise active docs, and explicit release gates.
- Removed legacy alpha release-note and benchmark-report files from the *distribution snapshot*; previous commits and original uploaded archives preserve their history.
- Kept all deployment, CI, benchmarks source, interop, tests, and protocol modules.
- Release manifest regenerated to reflect this source distribution.

**Status remains release candidate.** Green GitHub Actions for the exact cleaned commit and additional external evidence are still required before stable tagging.

## Previous development history

RC5 dev4 Rev2 addresses high-level HTTP-v3 capability reuse by minting fresh per-upload credentials and ordering optional durable persistence ahead of remote writes. It also strengthens ST81 parsing and one-time SQLite backfill behavior. See `docs/RC5_DEV4_REVIEW_REVISION2_AUDIT_DISPOSITION.md` and project Git history for earlier milestones and previous alpha releases.
