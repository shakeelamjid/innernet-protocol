# Contracts

| Contract | Purpose |
|---|---|
| `INNERnetSplit` | One per provider. Clients pay it; `release(token)` sends `(10000 - feeBps) / 10000` to the provider (rounded down) and the rest to the network fee wallet. Anyone can call it. No owner, no admin, no upgrade. Works with tokens that return `bool` and with tokens that return nothing (USDT). Refuses ETH. |
| `INNERnetSplitFactory` | Fixes the fee wallet and fee share (capped at 10%). `create(provider)` deploys at most one split per provider at a deterministic address (`predict(provider)`); `isSplit(address)` is what the registry checks. |
| `test/MockTokens.sol` | Test-only tokens. Never deploy. |

Build: `npm ci && node build.js .` writes `build/contracts.json` (solc 0.8.28, optimizer 200 runs, EVM shanghai). The build is reproducible byte for byte.

Status: testnet only (Base Sepolia). The contracts need an independent audit before any mainnet use.
