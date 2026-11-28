"""Read USDC payments to provider payout contracts straight from the chain (JSON-RPC).

The registry never holds funds. It only reads public Transfer events, so every number
on the dashboard can be checked on a block explorer.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.request
from decimal import Decimal
from typing import Callable

from .config import EXPLORER_TX, USDC, Settings
from .store import Store

log = logging.getLogger("innernet.registry.chain")
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
CHUNK = 2000            # blocks per eth_getLogs call (public RPCs cap the range)
CONFIRMATIONS = 5
MAX_CHUNKS_PER_RUN = 50
DECIMALS = Decimal(10) ** 6

Rpc = Callable[[str, str, list], object]


def http_rpc(url: str, method: str, params: list):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    # Public RPC endpoints behind CDNs refuse the default "Python-urllib" agent; name ourselves.
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "Accept": "application/json",
                                                          "User-Agent": "innernet-registry/1.0 (+https://innernetcorp.com)"})
    with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - URL comes from operator config
        reply = json.loads(resp.read(4 << 20))
    if "error" in reply:
        raise RuntimeError(f"{method}: {reply['error']}")
    return reply["result"]


def _topic_address(address: str) -> str:
    return "0x" + "0" * 24 + address[2:].lower()


# Function selectors (keccak-256 of the signature), from contracts/build/contracts.json.
SEL_IS_SPLIT = "8b8f5031"       # isSplit(address)
SEL_FEE_RECIPIENT = "46904840"  # feeRecipient()
SEL_FEE_BPS = "24a9d853"        # feeBps()
SEL_SPLIT_OF = "41890891"       # splitOf(address)
SEL_PREDICT = "901b96e7"        # predict(address)


def _call(rpc: Rpc, url: str, to: str, selector: str, arg: str | None = None) -> int:
    data = "0x" + selector + (("0" * 24 + arg[2:].lower()) if arg else "")
    out = rpc(url, "eth_call", [{"to": to, "data": data}, "latest"])
    if not isinstance(out, str) or len(out) < 66:
        raise RuntimeError("short eth_call result")
    return int(out[2:66], 16)


def is_wallet_code(code) -> bool:
    """A wallet, not a contract: no code, or only an EIP-7702 delegation (0xef0100 + address), which
    "smart" wallets such as Trust Wallet or MetaMask set on an ordinary account."""
    c = str(code or "0x").lower()
    return c in ("0x", "0x0", "") or (c.startswith("0xef0100") and len(c) == 2 + 2 * 23)


def split_of(settings: Settings, network: str, wallet: str, rpc: Rpc = http_rpc) -> str | None:
    """The payout contract the factory created for wallet, or None."""
    factory, url = settings.split_factory.get(network), settings.rpc.get(network)
    if not factory or not url:
        return None
    value = _call(rpc, url, factory, SEL_SPLIT_OF, wallet)
    return None if not value else "0x" + format(value, "040x")


def predict_split(settings: Settings, network: str, wallet: str, rpc: Rpc = http_rpc) -> str | None:
    """The address the factory gives wallet's split, before or after it is created (CREATE2)."""
    factory, url = settings.split_factory.get(network), settings.rpc.get(network)
    if not factory or not url:
        return None
    value = _call(rpc, url, factory, SEL_PREDICT, wallet)
    return None if not value else "0x" + format(value, "040x")


def factory_terms(settings: Settings, network: str, rpc: Rpc = http_rpc) -> dict | None:
    """The factory's fixed fee share and fee wallet, read from the chain."""
    factory, url = settings.split_factory.get(network), settings.rpc.get(network)
    if not factory or not url:
        return None
    return {"factory": factory, "fee_bps": _call(rpc, url, factory, SEL_FEE_BPS),
            "fee_to": "0x" + format(_call(rpc, url, factory, SEL_FEE_RECIPIENT), "040x")}


def payout_check(settings: Settings, network: str, address: str, rpc: Rpc = http_rpc) -> tuple[bool, str]:
    """Return (ok, note). A payout must be a split created by the configured factory,
    paying the configured fee wallet the configured share."""
    url = settings.rpc.get(network)
    if not url:
        return True, "payout contract not checked: no RPC configured for this network"
    try:
        code = rpc(url, "eth_getCode", [address, "latest"])
        how = (f"Create it at {settings.origin}{settings.prefix}/payout: enter the wallet that should receive your "
               "earnings and approve one transaction in your wallet app (phone or browser). The network fee is about "
               "$0.01 in ETH on Base, paid from that wallet. Then set the contract address in Change settings.")
        if is_wallet_code(code):
            return False, f"{address} is a wallet, not a payout contract. Payments must go through a payout contract. {how}"
        factory = settings.split_factory.get(network)
        if not factory:
            return True, "payout is a contract; split check pending (split factory not configured yet)"
        if _call(rpc, url, factory, SEL_IS_SPLIT, address) != 1:
            return False, f"{address} was not created by the INNERNET payout factory. {how}"
        fee_wallet = settings.fee_payto.get(network, "")
        if _call(rpc, url, address, SEL_FEE_RECIPIENT) != int(fee_wallet, 16):
            return False, "payout split pays the network fee to a different wallet"
        if _call(rpc, url, address, SEL_FEE_BPS) != settings.fee_bps:
            return False, "payout split uses a different fee share than this registry"
        return True, ""
    except Exception as exc:  # network trouble must not reject an application outright
        log.warning("payout check failed for %s: %s", address, exc)
        return True, "payout contract check postponed: RPC unavailable"


def scan_once(store: Store, settings: Settings, rpc: Rpc = http_rpc) -> int:
    """Pull new USDC transfers into every provider's payout address. Returns rows added."""
    added = 0
    targets = {}
    for p in store.providers():
        if p["state"] == "removed":
            continue
        for network, payto in p["entry"]["payto"].items():
            if network in settings.rpc and network in USDC:
                targets[(network, payto.lower())] = p["id"]
    latest_cache: dict[str, int] = {}
    block_ts: dict[tuple[str, int], int] = {}
    for (network, payto), pid in targets.items():
        url = settings.rpc[network]
        try:
            if network not in latest_cache:
                latest_cache[network] = int(rpc(url, "eth_blockNumber", []), 16)
            head = latest_cache[network] - CONFIRMATIONS
            row = store.one("SELECT next_block FROM chain_cursor WHERE network=? AND payto=?", (network, payto))
            start = row["next_block"] if row else head + 1     # payments before joining are not ours to show
            if row is None:
                store.x("INSERT INTO chain_cursor(network, payto, next_block) VALUES (?,?,?)", (network, payto, start))
            for _ in range(MAX_CHUNKS_PER_RUN):
                if start > head:
                    break
                end = min(head, start + CHUNK - 1)
                logs = rpc(url, "eth_getLogs", [{
                    "address": USDC[network], "fromBlock": hex(start), "toBlock": hex(end),
                    "topics": [TRANSFER_TOPIC, None, _topic_address(payto)]}])
                with store.tx() as db:
                    for entry in logs:
                        if entry.get("removed"):
                            continue
                        block = int(entry["blockNumber"], 16)
                        key = (network, block)
                        if key not in block_ts:
                            block_ts[key] = int(rpc(url, "eth_getBlockByNumber", [hex(block), False])["timestamp"], 16)
                        tx_hash = entry["transactionHash"].lower()
                        # A shared payout contract: the machine that credited the payment gets it.
                        claimed = db.execute("SELECT provider FROM tx_claims WHERE network=? AND tx=?",
                                             (network, tx_hash)).fetchone()
                        cur = db.execute(
                            "INSERT OR IGNORE INTO payments(network, tx_hash, log_index, provider, payto, payer, amount,"
                            " block, ts) VALUES (?,?,?,?,?,?,?,?,?)",
                            (network, tx_hash, int(entry["logIndex"], 16), claimed["provider"] if claimed else pid, payto,
                             "0x" + entry["topics"][1][-40:], int(entry["data"], 16), block, block_ts[key]))
                        added += cur.rowcount
                    db.execute("UPDATE chain_cursor SET next_block=? WHERE network=? AND payto=?",
                               (end + 1, network, payto))
                start = end + 1
        except Exception as exc:
            log.warning("chain scan %s %s failed: %s", network, payto, exc)
    return added


def split(amount: int, fee_bps: int) -> tuple[int, int]:
    """(provider share, fee share) in USDC base units; the provider share rounds down."""
    provider = amount * (10_000 - fee_bps) // 10_000
    return provider, amount - provider


def usdc(units: int) -> str:
    return f"{(Decimal(units) / DECIMALS):.2f}"


def earnings(store: Store, pid: str, fee_bps: int, *, since: int) -> dict:
    gross = fee = 0
    for row in store.q("SELECT amount FROM payments WHERE provider=? AND ts>=?", (pid, since)):
        net_part, fee_part = split(row["amount"], fee_bps)
        gross += row["amount"]
        fee += fee_part
    return {"asset": "USDC", "gross": gross, "fee": fee, "net": gross - fee}


def recent_splits(store: Store, pid: str, fee_bps: int, limit: int = 100) -> list[dict]:
    out = []
    for r in store.q("SELECT * FROM payments WHERE provider=? ORDER BY ts DESC, log_index DESC LIMIT ?", (pid, limit)):
        provider_share, fee_share = split(r["amount"], fee_bps)
        out.append({"network": r["network"], "tx": r["tx_hash"], "explorer": EXPLORER_TX.get(r["network"], "") + r["tx_hash"],
                    "ts": r["ts"], "payer": r["payer"], "amount": usdc(r["amount"]),
                    "provider_share": usdc(provider_share), "fee_share": usdc(fee_share)})
    return out


def daily(store: Store, pid: str, fee_bps: int, days: int = 30) -> list[dict]:
    now = int(time.time())
    start = now - days * 86400
    buckets: dict[str, int] = {}
    for r in store.q("SELECT amount, ts FROM payments WHERE provider=? AND ts>=?", (pid, start)):
        day = time.strftime("%Y-%m-%d", time.gmtime(r["ts"]))
        buckets[day] = buckets.get(day, 0) + r["amount"]
    out = []
    for i in range(days - 1, -1, -1):
        day = time.strftime("%Y-%m-%d", time.gmtime(now - i * 86400))
        amount = buckets.get(day, 0)
        out.append({"day": day, "gross": usdc(amount), "net": usdc(split(amount, fee_bps)[0])})
    return out
