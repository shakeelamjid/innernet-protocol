"""Settings from environment variables. Secrets are read from mounted files, never env values."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

# Circle-issued USDC (6 decimals).
USDC = {
    "eip155:84532": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",  # Base Sepolia
    "eip155:8453": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",   # Base
}
CHAIN_IDS = {"eip155:84532": 84532, "eip155:8453": 8453}
EXPLORER_TX = {
    "eip155:84532": "https://sepolia.basescan.org/tx/",
    "eip155:8453": "https://basescan.org/tx/",
}
NETWORK_NAMES = {"eip155:84532": "Base Sepolia", "eip155:8453": "Base"}
_EVM = re.compile(r"^0x[0-9a-fA-F]{40}$")


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


@dataclass
class Settings:
    db_path: str = "/var/lib/innernet-registry/registry.db"
    key_file: str = ""
    fee_bps: int = 250                                  # 2.5% network fee
    fee_payto: dict = field(default_factory=dict)       # caip2 -> fee wallet
    rpc: dict = field(default_factory=dict)             # caip2 -> JSON-RPC URL
    split_factory: dict = field(default_factory=dict)  # caip2 -> INNERnetSplitFactory address
    origin: str = "https://innernetcorp.com"
    rp_id: str = "innernetcorp.com"
    login_host: str = "innernetcorp.com"
    prefix: str = "/registry"
    cookie_secure: bool = True
    trust_proxy: bool = False
    workers: bool = True                                 # probe and chain loops
    probe_interval: int = 300
    chain_interval: int = 120
    document_ttl: int = 3600

    @classmethod
    def from_env(cls) -> "Settings":
        s = cls()
        s.db_path = _env("INNERNET_REGISTRY_DB", s.db_path)
        s.key_file = _env("INNERNET_REGISTRY_KEY_FILE")
        s.fee_bps = int(_env("INNERNET_FEE_BPS", "250"))
        if not 0 <= s.fee_bps <= 10_000:
            raise SystemExit("INNERNET_FEE_BPS must be 0-10000")
        for var, net in (("INNERNET_FEE_PAYTO_BASE_SEPOLIA", "eip155:84532"), ("INNERNET_FEE_PAYTO_BASE", "eip155:8453")):
            addr = _env(var)
            if addr:
                if not _EVM.match(addr):
                    raise SystemExit(f"{var} is not an EVM address")
                s.fee_payto[net] = addr
        for var, net in (("INNERNET_RPC_BASE_SEPOLIA", "eip155:84532"), ("INNERNET_RPC_BASE", "eip155:8453")):
            if _env(var):
                s.rpc[net] = _env(var)
        for var, net in (("INNERNET_SPLIT_FACTORY_BASE_SEPOLIA", "eip155:84532"), ("INNERNET_SPLIT_FACTORY_BASE", "eip155:8453")):
            addr = _env(var)
            if addr:
                if not _EVM.match(addr):
                    raise SystemExit(f"{var} is not an EVM address")
                s.split_factory[net] = addr
        s.origin = _env("INNERNET_REGISTRY_ORIGIN", s.origin).rstrip("/")
        s.rp_id = _env("INNERNET_REGISTRY_RP_ID", s.rp_id)
        s.login_host = _env("INNERNET_REGISTRY_HOST", s.rp_id)
        s.trust_proxy = _env("INNERNET_TRUST_PROXY", "1") == "1"
        return s
