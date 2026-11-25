"""The offer a person chooses on the web setup page. The machine turns it into a signed
descriptor; the registry only checks it is well formed before passing it on."""
from __future__ import annotations

import re

from ..bulk_v080 import BulkError
from ..irm_registry import _validate_provider

UNITS = {"STO-1": "GiB-day", "RLY-1": "GiB", "CMP-1": "Ginstr"}
DEFAULT_PRICES = {"STO-1": "0.0010", "RLY-1": "0.0050", "CMP-1": "0.0100"}
_EVM = re.compile(r"^0x[0-9a-fA-F]{40}$")
_KEYS = {"name", "region", "host", "port", "storage_gib", "relay_gib", "compute", "cpus", "memory_mib",
         "prices", "network", "payout"}


def _int(v, lo, hi, label):
    if type(v) is not int or not lo <= v <= hi:
        raise BulkError(f"{label}: whole number from {lo} to {hi}")
    return v


def check_offer(offer: dict, networks: set[str]) -> dict:
    """Validate and normalise an offer; returns the clean offer. Raises BulkError with a readable reason."""
    if not isinstance(offer, dict) or not set(offer) <= _KEYS:
        raise BulkError("unexpected fields in offer")
    o = {
        "name": str(offer.get("name", "")).strip().lower(),
        "region": str(offer.get("region", "")).strip().lower(),
        "host": str(offer.get("host", "")).strip(),
        "port": _int(offer.get("port", 9443), 1, 65535, "port"),
        "storage_gib": _int(offer.get("storage_gib", 0), 0, 10_000_000, "storage"),
        "relay_gib": _int(offer.get("relay_gib", 0), 0, 10_000_000, "bandwidth"),
        "compute": bool(offer.get("compute", False)),
        "cpus": _int(offer.get("cpus", 1), 1, 1024, "CPUs"),
        "memory_mib": _int(offer.get("memory_mib", 512), 64, 4_194_304, "memory"),
        "prices": {k: str(v).strip() for k, v in dict(offer.get("prices") or {}).items() if k in UNITS},
        "network": str(offer.get("network", "")),
        "payout": str(offer.get("payout", "")).strip(),
    }
    if o["network"] not in networks:
        raise BulkError("choose a payment network the registry accepts")
    if not _EVM.match(o["payout"]):
        raise BulkError("payout contract: 0x followed by 40 hex characters")
    entry = to_entry(o, "00" * 32)
    if not entry["services"]:
        raise BulkError("offer at least one of storage, bandwidth or compute")
    _validate_provider(entry, registry=False)
    return o


def to_entry(o: dict, provider_id: str) -> dict:
    services, prices, limits = [], {}, {}
    if o["storage_gib"] > 0:
        services.append("STO-1")
        limits["STO-1"] = {"max_storage_gib": o["storage_gib"]}
    if o["relay_gib"] > 0:
        services.append("RLY-1")
        limits["RLY-1"] = {"max_gib_per_month": o["relay_gib"]}
    if o["compute"]:
        services.append("CMP-1")
        limits["CMP-1"] = {"max_cpus": o["cpus"], "max_memory_mib": o["memory_mib"]}
    for s in services:
        prices[s] = {"asset": "USDC", "unit": UNITS[s], "amount": o["prices"].get(s, DEFAULT_PRICES[s])}
    entry = {"id": provider_id, "name": o["name"], "region": o["region"],
             "endpoints": [{"host": o["host"], "port": o["port"]}], "services": services,
             "payto": {o["network"]: o["payout"]}, "prices": prices}
    if limits:
        entry["limits"] = limits
    return entry
