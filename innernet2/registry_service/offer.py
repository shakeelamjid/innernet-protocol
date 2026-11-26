"""The offer a person chooses on the web setup page. The machine turns it into a signed
descriptor; the registry only checks it is well formed before passing it on."""
from __future__ import annotations

import re

from ..bulk_v080 import BulkError
from ..irm_registry import _validate_provider

UNITS = {"STO-1": "GiB-day", "RLY-1": "GiB", "CMP-1": "CPU-hour", "GPU-1": "GPU-hour", "VPN-1": "GiB"}
DEFAULT_PRICES = {"STO-1": "0.0010", "RLY-1": "0.0050", "CMP-1": "0.0200", "GPU-1": "0.2500", "VPN-1": "0.0100"}
_EVM = re.compile(r"^0x[0-9a-fA-F]{40}$")
_KEYS = {"name", "region", "host", "port", "storage_gib", "relay_gib", "compute", "cpus", "memory_mib",
         "gpu", "gpus", "reserve_gib", "per_client", "terms", "relay", "vpn", "vpn_consent",
         "vpn_ports", "prices", "network", "payout", "hours", "month_days", "skip_dates"}


def _int(v, lo, hi, label):
    if type(v) is not int or not lo <= v <= hi:
        raise BulkError(f"{label}: whole number from {lo} to {hi}")
    return v


def best_gpu(detected: dict | None) -> dict | None:
    """The machine's strongest GPU for rent (most memory), or None. Generic display adapters never count."""
    gpus = [g for g in (detected or {}).get("gpus") or [] if g.get("api", "none") != "none"]
    return max(gpus, key=lambda g: (g.get("vram_mib", 0), g.get("cores", 0)), default=None)


_DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
_DATE = re.compile(r"^20[0-9]{2}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$")


def _day(name: str) -> int:
    for i, d in enumerate(_DAYS):
        if name.startswith(d):
            return i
    return -1


def check_hours(text) -> str:
    """Weekly hours as the machine reads them: "always" or e.g. "mon-fri 21:00-08:00, sat 10:00-14:00"."""
    t = str(text or "always").strip().lower()
    if t in ("", "always", "24/7"):
        return "always"
    if len(t) > 400:
        raise BulkError("hours: too long")
    for part in t.split(","):
        f = part.split()
        if len(f) != 2:
            raise BulkError(f"hours: write days then hours, e.g. mon-fri 21:00-08:00 (not {part.strip()!r})")
        days, span = f
        if days not in ("daily", "every", "all", "weekdays", "weekends"):
            a, _, b = days.partition("-")
            if _day(a) < 0 or (b and _day(b) < 0):
                raise BulkError(f"hours: days are mon..sun, weekdays, weekends or daily (not {days!r})")
        m = re.match(r"^([0-9]{1,2})(?::([0-9]{2}))?-([0-9]{1,2})(?::([0-9]{2}))?$", span)
        if not m:
            raise BulkError(f"hours: times look like 21:00-08:00 (not {span!r})")
        a = int(m[1]) * 60 + int(m[2] or 0)
        b = int(m[3]) * 60 + int(m[4] or 0)
        if a >= 1440 or b > 1440 or a == b or int(m[2] or 0) > 59 or int(m[4] or 0) > 59:
            raise BulkError(f"hours: times look like 21:00-08:00 (not {span!r})")
    return t


def check_month_days(days) -> list[int]:
    if not isinstance(days, list) or len(days) > 31:
        raise BulkError("days of the month: a list of 1..31")
    out = sorted({_int(d, 1, 31, "day of the month") for d in days})
    if out and len(out) == 31:
        return []          # every day: same as none
    return out


def check_skip(dates) -> list[str]:
    if not isinstance(dates, list) or len(dates) > 64:
        raise BulkError("dates off: at most 64")
    out = sorted({str(d).strip() for d in dates})
    for d in out:
        if not _DATE.match(d):
            raise BulkError(f"dates off: use YYYY-MM-DD (not {d!r})")
    return out


def check_offer(offer: dict, networks: set[str], detected: dict | None = None) -> dict:
    """Validate and normalise an offer; returns the clean offer. Raises BulkError with a readable reason.
    A GPU offer must match a GPU the machine reported when it connected."""
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
        "gpu": bool(offer.get("gpu", False)),
        "gpus": _int(offer.get("gpus", 1), 1, 16, "GPUs"),
        "reserve_gib": _int(offer.get("reserve_gib", 4), 0, 1024, "memory kept for you"),
        "relay": bool(offer.get("relay", True)),
        "vpn": bool(offer.get("vpn", False)),
        "vpn_consent": bool(offer.get("vpn_consent", False)),
        "vpn_ports": "all" if offer.get("vpn_ports") == "all" else "web",
        "per_client": _int(offer.get("per_client", 2), 1, 64, "jobs per client"),
        "prices": {k: str(v).strip() for k, v in dict(offer.get("prices") or {}).items() if k in UNITS},
        "network": str(offer.get("network", "")),
        "payout": str(offer.get("payout", "")).strip(),
        "hours": check_hours(offer.get("hours", "always")),
        "month_days": check_month_days(offer.get("month_days") or []),
        "skip_dates": check_skip(offer.get("skip_dates") or []),
    }
    if o["vpn"] and not o["vpn_consent"]:
        raise BulkError("VPN exit needs your consent: you are allowed to offer internet exit where you operate, "
                        "and you accept the abuse policy")
    if o["vpn"] and o["relay_gib"] <= 0:
        raise BulkError("VPN exit: set the monthly bandwidth (GiB)")
    if o["vpn"] and detected is not None and detected.get("path") == "tunnel":
        raise BulkError("VPN exit needs clients to reach this machine directly or through an INNERNET relay; "
                        "the HTTPS tunnel it uses now cannot carry VPN traffic. Untick VPN exit for now.")
    from . import terms
    if offer.get("terms") != terms.current("provider")["sha256"]:
        raise BulkError("read and agree to the provider terms")
    o["terms"] = offer["terms"]
    if o["network"] not in networks:
        raise BulkError("choose a payment network the registry accepts")
    if not _EVM.match(o["payout"]):
        raise BulkError("payout contract: 0x followed by 40 hex characters")
    if o["gpu"]:
        g = best_gpu(detected)
        if g is None:
            raise BulkError("this machine reported no GPU that can run jobs")
        same = [x for x in detected["gpus"] if x.get("model") == g["model"]]
        if o["gpus"] > len(same):
            raise BulkError(f"this machine reported {len(same)} {g['model']}")
        o["gpu_info"] = {k: g[k] for k in ("vendor", "model", "api", "vram_mib") if k in g}
    entry = to_entry(o, "00" * 32)
    if not entry["services"]:
        raise BulkError("offer at least one of storage, relay, VPN exit, CPU or GPU")
    _validate_provider(entry, registry=False)
    return o


def to_entry(o: dict, provider_id: str) -> dict:
    services, prices, limits = [], {}, {}
    if o["storage_gib"] > 0:
        services.append("STO-1")
        limits["STO-1"] = {"max_storage_gib": o["storage_gib"]}
    if o["relay_gib"] > 0 and o.get("relay", True):
        services.append("RLY-1")
        limits["RLY-1"] = {"max_gib_per_month": o["relay_gib"]}
    if o["relay_gib"] > 0 and o.get("vpn") and o.get("vpn_consent"):
        services.append("VPN-1")
        limits["VPN-1"] = {"max_gib_per_month": o["relay_gib"], "all_ports": 1 if o.get("vpn_ports") == "all" else 0}
    if o["compute"]:
        services.append("CMP-1")
        limits["CMP-1"] = {"max_cpus": o["cpus"], "max_memory_mib": o["memory_mib"]}
    hardware = None
    if o.get("gpu") and o.get("gpu_info"):
        g = o["gpu_info"]
        services.append("GPU-1")
        limits["GPU-1"] = {"max_gpus": o["gpus"]}
        hardware = {"gpu_vendor": g["vendor"], "gpu_model": g["model"], "gpu_api": g.get("api", "none")}
        if g.get("vram_mib"):
            hardware["gpu_vram_mib"] = g["vram_mib"]
    for s in services:
        prices[s] = {"asset": "USDC", "unit": UNITS[s], "amount": o["prices"].get(s, DEFAULT_PRICES[s])}
    entry = {"id": provider_id, "name": o["name"], "region": o["region"], **({"terms": o["terms"]} if o.get("terms") else {}),
             "endpoints": [{"host": o["host"], "port": o["port"]}], "services": services,
             "payto": {o["network"]: o["payout"]}, "prices": prices}
    if limits:
        entry["limits"] = limits
    if hardware:
        entry["hardware"] = hardware
    return entry
