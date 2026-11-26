"""IRM-1 draft: REG-1 signed provider registry, provider descriptors,
price checks and PAY-1 service tickets.

Status: DRAFT reference implementation of docs/IRM1_RESOURCE_MARKET_SPEC.md.
Not part of the v1.0.0 core and not a compatibility promise. Offline only:
no network, no payments, no chain access happen in this module.

Signing follows the R90 pattern: Ed25519 over a domain string plus the
canonical JSON of the payload.
"""
from __future__ import annotations

import base64
import hashlib
import re
import time
from decimal import Decimal, InvalidOperation

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .bulk_v080 import BulkError, _bytes
from .mailbox_e2ee import canonical
from .native_udp import pub_bytes
from .routing_v090 import SequenceStore

REGISTRY_DOMAIN = b"INNERnet/REG-1/provider-registry\x00"
ROTATION_DOMAIN = b"INNERnet/REG-1/registry-key-rotation\x00"
DESCRIPTOR_DOMAIN = b"INNERnet/REG-1/provider-descriptor\x00"
TICKET_DOMAIN = b"INNERnet/PAY-1/service-ticket\x00"

VERSION = "REG-1"
ROTATION_VERSION = "REG-1-ROTATE"
DESCRIPTOR_VERSION = "REG-1-DESCRIPTOR"
TICKET_VERSION = "PAY-1-TICKET"

SERVICES = frozenset({"STO-1", "RLY-1", "VPN-1", "CMP-1", "GPU-1"})
GPU_APIS = frozenset({"cuda", "metal", "vulkan", "directx", "rocm", "oneapi", "none"})
_HWTEXT = re.compile(r"^[A-Za-z0-9 ()._+/,-]{1,80}$")
ASSETS = frozenset({"USDC"})
MAX_SEQUENCE = 2**63 - 1
MAX_PROVIDERS = 10_000
MAX_WINDOW = 86_400          # registry documents live at most 24 h (spec 3.1)
MIN_WINDOW = 60
FUTURE_SKEW = 300

_CAIP2_EVM = re.compile(r"^eip155:[1-9][0-9]{0,15}$")
_EVM_ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HEX32 = re.compile(r"^[0-9a-f]{64}$")
_DECIMAL = re.compile(r"^(0|[1-9][0-9]{0,17})(\.[0-9]{1,18})?$")
_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_UNIT = re.compile(r"^[A-Za-z0-9-]{1,24}$")
_REGION = re.compile(r"^[a-z0-9-]{1,32}$")


def _int(value, lo: int, hi: int, label: str) -> int:
    if type(value) is not int or not lo <= value <= hi:
        raise BulkError(f"invalid {label}")
    return value


def _exact_keys(obj, required: set[str], optional: set[str] = frozenset(), label: str = "object") -> None:
    if not isinstance(obj, dict):
        raise BulkError(f"malformed {label}")
    keys = set(obj)
    if not required <= keys or not keys <= required | optional:
        raise BulkError(f"malformed {label}")


def _decimal(value, label: str) -> Decimal:
    if not isinstance(value, str) or not _DECIMAL.match(value):
        raise BulkError(f"invalid {label}")
    try:
        return Decimal(value)
    except InvalidOperation as exc:  # pragma: no cover - regex already guards
        raise BulkError(f"invalid {label}") from exc


def _payto_map(value, label: str) -> dict:
    if not isinstance(value, dict) or not value or len(value) > 16:
        raise BulkError(f"invalid {label}")
    for network, address in value.items():
        if not isinstance(network, str) or not _CAIP2_EVM.match(network):
            raise BulkError(f"invalid {label} network")
        if not isinstance(address, str) or not _EVM_ADDR.match(address):
            raise BulkError(f"invalid {label} address")
    return value


CLASSES = {"server", "desktop", "laptop"}
_TZ = re.compile(r"^(UTC[+-][0-9]{2}:[0-9]{2}|[A-Za-z_]{1,32}(/[A-Za-z0-9_+-]{1,32}){0,2}|UTC)$")


def validate_availability(av) -> None:
    """Weekly hours: {"tz": zone, "weekly": [[day 0=Mon..6, from_minute, to_minute], ...]}, sorted,
    non-overlapping, each window inside one day. Missing availability means always on."""
    _exact_keys(av, {"tz", "weekly"}, label="availability")
    if not isinstance(av["tz"], str) or not _TZ.match(av["tz"]):
        raise BulkError("invalid availability time zone")
    weekly = av["weekly"]
    if not isinstance(weekly, list) or not 1 <= len(weekly) <= 64:
        raise BulkError("invalid availability windows")
    last = (-1, 0)
    for w in weekly:
        if not isinstance(w, list) or len(w) != 3:
            raise BulkError("invalid availability window")
        day, start, end = (_int(w[0], 0, 6, "availability day"), _int(w[1], 0, 1439, "availability start"),
                           _int(w[2], 1, 1440, "availability end"))
        if start >= end or (day, start) < last or (day == last[0] and start < last[1]):
            raise BulkError("availability windows must be sorted and must not overlap")
        last = (day, end)


def available_minutes(entry: dict) -> int:
    av = entry.get("availability")
    return 7 * 1440 if av is None else sum(w[2] - w[1] for w in av["weekly"])


def validate_hardware(hw: dict) -> None:
    """Self-described hardware behind GPU-1: what the machine found, signed with the descriptor."""
    _exact_keys(hw, set(), {"gpu_vendor", "gpu_model", "gpu_api", "gpu_vram_mib"}, "provider hardware")
    for k in ("gpu_vendor", "gpu_model"):
        if k in hw and (not isinstance(hw[k], str) or not _HWTEXT.match(hw[k])):
            raise BulkError(f"invalid hardware {k}")
    if "gpu_api" in hw and hw["gpu_api"] not in GPU_APIS:
        raise BulkError("invalid hardware gpu_api")
    if "gpu_vram_mib" in hw:
        _int(hw["gpu_vram_mib"], 0, 2**30, "hardware gpu_vram_mib")


def validate_gpus(gpus) -> None:
    """The GPUs a machine reports when it connects (REG-1-CONNECT detected.gpus)."""
    if not isinstance(gpus, list) or len(gpus) > 16:
        raise BulkError("invalid detected gpus")
    for g in gpus:
        _exact_keys(g, {"vendor", "model"}, {"vram_mib", "cores", "api", "driver"}, "detected gpu")
        for k in ("vendor", "model", "driver"):
            if k in g and (not isinstance(g[k], str) or not _HWTEXT.match(g[k])):
                raise BulkError(f"invalid detected gpu {k}")
        for k in ("vram_mib", "cores"):
            if k in g:
                _int(g[k], 0, 2**30, f"detected gpu {k}")
        if "api" in g and g["api"] not in GPU_APIS:
            raise BulkError("invalid detected gpu api")


def _validate_provider(entry: dict, *, registry: bool) -> None:
    required = {"id", "name", "region", "endpoints", "services", "payto", "prices"}
    optional = {"limits", "availability", "class", "hardware", "terms"} | ({"listed_at", "reputation"} if registry else set())
    _exact_keys(entry, required, optional, "provider entry")
    if not isinstance(entry["id"], str) or not _HEX32.match(entry["id"]):
        raise BulkError("invalid provider id")
    if not isinstance(entry["name"], str) or not _NAME.match(entry["name"]):
        raise BulkError("invalid provider name")
    if not isinstance(entry["region"], str) or not _REGION.match(entry["region"]):
        raise BulkError("invalid provider region")
    endpoints = entry["endpoints"]
    if not isinstance(endpoints, list) or not 1 <= len(endpoints) <= 8:
        raise BulkError("invalid provider endpoints")
    for ep in endpoints:
        _exact_keys(ep, {"host", "port"}, label="provider endpoint")
        if not isinstance(ep["host"], str) or not _HOST.match(ep["host"]):
            raise BulkError("invalid endpoint host")
        _int(ep["port"], 1, 65535, "endpoint port")
    services = entry["services"]
    if (not isinstance(services, list) or not services or len(set(services)) != len(services)
            or not set(services) <= SERVICES):
        raise BulkError("invalid provider services")
    _payto_map(entry["payto"], "provider payto")
    prices = entry["prices"]
    if not isinstance(prices, dict) or set(prices) != set(services):
        raise BulkError("provider must price exactly the services it lists")
    for service, price in prices.items():
        _exact_keys(price, {"asset", "unit", "amount"}, label="price")
        if price["asset"] not in ASSETS:
            raise BulkError("unsupported price asset")
        if not isinstance(price["unit"], str) or not _UNIT.match(price["unit"]):
            raise BulkError("invalid price unit")
        _decimal(price["amount"], "price amount")
    if "limits" in entry:
        limits = entry["limits"]
        if not isinstance(limits, dict) or not set(limits) <= set(services):
            raise BulkError("invalid provider limits")
        for service_limits in limits.values():
            if not isinstance(service_limits, dict) or len(service_limits) > 16:
                raise BulkError("invalid provider limits")
            for k, v in service_limits.items():
                if not isinstance(k, str) or not _UNIT.match(k.replace("_", "-")):
                    raise BulkError("invalid provider limit name")
                _int(v, 0, 2**53, "provider limit value")
    if "terms" in entry and (not isinstance(entry["terms"], str) or not re.match(r"^[0-9a-f]{64}$", entry["terms"])):
        raise BulkError("terms: the SHA-256 of the provider terms the provider agreed to")
    if "hardware" in entry:
        validate_hardware(entry["hardware"])
    if ("GPU-1" in services) != ("hardware" in entry and "gpu_model" in entry["hardware"]):
        raise BulkError("GPU-1 needs hardware.gpu_model, and only GPU-1 may carry it")
    if "class" in entry and entry["class"] not in CLASSES:
        raise BulkError("invalid provider class")
    if "availability" in entry:
        validate_availability(entry["availability"])
    if registry:
        if "listed_at" in entry:
            _int(entry["listed_at"], 0, 2**53, "provider listed_at")
        if "reputation" in entry:
            rep = entry["reputation"]
            if not isinstance(rep, dict) or len(rep) > 16:
                raise BulkError("invalid provider reputation")
            for k, v in rep.items():
                if not isinstance(k, str) or not _UNIT.match(k.replace("_", "-")):
                    raise BulkError("invalid reputation name")
                _decimal(v, "reputation value")


def validate_registry_payload(payload: dict, instant: int) -> None:
    _exact_keys(payload, {"version", "sequence", "issued_at", "expires_at", "fee_bps", "fee_payto", "providers"},
                label="registry payload")
    if payload["version"] != VERSION:
        raise BulkError("unsupported registry version")
    _int(payload["sequence"], 0, MAX_SEQUENCE, "registry sequence")
    issued = _int(payload["issued_at"], 0, 2**53, "issued_at")
    expires = _int(payload["expires_at"], 0, 2**53, "expires_at")
    if not MIN_WINDOW <= expires - issued <= MAX_WINDOW:
        raise BulkError("registry validity window out of bounds")
    if issued > instant + FUTURE_SKEW:
        raise BulkError("registry issued in the future")
    if instant > expires:
        raise BulkError("registry expired")
    _int(payload["fee_bps"], 0, 10_000, "fee_bps")
    fee_payto = _payto_map(payload["fee_payto"], "fee_payto")
    providers = payload["providers"]
    if not isinstance(providers, list) or len(providers) > MAX_PROVIDERS:
        raise BulkError("invalid provider list")
    seen = set()
    for entry in providers:
        _validate_provider(entry, registry=True)
        if entry["id"] in seen:
            raise BulkError("duplicate provider id")
        seen.add(entry["id"])
        # A provider may only take payment on networks where a fee wallet exists.
        if not set(entry["payto"]) <= set(fee_payto):
            raise BulkError("provider payto network has no fee wallet")


def sign_registry(payload: dict, registry_key: Ed25519PrivateKey, *, now: int | None = None) -> dict:
    validate_registry_payload(payload, int(time.time()) if now is None else now)
    return {"payload": payload, "registry_key": pub_bytes(registry_key).hex(),
            "signature": registry_key.sign(REGISTRY_DOMAIN + canonical(payload)).hex()}


def verify_registry(document: dict, pinned_keys: list[bytes], *, now: int | None = None,
                    sequence_store: SequenceStore | None = None) -> dict:
    """Return the verified payload, or raise BulkError. Fails closed."""
    _exact_keys(document, {"payload", "registry_key", "signature"}, label="registry document")
    key = _bytes(document["registry_key"], 32, "registry key")
    if key not in {bytes(k) for k in pinned_keys}:
        raise BulkError("registry key not pinned")
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(
            _bytes(document["signature"], 64, "registry signature"),
            REGISTRY_DOMAIN + canonical(document["payload"]))
    except (ValueError, InvalidSignature) as exc:
        raise BulkError("registry signature invalid") from exc
    payload = document["payload"]
    validate_registry_payload(payload, int(time.time()) if now is None else now)
    if sequence_store is not None:
        sequence_store.check_and_update("reg1:" + document["registry_key"], payload["sequence"])
    return payload


# ---- registry key rotation (spec 3.5) -------------------------------------

def sign_rotation(new_key: bytes, sequence: int, *, backup_key: Ed25519PrivateKey,
                  old_key: Ed25519PrivateKey | None = None, now: int | None = None) -> dict:
    payload = {"version": ROTATION_VERSION, "new_key": bytes(new_key).hex(), "sequence": sequence,
               "issued_at": int(time.time()) if now is None else now}
    _int(sequence, 0, MAX_SEQUENCE, "rotation sequence")
    signatures = {"backup": backup_key.sign(ROTATION_DOMAIN + canonical(payload)).hex()}
    if old_key is not None:
        signatures["old"] = old_key.sign(ROTATION_DOMAIN + canonical(payload)).hex()
    return {"payload": payload, "signatures": signatures}


def verify_rotation(record: dict, *, active_key: bytes, backup_key: bytes,
                    sequence_store: SequenceStore | None = None) -> bytes:
    """Return the new active registry key. The pinned backup key MUST sign.
    The old key's signature is checked when present; a backup-only (emergency)
    rotation is accepted but still has to move the sequence forward."""
    _exact_keys(record, {"payload", "signatures"}, label="rotation record")
    payload = record["payload"]
    _exact_keys(payload, {"version", "new_key", "sequence", "issued_at"}, label="rotation payload")
    if payload["version"] != ROTATION_VERSION:
        raise BulkError("unsupported rotation version")
    new_key = _bytes(payload["new_key"], 32, "rotation new key")
    _int(payload["sequence"], 0, MAX_SEQUENCE, "rotation sequence")
    _int(payload["issued_at"], 0, 2**53, "rotation issued_at")
    sigs = record["signatures"]
    if not isinstance(sigs, dict) or "backup" not in sigs or not set(sigs) <= {"backup", "old"}:
        raise BulkError("rotation must be signed by the backup key")
    message = ROTATION_DOMAIN + canonical(payload)
    try:
        Ed25519PublicKey.from_public_bytes(backup_key).verify(_bytes(sigs["backup"], 64, "backup signature"), message)
        if "old" in sigs:
            Ed25519PublicKey.from_public_bytes(active_key).verify(_bytes(sigs["old"], 64, "old signature"), message)
    except (ValueError, InvalidSignature) as exc:
        raise BulkError("rotation signature invalid") from exc
    if new_key in (bytes(active_key), bytes(backup_key)):
        raise BulkError("rotation must introduce a new key")
    if sequence_store is not None:
        sequence_store.check_and_update("reg1-rotate:" + bytes(backup_key).hex(), payload["sequence"])
    return new_key


# ---- provider self-signed descriptor (spec 3.3) ---------------------------

def sign_descriptor(entry: dict, provider_key: Ed25519PrivateKey) -> dict:
    if entry.get("id") != pub_bytes(provider_key).hex():
        raise BulkError("descriptor id must be the signing provider key")
    _validate_provider(entry, registry=False)
    payload = {"version": DESCRIPTOR_VERSION, "provider": entry}
    return {"payload": payload, "signature": provider_key.sign(DESCRIPTOR_DOMAIN + canonical(payload)).hex()}


def verify_descriptor(record: dict) -> dict:
    _exact_keys(record, {"payload", "signature"}, label="descriptor")
    payload = record["payload"]
    _exact_keys(payload, {"version", "provider"}, label="descriptor payload")
    if payload["version"] != DESCRIPTOR_VERSION:
        raise BulkError("unsupported descriptor version")
    entry = payload["provider"]
    _validate_provider(entry, registry=False)
    try:
        Ed25519PublicKey.from_public_bytes(_bytes(entry["id"], 32, "provider id")).verify(
            _bytes(record["signature"], 64, "descriptor signature"), DESCRIPTOR_DOMAIN + canonical(payload))
    except (ValueError, InvalidSignature) as exc:
        raise BulkError("descriptor signature invalid") from exc
    return entry


# ---- client-side helpers --------------------------------------------------

def find_provider(payload: dict, provider_id: bytes) -> dict:
    hex_id = bytes(provider_id).hex()
    for entry in payload["providers"]:
        if entry["id"] == hex_id:
            return entry
    raise BulkError("provider not listed")


def check_quoted_price(entry: dict, service: str, *, asset: str, amount: str, unit: str) -> Decimal:
    """Spec 4.4: refuse any 402 quote above the signed registry price."""
    price = entry["prices"].get(service)
    if price is None:
        raise BulkError("provider does not offer this service")
    if asset != price["asset"] or unit != price["unit"]:
        raise BulkError("quote asset or unit differs from registry")
    quoted = _decimal(amount, "quoted amount")
    if quoted > Decimal(price["amount"]):
        raise BulkError("quote exceeds signed registry price")
    return quoted


def check_payto(payload: dict, entry: dict, network: str, pay_to: str) -> None:
    """The 402's payTo must be the provider's registered split contract."""
    registered = entry["payto"].get(network)
    if registered is None or registered.lower() != str(pay_to).lower():
        raise BulkError("payTo is not the provider's registered split contract")
    if network not in payload["fee_payto"]:
        raise BulkError("no fee wallet for this network")


# ---- PAY-1 service tickets (spec 4.1) -------------------------------------

def sign_ticket(fields: dict, provider_key: Ed25519PrivateKey) -> dict:
    payload = dict(fields, version=TICKET_VERSION, provider=pub_bytes(provider_key).hex())
    _validate_ticket(payload)
    return {"payload": payload, "signature": provider_key.sign(TICKET_DOMAIN + canonical(payload)).hex()}


def _validate_ticket(payload: dict) -> None:
    _exact_keys(payload, {"version", "provider", "client", "service", "lease", "units", "unit",
                          "payment_tx", "expires_at"}, {"held", "released", "terms"}, label="service ticket")
    for k in ("held", "released"):
        if k in payload:
            _int(payload[k], 0, 2**53, f"ticket {k}")
    if "terms" in payload and (not isinstance(payload["terms"], str) or len(payload["terms"]) > 64):
        raise BulkError("invalid ticket terms")
    if payload["version"] != TICKET_VERSION:
        raise BulkError("unsupported ticket version")
    for k in ("provider", "client"):
        if not isinstance(payload[k], str) or not _HEX32.match(payload[k]):
            raise BulkError(f"invalid ticket {k}")
    if payload["service"] not in SERVICES:
        raise BulkError("invalid ticket service")
    if not isinstance(payload["lease"], str) or not re.match(r"^[0-9a-f]{32}$", payload["lease"]):
        raise BulkError("invalid ticket lease id")
    _decimal(payload["units"], "ticket units")
    if not isinstance(payload["unit"], str) or not _UNIT.match(payload["unit"]):
        raise BulkError("invalid ticket unit")
    if not isinstance(payload["payment_tx"], str) or not re.match(r"^0x[0-9a-fA-F]{64}$", payload["payment_tx"]):
        raise BulkError("invalid ticket payment transaction")
    _int(payload["expires_at"], 0, 2**53, "ticket expires_at")


def verify_ticket(record: dict, provider_id: bytes, *, now: int | None = None) -> dict:
    _exact_keys(record, {"payload", "signature"}, label="ticket record")
    payload = record["payload"]
    _validate_ticket(payload)
    if payload["provider"] != bytes(provider_id).hex():
        raise BulkError("ticket from a different provider")
    try:
        Ed25519PublicKey.from_public_bytes(provider_id).verify(
            _bytes(record["signature"], 64, "ticket signature"), TICKET_DOMAIN + canonical(payload))
    except (ValueError, InvalidSignature) as exc:
        raise BulkError("ticket signature invalid") from exc
    if (int(time.time()) if now is None else now) > payload["expires_at"]:
        raise BulkError("ticket expired")
    return payload


# ---- usage receipts (CMP-1 CPU, GPU-1 GPU) ----------------------------------
# Compute is paid from a prepaid credit balance on the provider. Each job or session ends with a
# receipt signed by the provider: what ran, for how long, what it cost and the balance left.

USAGE_DOMAIN = b"INNERnet/PAY-1/usage-receipt\x00"
USAGE_SERVICES = {"CMP-1": "CPU-hour", "GPU-1": "GPU-hour", "VPN-1": "GiB"}


def verify_usage(record: dict, provider_id: bytes, client_hex: str) -> dict:
    _exact_keys(record, {"payload", "signature"}, label="usage receipt")
    p = record["payload"]
    if not isinstance(p, dict) or p.get("version") != "PAY-1-USAGE" or p.get("service") not in USAGE_SERVICES:
        raise BulkError("malformed usage receipt")
    for k in ("units", "cost", "balance"):
        _decimal(p.get(k), f"usage {k}")
    if p.get("provider") != bytes(provider_id).hex() or p.get("client") != client_hex or p.get("asset") != "USDC":
        raise BulkError("usage receipt for a different provider or client")
    try:
        Ed25519PublicKey.from_public_bytes(provider_id).verify(
            _bytes(record["signature"], 64, "usage signature"), USAGE_DOMAIN + canonical(p))
    except (ValueError, InvalidSignature) as exc:
        raise BulkError("usage receipt signature invalid") from exc
    return p


# ---- provider login (web dashboard bootstrap) ------------------------------
# The CLI proves it holds the provider key by signing a one-time challenge.
# The registry then hands out a short-lived link where the provider can
# register a WebAuthn passkey for the web dashboard. The passkey never signs
# protocol messages; only the provider key does.

LOGIN_DOMAIN = b"INNERnet/REG-1/provider-login\x00"
LOGIN_VERSION = "REG-1-LOGIN"
LOGIN_TTL = 300


def make_login_challenge(*, now: int | None = None) -> dict:
    import secrets
    instant = int(time.time()) if now is None else now
    return {"challenge": secrets.token_hex(32), "expires_at": instant + LOGIN_TTL}


def verify_login(record: dict, *, expected_challenge: str, registry_host: str,
                 now: int | None = None) -> bytes:
    """Return the provider id (32 bytes) if the record answers our challenge."""
    _exact_keys(record, {"payload", "signature"}, label="login record")
    payload = record["payload"]
    _exact_keys(payload, {"version", "provider", "challenge", "registry", "expires_at"}, label="login payload")
    if payload["version"] != LOGIN_VERSION:
        raise BulkError("unsupported login version")
    if payload["challenge"] != expected_challenge or not re.match(r"^[0-9a-f]{64}$", str(expected_challenge)):
        raise BulkError("login challenge mismatch")
    if payload["registry"] != registry_host:
        raise BulkError("login was signed for a different registry")
    expires = _int(payload["expires_at"], 0, 2**53, "login expires_at")
    if (int(time.time()) if now is None else now) > expires:
        raise BulkError("login challenge expired")
    provider = _bytes(payload["provider"], 32, "provider id")
    try:
        Ed25519PublicKey.from_public_bytes(provider).verify(
            _bytes(record["signature"], 64, "login signature"), LOGIN_DOMAIN + canonical(payload))
    except (ValueError, InvalidSignature) as exc:
        raise BulkError("login signature invalid") from exc
    return provider


# ---- machine connect (web setup) --------------------------------------------
# `innernet-provider start` signs what it detected on the machine with the
# provider key. The registry answers with a one-time claim code. The person
# enters the code on the website, adds a passkey and chooses the offer; the
# machine then signs the final descriptor itself. The key never leaves it.

CONNECT_DOMAIN = b"INNERnet/REG-1/provider-connect\x00"
# A setup chosen on the website: the person's passkey signs SHA-256(SETUP_DOMAIN || canonical(setup)),
# and the machine checks that signature against the passkeys it trusts before it signs the offer.
SETUP_DOMAIN = b"INNERnet/REG-1/setup-offer\x00"
SETUP_VERSION = "REG-1-SETUP"


def setup_challenge(setup: dict) -> bytes:
    return hashlib.sha256(SETUP_DOMAIN + canonical(setup)).digest()


def valid_seal_key(value) -> bool:
    """An uncompressed P-256 public key, base64url without padding (the browser seals the backup passphrase to it)."""
    if not isinstance(value, str) or not re.match(r"^[A-Za-z0-9_-]{87}$", value):
        return False
    raw = base64.urlsafe_b64decode(value + "=")
    return len(raw) == 65 and raw[0] == 4
CONNECT_VERSION = "REG-1-CONNECT"
_DETECTED_KEYS = {"name": str, "region": str, "host": str, "port": int, "storage_free_gib": int, "cpus": int,
                  "memory_mib": int, "os": str, "arch": str, "reachable": bool, "version": str, "class": str,
                  "tz": str, "port_map": str, "path": str, "gpus": list, "seal_key": str}


def verify_connect(record: dict, *, now: int | None = None, max_age: int = 300) -> tuple[bytes, dict]:
    """Return (provider id, detected facts) for a fresh, correctly signed connect record."""
    _exact_keys(record, {"payload", "signature"}, label="connect record")
    payload = record["payload"]
    _exact_keys(payload, {"version", "provider", "detected", "nonce", "issued_at"}, label="connect payload")
    if payload["version"] != CONNECT_VERSION:
        raise BulkError("unsupported connect version")
    issued = _int(payload["issued_at"], 0, 2**53, "connect issued_at")
    instant = int(time.time()) if now is None else now
    if not instant - max_age <= issued <= instant + FUTURE_SKEW:
        raise BulkError("connect record is stale")
    if not isinstance(payload["nonce"], str) or not re.match(r"^[0-9a-f]{32}$", payload["nonce"]):
        raise BulkError("invalid connect nonce")
    detected = payload["detected"]
    if not isinstance(detected, dict) or not set(detected) <= set(_DETECTED_KEYS):
        raise BulkError("invalid detected facts")
    for key, value in detected.items():
        kind = _DETECTED_KEYS[key]
        if kind is list:
            validate_gpus(value)
        elif kind is int:
            _int(value, 0, 2**40, f"detected {key}")
        elif type(value) is not kind or (kind is str and len(value) > 253):
            raise BulkError(f"invalid detected {key}")
        elif key == "seal_key" and not valid_seal_key(value):
            raise BulkError("invalid detected seal_key")
    provider = _bytes(payload["provider"], 32, "provider id")
    try:
        Ed25519PublicKey.from_public_bytes(provider).verify(
            _bytes(record["signature"], 64, "connect signature"), CONNECT_DOMAIN + canonical(payload))
    except (ValueError, InvalidSignature) as exc:
        raise BulkError("connect signature invalid") from exc
    return provider, detected


# ---- live presence (REG-1-PRESENCE) -------------------------------------------
# `innernet-provider serve` signs a short record about once a minute: where it can be
# reached right now, how, and a few usage counters. The registry keeps the latest one
# and hands it to clients as is, so it cannot invent an address for a provider.

PRESENCE_DOMAIN = b"INNERnet/REG-1/provider-presence\x00"
PRESENCE_VERSION = "REG-1-PRESENCE"
PATHS = {"direct", "router", "relay", "tunnel"}   # relay: RLY-0 over ST81; tunnel: HTTPS fallback
_STAT_KEYS = {"stored_bytes", "leases", "requests_24h", "served_bytes_24h", "challenges_24h", "payments_24h",
              "uptime_s", "storage_limit_bytes",
              # live compute capacity: clients prefer providers with free CPU or GPU
              "cpu_slots", "cpu_free", "gpu_slots", "gpu_free", "compute_mem_free_mib", "queued"}


def verify_presence(record: dict, *, now: int | None = None, max_age: int = 300) -> dict:
    """Return the payload of a fresh, correctly signed presence record."""
    _exact_keys(record, {"payload", "signature"}, label="presence record")
    p = record["payload"]
    _exact_keys(p, {"version", "provider", "endpoint", "path", "seq", "issued_at", "stats", "software"},
                {"relay_key"}, label="presence payload")
    if (p.get("path") == "relay") != ("relay_key" in p):
        raise BulkError("relay_key goes with path relay, and only with it")
    if "relay_key" in p:
        _bytes(p["relay_key"], 32, "relay key")
    if p["version"] != PRESENCE_VERSION:
        raise BulkError("unsupported presence version")
    issued = _int(p["issued_at"], 0, 2**53, "presence issued_at")
    instant = int(time.time()) if now is None else now
    if not instant - max_age <= issued <= instant + FUTURE_SKEW:
        raise BulkError("presence record is stale")
    _int(p["seq"], 1, 2**62, "presence seq")
    ep = p["endpoint"]
    _exact_keys(ep, {"host", "port"}, label="presence endpoint")
    if not isinstance(ep["host"], str) or not _HOST.match(ep["host"]):
        raise BulkError("invalid presence host")
    _int(ep["port"], 1, 65535, "presence port")
    if p["path"] not in PATHS:
        raise BulkError("invalid presence path")
    stats = p["stats"]
    if not isinstance(stats, dict) or not set(stats) <= _STAT_KEYS:
        raise BulkError("invalid presence stats")
    for k, v in stats.items():
        _int(v, 0, 2**62, f"presence {k}")
    if not isinstance(p["software"], str) or len(p["software"]) > 64:
        raise BulkError("invalid presence software")
    provider = _bytes(p["provider"], 32, "provider id")
    try:
        Ed25519PublicKey.from_public_bytes(provider).verify(
            _bytes(record["signature"], 64, "presence signature"), PRESENCE_DOMAIN + canonical(p))
    except (ValueError, InvalidSignature) as exc:
        raise BulkError("presence signature invalid") from exc
    return p


# ---- provider intents (pause, resume, leave, reinstate) ------------------------

INTENT_DOMAIN = b"INNERnet/REG-1/provider-intent\x00"
INTENT_VERSION = "REG-1-INTENT"
INTENTS = {"pause", "resume", "leave", "reinstate"}
MACHINE_ACTIONS = INTENTS | {"passkey-list", "passkey-remove", "pairing-set", "setup-fetch"}
_TARGETED = {"passkey-remove", "pairing-set"}   # pairing-set: target is SHA-256 hex of the machine code


def verify_intent(record: dict, *, now: int | None = None, max_age: int = 300) -> tuple[bytes, str, str]:
    """Return (provider id, action, nonce) for a fresh, correctly signed intent."""
    _exact_keys(record, {"payload", "signature"}, label="intent record")
    p = record["payload"]
    _exact_keys(p, {"version", "provider", "action", "nonce", "issued_at"}, {"target"}, label="intent payload")
    if p["version"] != INTENT_VERSION or p["action"] not in MACHINE_ACTIONS:
        raise BulkError("unsupported intent")
    if ("target" in p) != (p["action"] in _TARGETED) or ("target" in p and (
            not isinstance(p["target"], str) or not 1 <= len(p["target"]) <= 128)):
        raise BulkError("invalid intent target")
    if p["action"] == "pairing-set" and not re.match(r"^[0-9a-f]{64}$", p["target"]):
        raise BulkError("pairing-set needs the SHA-256 of the machine code")
    issued = _int(p["issued_at"], 0, 2**53, "intent issued_at")
    instant = int(time.time()) if now is None else now
    if not instant - max_age <= issued <= instant + FUTURE_SKEW:
        raise BulkError("intent is stale")
    if not isinstance(p["nonce"], str) or not re.match(r"^[0-9a-f]{32}$", p["nonce"]):
        raise BulkError("invalid intent nonce")
    provider = _bytes(p["provider"], 32, "provider id")
    try:
        Ed25519PublicKey.from_public_bytes(provider).verify(
            _bytes(record["signature"], 64, "intent signature"), INTENT_DOMAIN + canonical(p))
    except (ValueError, InvalidSignature) as exc:
        raise BulkError("intent signature invalid") from exc
    return provider, p["action"], p["nonce"]


def intent_target(record: dict) -> str:
    return record["payload"].get("target", "")


def in_hours(entry: dict, instant: int) -> bool:
    """Is `instant` inside the provider's promised hours? No hours means always."""
    av = entry.get("availability")
    if av is None:
        return True
    from datetime import datetime, timedelta, timezone
    tz = av["tz"]
    try:
        if tz.startswith("UTC") and len(tz) == 9:
            sign = 1 if tz[3] == "+" else -1
            zone = timezone(sign * timedelta(hours=int(tz[4:6]), minutes=int(tz[7:9])))
        elif tz == "UTC":
            zone = timezone.utc
        else:
            from zoneinfo import ZoneInfo
            zone = ZoneInfo(tz)
    except Exception:
        return True                                   # unknown zone: do not penalise
    local = datetime.fromtimestamp(instant, zone)
    minute = local.hour * 60 + local.minute
    return any(w[0] == local.weekday() and w[1] <= minute < w[2] for w in av["weekly"])
