"""Provider relay tunnel (IRM-1 section 3.4b, draft).

A provider that cannot accept incoming connections (behind a home router, or an internet
provider that shares one public address between customers) keeps a few outgoing HTTPS
long-polls open to the registry. Clients send their STO-1 requests to

    https://innernetcorp.com/registry/t/<provider id>/<path>

and the registry hands each one to the provider over its next poll, then returns the
provider's answer. The relay never sees content: requests are signed by clients and
answers by the provider, end to end, and stored data is sealed and mixed before upload.

Limits keep the operator's server safe: only listed paths, bounded bodies, a few requests
in flight per provider, and a daily byte budget per provider.
"""
from __future__ import annotations

import asyncio
import base64
import re
import secrets
import time
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

TUNNEL_DOMAIN = b"INNERnet/REG-1/provider-tunnel\x00"
POLL_SECONDS = 25            # a poll returns empty after this long
ANSWER_SECONDS = 30          # a client waits this long for the provider's answer
ATTACHED_WITHIN = 40         # seconds since the last poll to count as attached
MAX_BODY = 2 * 1024 * 1024 + 1024
MAX_IN_FLIGHT = 16
DAILY_BYTES = 4 * 1024 ** 3  # per provider, both directions (testnet budget)
FORWARD_PATHS = re.compile(r"^/(healthz|reach/[0-9a-f]{32}|sto/v1/[A-Za-z0-9/_.-]{1,200})$")
PASS_HEADERS = ("content-type", "x-innernet-client", "x-innernet-time", "x-innernet-nonce", "x-innernet-signature",
                "x-innernet-provider")


class TunnelError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


@dataclass
class Slot:
    queue: asyncio.Queue = field(default_factory=asyncio.Queue)
    waiting: dict = field(default_factory=dict)          # request id -> Future
    last_poll: float = 0.0
    day: int = 0
    used: int = 0
    seen: dict = field(default_factory=dict)             # poll signature -> expiry (replay guard)


class Tunnels:
    def __init__(self, now=time.time):
        self.slots: dict[str, Slot] = {}
        self.now = now

    def slot(self, pid: str) -> Slot:
        return self.slots.setdefault(pid, Slot())

    def attached(self, pid: str) -> bool:
        s = self.slots.get(pid)
        return bool(s and self.now() - s.last_poll <= ATTACHED_WITHIN)

    # ---- provider side --------------------------------------------------------
    def authenticate(self, pid: str, headers, kind: str) -> None:
        """Polls and replies carry a signature by the provider key over
        domain || kind \\n pid \\n time \\n nonce; fresh within 120 s, single use."""
        ts, nonce, sig = headers.get("x-innernet-time", ""), headers.get("x-innernet-nonce", ""), \
            headers.get("x-innernet-signature", "")
        if not (ts.isdigit() and re.match(r"^[0-9a-f]{32}$", nonce) and re.match(r"^[0-9a-f]{128}$", sig)):
            raise TunnelError(401, "signed tunnel headers required")
        if abs(int(ts) - self.now()) > 120:
            raise TunnelError(401, "tunnel request is stale")
        s = self.slot(pid)
        if sig in s.seen:
            raise TunnelError(401, "tunnel request replayed")
        msg = TUNNEL_DOMAIN + f"{kind}\n{pid}\n{ts}\n{nonce}".encode()
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pid)).verify(bytes.fromhex(sig), msg)
        except (ValueError, InvalidSignature):
            raise TunnelError(401, "tunnel signature invalid") from None
        now = self.now()
        s.seen = {k: v for k, v in s.seen.items() if v > now}
        s.seen[sig] = now + 240

    async def poll(self, pid: str, wait: float = POLL_SECONDS) -> dict | None:
        s = self.slot(pid)
        s.last_poll = self.now()
        try:
            item = await asyncio.wait_for(s.queue.get(), timeout=wait)
        except asyncio.TimeoutError:
            s.last_poll = self.now()
            return None
        s.last_poll = self.now()
        return item

    def reply(self, pid: str, rid: str, answer: dict) -> None:
        s = self.slot(pid)
        fut = s.waiting.pop(rid, None)
        if fut is None or fut.done():
            raise TunnelError(404, "no client is waiting for this answer")
        body = base64.b64decode(answer.get("body", ""))
        if len(body) > MAX_BODY:
            fut.set_exception(TunnelError(502, "provider answer too large"))
            raise TunnelError(413, "answer too large")
        self._count(s, len(body))
        fut.set_result({"status": int(answer.get("status", 502)), "body": body,
                        "headers": {k.lower(): str(v) for k, v in (answer.get("headers") or {}).items()
                                    if k.lower() in PASS_HEADERS}})

    # ---- client side ------------------------------------------------------------
    async def forward(self, pid: str, method: str, path: str, headers, body: bytes) -> dict:
        if not FORWARD_PATHS.match(path):
            raise TunnelError(404, "not a provider path")
        if len(body) > MAX_BODY:
            raise TunnelError(413, "request too large")
        if not self.attached(pid):
            raise TunnelError(503, "provider is not connected to the relay right now")
        s = self.slot(pid)
        if len(s.waiting) >= MAX_IN_FLIGHT:
            raise TunnelError(429, "provider is busy; try again")
        self._count(s, len(body))
        rid = secrets.token_hex(12)
        fut = asyncio.get_running_loop().create_future()
        s.waiting[rid] = fut
        await s.queue.put({"id": rid, "method": method, "path": path,
                           "headers": {k: v for k, v in headers.items() if k.lower() in PASS_HEADERS},
                           "body": base64.b64encode(body).decode()})
        try:
            return await asyncio.wait_for(fut, timeout=ANSWER_SECONDS)
        except asyncio.TimeoutError:
            s.waiting.pop(rid, None)
            raise TunnelError(504, "provider did not answer in time") from None

    def _count(self, s: Slot, n: int) -> None:
        day = int(self.now() // 86400)
        if s.day != day:
            s.day, s.used = day, 0
        s.used += n
        if s.used > DAILY_BYTES:
            raise TunnelError(429, "this provider used up today's relay budget")
