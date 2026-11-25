"""RLY-0 client: reach a provider through an ST81 relay (IRM-1 section 3.4b, draft).

    client --ST81--> relay   {"op":"open","to":<provider id>}  -> {"ok":true}
    then {"op":"data"} frames carry the bytes of a second ST81 session, end to end
    between client and provider and pinned to the provider key. The relay cannot read
    or change anything; it only forwards ciphertext.
"""
from __future__ import annotations

import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import stream_v080 as st

CHUNK = 64 * 1024


class RelayedSocket:
    """The socket methods stream_v080 uses, carried inside an outer ST81 session."""

    def __init__(self, outer: st.Session, timeout: float):
        self.outer, self._buf, self._timeout = outer, b"", timeout

    def settimeout(self, value):
        self._timeout = value

    def gettimeout(self):
        return self._timeout

    def recv(self, n: int) -> bytes:
        if not self._buf:
            deadline = time.monotonic() + (self._timeout if self._timeout is not None else 600)
            self.outer.sock.settimeout(max(0.001, deadline - time.monotonic()))
            head, body = self.outer.read(deadline=deadline)
            if head.get("op") != "data":
                return b""
            self._buf = body
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def sendall(self, data: bytes) -> None:
        for i in range(0, len(data), CHUNK):
            self.outer.write({"op": "data"}, data[i:i + CHUNK])

    def close(self) -> None:
        self.outer.sock.close()


def connect(relay_host: str, relay_port: int, relay_key: bytes, provider: bytes, key: Ed25519PrivateKey,
            *, timeout: float = 10) -> st.Session:
    """End-to-end ST81 session with `provider`, carried through the relay."""
    outer = st.connect(relay_host, relay_port, key, relay_key, timeout=timeout)
    try:
        outer.write({"op": "open", "to": provider.hex()})
        head, _ = outer.read()
        if head.get("ok") is not True:
            raise st.StreamError(f"relay: {head.get('error', 'refused')}")
        return st.handshake(RelayedSocket(outer, timeout), key, provider, timeout=timeout)
    except BaseException:
        outer.sock.close()
        raise
