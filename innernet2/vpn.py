"""VPN-1 client: a local SOCKS5 proxy whose connections leave to the internet through an INNERnet
provider's VPN exit. Each connection is its own ST81 session to the provider (direct, or end to end
through a relay), so the traffic is sealed between this device and the exit.

    python -m innernet2.vpn --provider <provider id> [--listen 127.0.0.1:1080]

Point a browser or app at SOCKS5 127.0.0.1:1080 (with remote DNS, so names resolve at the exit).
Credit on the provider comes first (Provider.credit); traffic is charged per GiB as it flows, and
each connection ends with a usage receipt signed by the provider."""
from __future__ import annotations

import argparse
import ipaddress
import socket
import struct
import threading

from .bulk_v080 import BulkError
from .irm_client import Client, Provider, ProviderError
from .irm_registry import verify_usage

CHUNK = 64 * 1024


class ExitError(Exception):
    pass


def open_exit(provider: Provider, host: str, port: int):
    """An ST81 session to the provider's VPN exit, connected to host:port."""
    sess = provider.open_session()
    sess.sock.settimeout(30)
    sess.write({"op": "vpn-connect", "host": host, "port": port, "terms": provider.terms})
    head, _ = sess.read()
    if head.get("ok") is not True:
        sess.sock.close()
        raise ExitError(str(head.get("error", "exit refused")))
    sess.sock.settimeout(600)
    return sess


def bridge(local: socket.socket, sess, provider: Provider, receipts: list | None = None) -> None:
    """Carry bytes both ways until either side ends; keep the provider's receipt."""
    def up():
        try:
            while True:
                data = local.recv(CHUNK)
                if not data:
                    break
                sess.write({"op": "data"}, data)
        except OSError:
            pass
        try:
            sess.write({"op": "end"})          # anything but "data" ends the connection at the exit
        except OSError:
            pass
    t = threading.Thread(target=up, daemon=True)
    t.start()
    try:
        while True:
            head, data = sess.read()
            if head.get("op") == "data":
                local.sendall(data)
                continue
            if head.get("op") == "close" and head.get("receipt") and receipts is not None:
                me = provider.key.public_key().public_bytes_raw().hex()
                receipts.append(verify_usage(head["receipt"], bytes.fromhex(provider.id), me))
            break
    except Exception:  # noqa: BLE001 - any read error ends the connection
        pass
    finally:
        try:
            local.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        local.close()
        try:
            sess.sock.close()
        except OSError:
            pass


def _socks_request(c: socket.socket) -> tuple[str, int]:
    def need(n):
        b = b""
        while len(b) < n:
            chunk = c.recv(n - len(b))
            if not chunk:
                raise ExitError("client went away")
            b += chunk
        return b
    ver, n = need(2)
    if ver != 5:
        raise ExitError("SOCKS5 only")
    need(n)
    c.sendall(b"\x05\x00")                                   # no authentication: listens on this device only
    ver, cmd, _, atyp = need(4)
    if cmd != 1:
        c.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)          # only CONNECT
        raise ExitError("only CONNECT is supported")
    if atyp == 1:
        host = str(ipaddress.IPv4Address(need(4)))
    elif atyp == 3:
        host = need(need(1)[0]).decode("idna")
    elif atyp == 4:
        host = str(ipaddress.IPv6Address(need(16)))
    else:
        raise ExitError("bad address")
    (port,) = struct.unpack(">H", need(2))
    return host, port


def serve_socks(provider: Provider, listen: tuple[str, int], receipts: list | None = None,
                ready: threading.Event | None = None, stop: threading.Event | None = None) -> None:
    srv = socket.create_server(listen)
    srv.settimeout(0.5)
    if ready:
        ready.port = srv.getsockname()[1]
        ready.set()

    def handle(c: socket.socket):
        try:
            host, port = _socks_request(c)
            try:
                sess = open_exit(provider, host, port)
            except (ExitError, ProviderError, OSError) as exc:
                c.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)  # connection refused
                raise ExitError(str(exc))
            c.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
            bridge(c, sess, provider, receipts)
        except (ExitError, OSError):
            c.close()

    while not (stop and stop.is_set()):
        try:
            c, _ = srv.accept()
        except socket.timeout:
            continue
        threading.Thread(target=handle, args=(c,), daemon=True).start()
    srv.close()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="SOCKS5 proxy through an INNERnet VPN exit")
    ap.add_argument("--registry", default="https://innernetcorp.com/registry/v1")
    ap.add_argument("--provider", help="provider id (default: the exit with the most room, then the cheapest)")
    ap.add_argument("--listen", default="127.0.0.1:1080")
    ap.add_argument("--accept-terms", required=True, help="SHA-256 of the client terms you agreed to (/registry/terms)")
    a = ap.parse_args(argv)
    client = Client(registry_url=a.registry, presence_url=a.registry, accept_terms=a.accept_terms)
    exits = [e for e in client.compute_providers("VPN-1") if not a.provider or e["id"] == a.provider]
    if not exits:
        raise SystemExit("no VPN exit found")
    provider = client.provider(exits[0])
    host, port = a.listen.rsplit(":", 1)
    print(f"SOCKS5 on {host}:{port} -> VPN exit {provider.entry['name']} ({provider.id[:12]}…). Ctrl+C to stop.")
    try:
        serve_socks(provider, (host, int(port)))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
