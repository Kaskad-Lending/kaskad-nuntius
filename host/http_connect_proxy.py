#!/usr/bin/env python3
"""HTTP CONNECT proxy (stdlib only) for enclave outbound TLS.

Listens on 127.0.0.1:8888. Both keyex enclaves reach it through the egress
chain: in-enclave 127.0.0.1:5000 → socat VSOCK-LISTEN:5000 → here. Used for
Robinhood/Igra RPC over TLS and for RA-TLS peer fetches (CONNECT peer:8443).
TLS terminates inside the enclave; this proxy only tunnels bytes.
"""
from __future__ import annotations

import argparse
import logging
import select
import socket
import sys
import threading

log = logging.getLogger("connect-proxy")

BUF = 65536
CONNECT_TIMEOUT = 10
IDLE_TIMEOUT = 300  # drop a tunnel idle this long, both directions


def _pump(a: socket.socket, b: socket.socket) -> None:
    """Bidirectional relay until either side closes or goes idle."""
    socks = [a, b]
    try:
        while True:
            readable, _, errored = select.select(socks, [], socks, IDLE_TIMEOUT)
            if errored or not readable:
                break
            for src in readable:
                dst = b if src is a else a
                data = src.recv(BUF)
                if not data:
                    return
                dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass


def _handle(client: socket.socket) -> None:
    try:
        client.settimeout(CONNECT_TIMEOUT)
        header = b""
        while b"\r\n\r\n" not in header:
            chunk = client.recv(4096)
            if not chunk:
                client.close()
                return
            header += chunk
            if len(header) > 8192:
                client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                client.close()
                return

        line = header.split(b"\r\n", 1)[0].decode("latin-1")
        parts = line.split()
        if len(parts) < 2 or parts[0] != "CONNECT":
            client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            client.close()
            return

        host_port = parts[1]
        host, _, port_s = host_port.rpartition(":")
        if not host:
            host, port = host_port, 443
        else:
            port = int(port_s)

        remote = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
        client.settimeout(None)
        remote.settimeout(None)
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        _pump(client, remote)
    except (OSError, ValueError) as e:
        log.info("tunnel error: %s", e)
        try:
            client.close()
        except OSError:
            pass


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s",
                        stream=sys.stdout)
    p = argparse.ArgumentParser(description="Enclave egress HTTP CONNECT proxy")
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8888)
    args = p.parse_args(argv)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, args.port))
    srv.listen(128)
    log.info("listening on %s:%d", args.bind, args.port)
    try:
        while True:
            client, _ = srv.accept()
            threading.Thread(target=_handle, args=(client,), daemon=True).start()
    except KeyboardInterrupt:
        log.info("shutting down")
    finally:
        srv.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
