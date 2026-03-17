#!/usr/bin/env python3
"""
VSOCK Proxy — runs on the EC2 host (parent instance).
Forwards HTTP requests from the Nitro Enclave to the internet.

The enclave has NO network — it communicates with the host via VSOCK only.
This proxy listens on VSOCK and forwards:
  - HTTP/HTTPS requests to CEX APIs  → returns responses
  - JSON-RPC requests to blockchain  → returns responses

Protocol (simple framing over VSOCK):
  Request:  [4 bytes: length][JSON payload]
  Response: [4 bytes: length][JSON payload]

  Request payload:
    {"method": "http", "url": "https://...", "headers": {...}, "body": "..."}

  Response payload:
    {"status": 200, "body": "...", "headers": {...}}
    or
    {"error": "connection refused"}
"""

import json
import socket
import struct
import threading
import sys
import urllib.request
import urllib.error
import ssl
import traceback

# VSOCK constants
AF_VSOCK = 40
VMADDR_CID_ANY = 0xFFFFFFFF
VSOCK_PORT = 5000

def handle_client(conn, addr):
    """Handle a single connection from the enclave."""
    print(f"[proxy] connection from CID={addr[0]} port={addr[1]}")
    try:
        while True:
            # Read request length (4 bytes, big-endian)
            length_bytes = recv_exact(conn, 4)
            if not length_bytes:
                break
            length = struct.unpack(">I", length_bytes)[0]

            # Read request payload
            payload = recv_exact(conn, length)
            if not payload:
                break

            request = json.loads(payload.decode("utf-8"))
            response = process_request(request)

            # Send response
            response_bytes = json.dumps(response).encode("utf-8")
            conn.sendall(struct.pack(">I", len(response_bytes)))
            conn.sendall(response_bytes)

    except Exception as e:
        print(f"[proxy] error: {e}")
        traceback.print_exc()
    finally:
        conn.close()
        print(f"[proxy] connection closed")


def recv_exact(sock, n):
    """Receive exactly n bytes from socket."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def process_request(request):
    """Process a request from the enclave."""
    method = request.get("method", "")

    if method == "http":
        return do_http_request(request)
    else:
        return {"error": f"unknown method: {method}"}


def do_http_request(request):
    """Forward an HTTP request to the internet and return the response."""
    url = request.get("url", "")
    headers = request.get("headers", {})
    body = request.get("body")
    http_method = request.get("http_method", "GET")

    if not url:
        return {"error": "missing url"}

    # Security: whitelist allowed domains
    allowed_domains = [
        "api.binance.com",
        "www.okx.com",
        "api.bybit.com",
        "api.coinbase.com",
        "api.coingecko.com",
        "api.mexc.com",
        "api.kucoin.com",
        "api.gateio.ws",
        # Add your RPC endpoint here
    ]

    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.hostname not in allowed_domains:
        return {"error": f"domain not whitelisted: {parsed.hostname}"}

    try:
        req = urllib.request.Request(
            url,
            data=body.encode("utf-8") if body else None,
            headers=headers,
            method=http_method,
        )

        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            response_body = resp.read().decode("utf-8")
            response_headers = dict(resp.headers)
            return {
                "status": resp.status,
                "body": response_body,
                "headers": response_headers,
            }

    except urllib.error.HTTPError as e:
        return {
            "status": e.code,
            "body": e.read().decode("utf-8", errors="replace"),
            "error": str(e),
        }
    except Exception as e:
        return {"error": str(e)}


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else VSOCK_PORT

    # Create VSOCK socket
    sock = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((VMADDR_CID_ANY, port))
    sock.listen(5)

    print(f"[proxy] VSOCK proxy listening on port {port}")
    print(f"[proxy] whitelisted domains: CEX APIs + RPC endpoints")
    print(f"[proxy] waiting for enclave connections...")

    while True:
        conn, addr = sock.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.daemon = True
        thread.start()


if __name__ == "__main__":
    main()
