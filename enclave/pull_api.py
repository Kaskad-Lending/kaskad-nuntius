#!/usr/bin/env python3
"""
Pull API — runs on the EC2 host (parent instance).
Provides an HTTP interface to query the Nitro Enclave for signed price data.

Architecture:
  Internet → HTTP:8080 → pull_api.py → VSOCK:5001 → Enclave

Endpoints:
  GET /prices          → all signed prices
  GET /prices/{symbol} → single asset (e.g., /prices/ETH/USD)
  GET /health          → enclave health status

Security:
  - Rate-limit: 60 requests/minute per IP (token bucket)
  - No secrets exposed — only signed price data
"""

import json
import socket
import struct
import sys
import time
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from collections import defaultdict

# VSOCK constants
AF_VSOCK = 40
ENCLAVE_CID = 16  # Default enclave CID (set by nitro-cli)
VSOCK_PORT = 5001

# Rate limiting
RATE_LIMIT = 60        # requests per window
RATE_WINDOW = 60       # seconds

# Concurrency cap. `ThreadingHTTPServer` spawns a fresh thread per request
# unbounded — one slowloris-style client can exhaust threads / FDs. This
# semaphore caps simultaneous in-flight handlers; overflow returns 503.
MAX_CONCURRENT = 64
_concurrency = threading.Semaphore(MAX_CONCURRENT)

# ─── Rate Limiter ────────────────────────────────────────────

class RateLimiter:
    """Simple token-bucket rate limiter per IP."""

    def __init__(self, limit=RATE_LIMIT, window=RATE_WINDOW):
        self.limit = limit
        self.window = window
        self.clients = defaultdict(lambda: {"tokens": limit, "last": time.time()})
        self.lock = threading.Lock()

    def is_allowed(self, ip):
        with self.lock:
            now = time.time()
            client = self.clients[ip]

            # Refill tokens
            elapsed = now - client["last"]
            client["tokens"] = min(
                self.limit,
                client["tokens"] + elapsed * (self.limit / self.window)
            )
            client["last"] = now

            if client["tokens"] >= 1:
                client["tokens"] -= 1
                return True
            return False

    def remaining(self, ip):
        with self.lock:
            return int(self.clients[ip]["tokens"])


rate_limiter = RateLimiter()

# ─── VSOCK Client ────────────────────────────────────────────

def query_enclave(method, asset=None, timeout=10):
    """Send a request to the enclave via VSOCK and return the response."""
    request = {"method": method}
    if asset:
        request["asset"] = asset

    request_bytes = json.dumps(request).encode("utf-8")

    try:
        sock = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ENCLAVE_CID, VSOCK_PORT))

        # Send: [4 bytes length][payload]
        sock.sendall(struct.pack(">I", len(request_bytes)))
        sock.sendall(request_bytes)

        # Receive: [4 bytes length][payload]
        length_bytes = recv_exact(sock, 4)
        if not length_bytes:
            return {"error": "enclave connection closed"}
        length = struct.unpack(">I", length_bytes)[0]

        response_bytes = recv_exact(sock, length)
        if not response_bytes:
            return {"error": "enclave response truncated"}

        sock.close()
        return json.loads(response_bytes.decode("utf-8"))

    except ConnectionRefusedError:
        return {"error": "enclave not running"}
    except socket.timeout:
        return {"error": "enclave timeout"}
    except Exception as e:
        return {"error": f"enclave error: {str(e)}"}


def recv_exact(sock, n):
    """Receive exactly n bytes."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


# ─── HTTP Handler ────────────────────────────────────────────

class PullAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the pull API."""

    def do_GET(self):
        # Concurrency gate: non-blocking acquire — if MAX_CONCURRENT
        # handlers are already in flight, shed load with 503 instead of
        # growing the thread pool unbounded.
        if not _concurrency.acquire(blocking=False):
            self.send_json(503, {"error": "server overloaded, retry"})
            return
        try:
            self._handle_get()
        finally:
            _concurrency.release()

    def _handle_get(self):
        # Rate limit check
        client_ip = self.client_address[0]
        if not rate_limiter.is_allowed(client_ip):
            self.send_json(429, {
                "error": "rate limit exceeded",
                "retry_after": RATE_WINDOW,
            })
            return

        # Route
        path = self.path.rstrip("/")

        if path == "/prices":
            result = query_enclave("get_prices")
            self.send_json(200, result)

        elif path.startswith("/prices/"):
            asset = path[len("/prices/"):]
            asset = asset.replace("%2F", "/").upper()
            result = query_enclave("get_price", asset=asset)
            status = 200 if "error" not in result or result.get("price") else 404
            self.send_json(status, result)

        elif path == "/health":
            result = query_enclave("health")
            status = 200 if result.get("status") == "ok" else 503
            self.send_json(status, result)

        elif path == "/attestation":
            result = query_enclave("get_attestation")
            status = 200 if result.get("attestation_doc") else 404
            self.send_json(status, result)

        elif path == "/" or path == "":
            self.send_json(200, {
                "service": "Kaskad TEE Oracle",
                "version": "0.1.0",
                "endpoints": ["/prices", "/prices/{SYMBOL}", "/health", "/attestation"],
                "docs": "Query signed price data from Nitro Enclave",
            })

        else:
            self.send_json(404, {"error": "not found"})

    def send_json(self, status, data):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("X-RateLimit-Remaining", str(rate_limiter.remaining(self.client_address[0])))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        """Override to use structured logging."""
        print(f"[pull-api] {self.client_address[0]} - {format % args}")


# ─── Main ────────────────────────────────────────────────────

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080

    server = ThreadingHTTPServer(("0.0.0.0", port), PullAPIHandler)
    # Daemonise request threads so shutdown doesn't wait on in-flight
    # handlers that are themselves blocked on a slow VSOCK call.
    server.daemon_threads = True
    print(f"[pull-api] HTTP server listening on port {port}")
    print(f"[pull-api] Rate limit: {RATE_LIMIT} req/{RATE_WINDOW}s per IP")
    print(f"[pull-api] Max concurrent handlers: {MAX_CONCURRENT}")
    print(f"[pull-api] Enclave VSOCK: CID={ENCLAVE_CID} port={VSOCK_PORT}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[pull-api] Shutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
