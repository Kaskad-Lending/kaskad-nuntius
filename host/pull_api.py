#!/usr/bin/env python3
"""Keyex host pull API: nuntius (CloudFront) -> ALB -> :8080 -> VSOCK CID16:5001.

GET /prices, /prices/{SYMBOL}, /health, /attestation. A 503 means this host cannot
serve (enclave down, refusing or empty), so the edge fails over to the other region.
Rate limit: 60 req/min per real client IP. Serves only signed data, holds no secrets.
"""

import ipaddress
import json
import os
import re
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

# Per-connection read timeout, applied by `PullAPIHandler.timeout`.
HTTP_READ_TIMEOUT = 15

# Real-client-IP resolution behind the ALB. Only the ALB (inside VPC_CIDR) can
# reach :8080, so X-Forwarded-For is trusted only from in-VPC peers.
_VPC_CIDR_STR = os.environ.get("VPC_CIDR", "10.0.0.0/16")
try:
    _VPC_CIDR = ipaddress.ip_network(_VPC_CIDR_STR)
except ValueError:
    print(f"[pull-api] WARN: invalid VPC_CIDR={_VPC_CIDR_STR!r}, falling back to 10.0.0.0/16",
          file=sys.stderr)
    _VPC_CIDR = ipaddress.ip_network("10.0.0.0/16")

# The ALB forwards this Host only with our distribution's origin header, so for
# it the hop CloudFront appended (second to last) is the viewer. Empty disables.
EDGE_HOST = os.environ.get("EDGE_HOST", "").lower()

# price_server.rs get_price miss; any other get_price error is a host failure.
UNKNOWN_ASSET = re.compile(r"^asset '.*' not found$")


def get_client_ip(handler):
    """Return the real client IP. Trusts `X-Forwarded-For` only when the
    immediate peer is inside the VPC (i.e. our ALB). For anything else
    the peer address is returned as-is."""
    peer_str = handler.client_address[0]
    try:
        peer = ipaddress.ip_address(peer_str)
    except (ValueError, TypeError):
        return peer_str

    if peer not in _VPC_CIDR:
        # Direct hit (dev / mis-routed) — peer IS the client, do not
        # honour `X-Forwarded-For` (spoofable in this case).
        return str(peer)

    # The ALB runs `xff_header_processing_mode = "append"`, so it appends the
    # address it observed to whatever the client sent: the LAST entry is the
    # only one the ALB vouches for. Taking the first would let a caller set
    # the header and mint a fresh rate-limit bucket per request.
    forwarded = handler.headers.get_all("X-Forwarded-For", [])
    if not forwarded:
        return str(peer)
    # More than one header, or control characters, means a splitting attempt:
    # refuse to parse and rate-limit on the ALB instead.
    if len(forwarded) != 1 or any(c in forwarded[0] for c in "\r\n%"):
        return str(peer)
    try:
        # Validate the whole chain: one bad hop invalidates the header.
        chain = [ipaddress.ip_address(tok.strip(" \t")) for tok in forwarded[0].split(",")]
    except ValueError:
        return str(peer)
    if not chain:
        return str(peer)
    if len(chain) >= 2 and _via_edge(handler):
        return str(chain[-2])
    return str(chain[-1])


def _via_edge(handler):
    """Exact edge Host only: a looser match could pass where the ALB rule does not."""
    if not EDGE_HOST:
        return False
    hosts = handler.headers.get_all("Host", [])
    return len(hosts) == 1 and hosts[0].lower() == EDGE_HOST


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

class EnclaveUnavailable(Exception):
    """VSOCK transport failed: this host cannot answer."""


def query_enclave(method, asset=None, timeout=10):
    """Send one request to the enclave; raise EnclaveUnavailable on transport failure."""
    request = {"method": method}
    if asset:
        request["asset"] = asset

    request_bytes = json.dumps(request).encode("utf-8")

    try:
        with socket.socket(AF_VSOCK, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ENCLAVE_CID, VSOCK_PORT))

            # Send: [4 bytes length][payload]
            sock.sendall(struct.pack(">I", len(request_bytes)))
            sock.sendall(request_bytes)

            # Receive: [4 bytes length][payload]
            length_bytes = recv_exact(sock, 4)
            if not length_bytes:
                raise EnclaveUnavailable("enclave connection closed")
            length = struct.unpack(">I", length_bytes)[0]

            response_bytes = recv_exact(sock, length)
            if not response_bytes:
                raise EnclaveUnavailable("enclave response truncated")

        response = json.loads(response_bytes.decode("utf-8"))
    except EnclaveUnavailable:
        raise
    except ConnectionRefusedError:
        raise EnclaveUnavailable("enclave not running") from None
    except socket.timeout:
        raise EnclaveUnavailable("enclave timeout") from None
    except Exception as e:
        raise EnclaveUnavailable(f"enclave error: {e}") from None
    if not isinstance(response, dict):
        raise EnclaveUnavailable("enclave response is not an object")
    return response


def recv_exact(sock, n):
    """Receive exactly n bytes."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def route(raw_path):
    """Map a request path to (status, body). Raises EnclaveUnavailable."""
    path = raw_path.split("?", 1)[0].rstrip("/")

    if path == "/prices":
        result = query_enclave("get_prices")
        ok = bool(result.get("prices")) and "error" not in result
        return (200 if ok else 503), result

    if path.startswith("/prices/"):
        asset = path[len("/prices/"):].upper().replace("%2F", "/")
        result = query_enclave("get_price", asset=asset)
        if result.get("price"):
            return 200, result
        unknown = UNKNOWN_ASSET.match(str(result.get("error", "")))
        return (404 if unknown else 503), result

    if path == "/health":
        result = query_enclave("health")
        return (200 if result.get("status") == "ok" else 503), result

    if path == "/attestation":
        result = query_enclave("get_attestation")
        return (200 if result.get("attestation_doc") else 503), result

    if path == "":
        return 200, {
            "service": "Kaskad TEE Oracle",
            "version": "0.1.0",
            "endpoints": ["/prices", "/prices/{SYMBOL}", "/health", "/attestation"],
            "docs": "Query signed price data from Nitro Enclave",
        }

    return 404, {"error": "not found"}


# ─── HTTP Handler ────────────────────────────────────────────

class PullAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the pull API."""

    # Slowloris guard. The concurrency semaphore is acquired in `do_GET`, i.e.
    # only after the request line is parsed, so a client that connects and stays
    # silent never reaches it. This bounds that wait.
    timeout = HTTP_READ_TIMEOUT

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
        # Rate limit check — keyed on the real client IP, not the ALB.
        client_ip = get_client_ip(self)
        if not rate_limiter.is_allowed(client_ip):
            self.send_json(429, {
                "error": "rate limit exceeded",
                "retry_after": RATE_WINDOW,
            })
            return

        try:
            status, body = route(self.path)
        except EnclaveUnavailable as exc:
            status, body = 503, {"error": str(exc)}
        self.send_json(status, body)

    def send_json(self, status, data):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("X-RateLimit-Remaining", str(rate_limiter.remaining(get_client_ip(self))))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        """Override to use structured logging."""
        print(f"[pull-api] {get_client_ip(self)} - {format % args}")


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
    print(f"[pull-api] Edge host: {EDGE_HOST or '(none)'}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[pull-api] Shutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
