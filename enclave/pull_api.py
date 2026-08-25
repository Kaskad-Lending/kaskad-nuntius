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

import ipaddress
import json
import os
import socket
import struct
import sys
import time
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from collections import OrderedDict
from enum import Enum

# VSOCK constants
AF_VSOCK = 40
ENCLAVE_CID = 16  # Default enclave CID (set by nitro-cli)
VSOCK_PORT = 5001

# Rate limiting
RATE_LIMIT = 60        # requests per window
RATE_WINDOW = 60       # seconds

# Cap on distinct rate-limit keys kept in memory. Buckets idle for a full
# window are dropped first — they have provably refilled to RATE_LIMIT and
# carry no information — so the cap only bites under a key-flooding attack.
MAX_TRACKED_KEYS = 50_000

# Concurrency cap. `ThreadingHTTPServer` spawns a fresh thread per request
# unbounded — one slowloris-style client can exhaust threads / FDs. This
# semaphore caps simultaneous in-flight handlers; overflow returns 503.
MAX_CONCURRENT = 64
_concurrency = threading.Semaphore(MAX_CONCURRENT)

# Real-client-IP resolution behind the ALB.
#
# Direct connections to :8080 are blocked at the host security group —
# only ALB inside the VPC can reach us — so when the TCP peer is in
# `VPC_CIDR` we read `X-Forwarded-For`. Anything from outside the VPC
# is a misconfiguration / direct hit; fall back to the peer address
# verbatim (no spoof window).
#
# The ALB is publicly reachable, so `X-Forwarded-For` is attacker-authored
# up to the entry the ALB itself appends. `TRUSTED_PROXIES` names the egress
# addresses of our own front proxies; the chain is then walked right to left
# past trusted and private hops, and the first remaining entry is the client.
# Unset, that walk is impossible and we fall back to the legacy leftmost
# entry, which any caller can forge — `main()` says so loudly at startup.
#
# `VPC_CIDR` and `TRUSTED_PROXIES` are set via systemd `Environment=` in
# kaskad-pull-api.service, substituted from terraform.
_VPC_CIDR_STR = os.environ.get("VPC_CIDR", "10.0.0.0/16")
try:
    _VPC_CIDR = ipaddress.ip_network(_VPC_CIDR_STR)
except ValueError:
    print(f"[pull-api] WARN: invalid VPC_CIDR={_VPC_CIDR_STR!r}, falling back to 10.0.0.0/16",
          file=sys.stderr)
    _VPC_CIDR = ipaddress.ip_network("10.0.0.0/16")


class TrustMode(str, Enum):
    """How the client is picked out of the `X-Forwarded-For` chain."""

    LEFTMOST = "leftmost"            # legacy, forgeable by any caller
    TRUSTED_CHAIN = "trusted_chain"  # right to left past trusted hops


def _parse_networks(raw):
    """Parse a comma-separated list of IPs / CIDRs, skipping bad entries."""
    nets = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            nets.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            print(f"[pull-api] WARN: ignoring invalid TRUSTED_PROXIES entry {token!r}",
                  file=sys.stderr)
    return tuple(nets)


_TRUSTED_PROXIES = _parse_networks(os.environ.get("TRUSTED_PROXIES", ""))
_TRUST_MODE = TrustMode.TRUSTED_CHAIN if _TRUSTED_PROXIES else TrustMode.LEFTMOST


def _is_trusted(ip):
    # `in` is False across address families, so mixed v4/v6 lists are fine.
    return any(ip in net for net in _TRUSTED_PROXIES)


def _xff_chain(handler):
    """`X-Forwarded-For` entries left to right, unparseable ones dropped.
    Repeated header lines are one chain, per RFC 9110."""
    headers = handler.headers
    get_all = getattr(headers, "get_all", None)
    values = get_all("X-Forwarded-For") if get_all else None
    if values is None:
        single = headers.get("X-Forwarded-For", "")
        values = [single] if single else []

    chain = []
    for value in values:
        for token in value.split(","):
            token = token.strip()
            if not token:
                continue
            try:
                chain.append(ipaddress.ip_address(token))
            except ValueError:
                continue
    return chain


def get_client_ip(handler):
    """Rate-limit key for this request: the real client where we can prove
    it, the closest unforgeable hop otherwise."""
    peer_str = handler.client_address[0]
    try:
        peer = ipaddress.ip_address(peer_str)
    except (ValueError, TypeError):
        return peer_str

    if peer not in _VPC_CIDR:
        # Direct hit (dev / mis-routed) — peer IS the client, do not
        # honour `X-Forwarded-For` (spoofable in this case).
        return str(peer)

    chain = _xff_chain(handler)
    if not chain:
        return str(peer)

    if _TRUST_MODE is TrustMode.LEFTMOST:
        return str(chain[0])

    # The ALB appends the true TCP peer, so the rightmost entry is authentic
    # and every entry left of a trusted hop is only as trustworthy as that hop.
    for ip in reversed(chain):
        if _is_trusted(ip) or ip.is_private or ip.is_loopback:
            continue
        return str(ip)
    return str(chain[-1])


# ─── Rate Limiter ────────────────────────────────────────────

class RateLimiter:
    """Token bucket per key, with bounded state.

    Uses `time.monotonic()` so an NTP step cannot mint or withhold tokens.
    """

    def __init__(self, limit=RATE_LIMIT, window=RATE_WINDOW, max_keys=MAX_TRACKED_KEYS):
        self.limit = limit
        self.window = window
        self.max_keys = max_keys
        # key -> (tokens, last_seen); ordered oldest-touched first.
        self.clients = OrderedDict()
        self.lock = threading.Lock()

    def _tokens(self, key, now):
        entry = self.clients.get(key)
        if entry is None:
            return float(self.limit)
        tokens, last = entry
        return min(self.limit, tokens + (now - last) * (self.limit / self.window))

    def _evict(self, now):
        cutoff = now - self.window
        while self.clients:
            _, (_, last) = next(iter(self.clients.items()))
            # Idle for a full window ⇒ refilled to `limit` ⇒ nothing to remember.
            # Past the cap we also drop live buckets, which hands that key a
            # fresh allowance — the memory bound wins over per-key accuracy.
            if last > cutoff and len(self.clients) <= self.max_keys:
                break
            self.clients.popitem(last=False)

    def is_allowed(self, key):
        with self.lock:
            now = time.monotonic()
            tokens = self._tokens(key, now)
            allowed = tokens >= 1
            self.clients[key] = (tokens - 1 if allowed else tokens, now)
            self.clients.move_to_end(key)
            self._evict(now)
            return allowed

    def remaining(self, key):
        """Read-only — never creates a bucket."""
        with self.lock:
            return int(self._tokens(key, time.monotonic()))


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
        # Resolved once so the limiter decision and the header agree.
        self.client_ip = get_client_ip(self)

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
        if not rate_limiter.is_allowed(self.client_ip):
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
        self.send_header("X-RateLimit-Remaining", str(rate_limiter.remaining(self.client_ip)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        """Override to use structured logging."""
        print(f"[pull-api] {getattr(self, 'client_ip', '-')} - {format % args}")


# ─── Main ────────────────────────────────────────────────────

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080

    server = ThreadingHTTPServer(("0.0.0.0", port), PullAPIHandler)
    # Daemonise request threads so shutdown doesn't wait on in-flight
    # handlers that are themselves blocked on a slow VSOCK call.
    server.daemon_threads = True
    print(f"[pull-api] HTTP server listening on port {port}")
    print(f"[pull-api] Rate limit: {RATE_LIMIT} req/{RATE_WINDOW}s per IP "
          f"(max {MAX_TRACKED_KEYS} tracked keys)")
    if _TRUST_MODE is TrustMode.LEFTMOST:
        print("[pull-api] WARN: TRUSTED_PROXIES is unset — the rate-limit key is "
              "the first X-Forwarded-For entry, which any caller can forge. "
              "Set it to the front proxy egress addresses.", file=sys.stderr)
    else:
        print(f"[pull-api] Trusted proxies: {', '.join(str(n) for n in _TRUSTED_PROXIES)}")
    print(f"[pull-api] Max concurrent handlers: {MAX_CONCURRENT}")
    print(f"[pull-api] Enclave VSOCK: CID={ENCLAVE_CID} port={VSOCK_PORT}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[pull-api] Shutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
