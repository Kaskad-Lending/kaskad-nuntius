#!/usr/bin/env python3
"""Pontifex keyex host — HTTP :8081 relayer front end + enclave config loop.

Fronts the two keyex enclaves on this instance over VSOCK:

    relayer → HTTP:8081 → pontifex_host.py → VSOCK CID17:5004 → bridge enclave

HTTP surface (bridge enclave, CID 17, port 5004):
    GET  /health       → bridge `health`
    GET  /attestation  → bridge `get_attestation`  (optional ?nonce=<hex>)
    POST /sign         → bridge `sign_claim` {"recipient": "0x..."}

Config loop (background): every --configure-interval seconds it re-sends the
idempotent `configure` frame to the oracle (CID16:5005) and bridge (CID17:5004)
with peer hints from `ec2:DescribeInstances` (same ASG) and posts approval blobs
from `s3://<eif-bucket>/approvals/`. The registry is the arbiter; these inputs
are untrusted hints, so a stale/empty answer only delays readiness.

No secrets in code: addresses, RPC URLs, bucket and ASG tag arrive via env /
CLI; peers and approvals are read at runtime through the instance role.
"""
from __future__ import annotations

import argparse
import enum
import json
import logging
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional

# ─── VSOCK topology (fixed by the EIF measurement / ENCLAVE.md API table) ───

AF_VSOCK = 40

ORACLE_CID = 16
BRIDGE_CID = 17
ORACLE_CONFIG_PORT = 5005  # configure / approval / get_attestation / keyex_health
BRIDGE_API_PORT = 5004     # configure / sign_claim / get_attestation / health

FRAME_HEADER = struct.Struct(">I")   # 4-byte big-endian length prefix
MAX_FRAME = 1 << 20                  # 1 MiB response cap

_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

log = logging.getLogger("pontifex-host")


class EnclaveMethod(str, enum.Enum):
    CONFIGURE = "configure"
    APPROVAL = "approval"
    GET_ATTESTATION = "get_attestation"
    HEALTH = "health"
    SIGN_CLAIM = "sign_claim"


# ─── VSOCK client ────────────────────────────────────────────

class VsockError(Exception):
    """A VSOCK round-trip failed (transport, timeout, or malformed frame)."""


def vsock_call(cid: int, port: int, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
    """One length-prefixed JSON request/response over VSOCK. Raises VsockError."""
    body = json.dumps(payload).encode("utf-8")
    sock = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((cid, port))
        sock.sendall(FRAME_HEADER.pack(len(body)))
        sock.sendall(body)

        header = _recv_exact(sock, FRAME_HEADER.size)
        (length,) = FRAME_HEADER.unpack(header)
        if length > MAX_FRAME:
            raise VsockError(f"oversized response frame: {length} bytes")
        return json.loads(_recv_exact(sock, length).decode("utf-8"))
    except ConnectionRefusedError as e:
        raise VsockError("enclave not listening") from e
    except socket.timeout as e:
        raise VsockError("enclave timeout") from e
    except (OSError, json.JSONDecodeError) as e:
        raise VsockError(str(e)) from e
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise VsockError("connection closed mid-frame")
        buf.extend(chunk)
    return bytes(buf)


# ─── Rate limiting + per-recipient sign cache ─────────────────

class RateLimiter:
    """Token bucket per client IP."""

    def __init__(self, limit: int, window: float) -> None:
        self.limit = limit
        self.window = window
        self._rate = limit / window
        self._clients: dict[str, dict[str, float]] = defaultdict(
            lambda: {"tokens": float(limit), "last": time.monotonic()}
        )
        self._lock = threading.Lock()

    def allow(self, ip: str) -> bool:
        with self._lock:
            now = time.monotonic()
            c = self._clients[ip]
            c["tokens"] = min(self.limit, c["tokens"] + (now - c["last"]) * self._rate)
            c["last"] = now
            if c["tokens"] >= 1.0:
                c["tokens"] -= 1.0
                return True
            return False


class SignCache:
    """Caches a recipient's signed claim for `ttl` seconds. A cached deadline
    stays valid far longer than the TTL, so re-serving it is safe and spares the
    enclave a double `burned` read per burst."""

    def __init__(self, ttl: float) -> None:
        self.ttl = ttl
        self._store: dict[str, tuple[float, dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def get(self, recipient: str) -> Optional[dict[str, Any]]:
        with self._lock:
            hit = self._store.get(recipient)
            if hit and (time.monotonic() - hit[0]) < self.ttl:
                return hit[1]
            return None

    def put(self, recipient: str, response: dict[str, Any]) -> None:
        with self._lock:
            self._store[recipient] = (time.monotonic(), response)


# ─── HTTP front end ──────────────────────────────────────────

class HostContext:
    """Shared, immutable-after-start config + the rate limiter and cache."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.bridge_timeout = args.bridge_timeout
        self.rate = RateLimiter(args.rate_limit, args.rate_window)
        self.sign_cache = SignCache(args.sign_cache_ttl)


class PontifexHandler(BaseHTTPRequestHandler):
    ctx: HostContext  # injected on the server instance

    protocol_version = "HTTP/1.1"

    def _client_ip(self) -> str:
        return self.client_address[0]

    def _send(self, status: int, data: dict[str, Any]) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _gated(self) -> bool:
        if self.ctx.rate.allow(self._client_ip()):
            return True
        self._send(429, {"error": "rate_limited"})
        return False

    def do_GET(self) -> None:  # noqa: N802
        if not self._gated():
            return
        path = self.path.split("?", 1)[0].rstrip("/")
        if path == "/health" or path == "":
            self._proxy_bridge(EnclaveMethod.HEALTH, {}, ok_key="state")
        elif path == "/attestation":
            self._attestation()
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._gated():
            return
        if self.path.split("?", 1)[0].rstrip("/") == "/sign":
            self._sign()
        else:
            self._send(404, {"error": "not_found"})

    def _attestation(self) -> None:
        payload: dict[str, Any] = {}
        query = self.path.split("?", 1)
        if len(query) == 2:
            for part in query[1].split("&"):
                if part.startswith("nonce="):
                    nonce = part[len("nonce="):]
                    if not _HEX_RE.match(nonce):
                        self._send(400, {"error": "bad_nonce"})
                        return
                    payload["nonce"] = nonce
        self._proxy_bridge(EnclaveMethod.GET_ATTESTATION, payload, ok_key="attestation")

    def _sign(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send(400, {"error": "bad_length"})
            return
        if length <= 0 or length > 4096:
            self._send(400, {"error": "bad_length"})
            return
        try:
            req = json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send(400, {"error": "bad_json"})
            return

        recipient = req.get("recipient")
        if not isinstance(recipient, str) or not _ADDR_RE.match(recipient):
            self._send(400, {"error": "bad_recipient"})
            return
        recipient = recipient.lower()

        cached = self.ctx.sign_cache.get(recipient)
        if cached is not None:
            self._send(200, {**cached, "cached": True})
            return

        try:
            resp = vsock_call(
                BRIDGE_CID, BRIDGE_API_PORT,
                {"method": EnclaveMethod.SIGN_CLAIM.value, "recipient": recipient},
                self.ctx.bridge_timeout,
            )
        except VsockError as e:
            log.warning("sign vsock failure ip=%s recipient=%s err=%s",
                        self._client_ip(), recipient, e)
            self._send(502, {"error": "enclave_unreachable"})
            return

        if "error" in resp:
            # sign_claim refusal path — pass the enclave's code through as 409.
            self._send(409, resp)
            return
        self.ctx.sign_cache.put(recipient, resp)
        self._send(200, resp)

    def _proxy_bridge(self, method: EnclaveMethod, payload: dict[str, Any], ok_key: str) -> None:
        try:
            resp = vsock_call(
                BRIDGE_CID, BRIDGE_API_PORT,
                {"method": method.value, **payload},
                self.ctx.bridge_timeout,
            )
        except VsockError as e:
            log.warning("proxy vsock failure method=%s err=%s", method.value, e)
            self._send(503, {"error": "enclave_unreachable"})
            return
        status = 200 if ok_key in resp and "error" not in resp else 503
        self._send(status, resp)

    def log_message(self, fmt: str, *fmt_args: Any) -> None:  # noqa: A002
        log.info("http %s - %s", self._client_ip(), fmt % fmt_args)


# ─── Config push loop ────────────────────────────────────────

class ConfigPusher(threading.Thread):
    """Re-sends idempotent `configure` to both enclaves and posts pending
    approvals. Peer hints come from EC2 (same ASG); approvals from S3. Every
    input is an untrusted hint — the registry decides what an enclave installs."""

    def __init__(self, args: argparse.Namespace, stop: threading.Event) -> None:
        super().__init__(name="config-pusher", daemon=True)
        self._stop = stop
        self._interval = args.configure_interval
        self._enclave_timeout = args.bridge_timeout
        self._asg_tag = args.asg_tag
        self._region = args.region
        self._eif_bucket = args.eif_bucket
        self._registry = args.oracle_registry
        self._entry = args.bridge_entry
        self._rh_rpcs = args.rh_rpc
        self._seen_approvals: set[str] = set()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception as e:  # never let the loop die
                log.error("config tick failed: %s", e)
            self._stop.wait(self._interval)

    def _tick(self) -> None:
        oracle_ips = self._discover_oracle_ips()

        if self._registry:
            self._push(ORACLE_CID, ORACLE_CONFIG_PORT, {
                "method": EnclaveMethod.CONFIGURE.value,
                "registry": self._registry,
                "rhRpcs": self._rh_rpcs,
                "oraclePeers": oracle_ips,
            })
        if self._entry:
            # Bridge fetches its child key from the co-located oracle (CID 16,
            # reached via 127.0.0.1), plus any cross-host oracle peers.
            self._push(BRIDGE_CID, BRIDGE_API_PORT, {
                "method": EnclaveMethod.CONFIGURE.value,
                "entry": self._entry,
                "rhRpcs": self._rh_rpcs,
                "oraclePeers": ["127.0.0.1", *oracle_ips],
            })
        self._push_approvals()

    def _push(self, cid: int, port: int, payload: dict[str, Any]) -> None:
        try:
            vsock_call(cid, port, payload, self._enclave_timeout)
        except VsockError as e:
            log.info("configure cid=%d not ready: %s", cid, e)

    def _push_approvals(self) -> None:
        if not self._eif_bucket:
            return
        for key in self._list_s3(f"s3://{self._eif_bucket}/approvals/"):
            if key in self._seen_approvals or not key.endswith(".json"):
                continue
            blob = self._read_s3(f"s3://{self._eif_bucket}/{key}")
            if blob is None:
                continue
            try:
                approval = json.loads(blob)
            except json.JSONDecodeError:
                log.warning("approval %s not JSON, skipping", key)
                self._seen_approvals.add(key)
                continue
            # Oracle image verifies + accepts; a rejected blob is retried never.
            try:
                resp = vsock_call(ORACLE_CID, ORACLE_CONFIG_PORT, {
                    "method": EnclaveMethod.APPROVAL.value,
                    **approval,
                }, self._enclave_timeout)
                log.info("approval %s → %s", key, resp)
                self._seen_approvals.add(key)
            except VsockError as e:
                log.info("approval %s deferred (oracle not ready): %s", key, e)

    # AWS access via the instance role, shelled to the CLI (stdlib-only host).

    def _discover_oracle_ips(self) -> list[str]:
        if not self._asg_tag:
            return []
        out = self._aws([
            "ec2", "describe-instances",
            "--filters",
            f"Name=tag:aws:autoscaling:groupName,Values={self._asg_tag}",
            "Name=instance-state-name,Values=running",
            "--query", "Reservations[].Instances[].PrivateIpAddress",
            "--output", "json",
        ])
        if out is None:
            return []
        try:
            ips = json.loads(out)
        except json.JSONDecodeError:
            return []
        # Cross-host oracle peers only (self excluded); each fronts oracle RA-TLS
        # on :8443. The bridge reaches its co-located oracle via 127.0.0.1.
        return [ip for ip in ips
                if isinstance(ip, str) and ip != self._self_ip()]

    def _self_ip(self) -> str:
        return _instance_private_ip()

    def _list_s3(self, uri: str) -> list[str]:
        out = self._aws(["s3", "ls", uri, "--recursive"])
        if out is None:
            return []
        keys = []
        for line in out.splitlines():
            parts = line.split()
            if parts:
                keys.append(parts[-1])
        return keys

    def _read_s3(self, uri: str) -> Optional[str]:
        return self._aws(["s3", "cp", uri, "-"])

    def _aws(self, cmd: list[str]) -> Optional[str]:
        full = ["aws"] + cmd
        if self._region:
            full += ["--region", self._region]
        try:
            proc = subprocess.run(full, capture_output=True, text=True, timeout=15)
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            log.warning("aws call failed: %s", e)
            return None
        if proc.returncode != 0:
            log.info("aws %s rc=%d: %s", cmd[0], proc.returncode, proc.stderr.strip())
            return None
        return proc.stdout


_SELF_IP_CACHE: Optional[str] = None


def _instance_private_ip() -> str:
    """IMDSv2 private IP, cached. Empty string if unavailable (dev)."""
    global _SELF_IP_CACHE
    if _SELF_IP_CACHE is not None:
        return _SELF_IP_CACHE
    import urllib.request
    try:
        tok_req = urllib.request.Request(
            "http://169.254.169.254/latest/api/token", method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
        )
        with urllib.request.urlopen(tok_req, timeout=2) as r:
            token = r.read().decode().strip()
        ip_req = urllib.request.Request(
            "http://169.254.169.254/latest/meta-data/local-ipv4",
            headers={"X-aws-ec2-metadata-token": token},
        )
        with urllib.request.urlopen(ip_req, timeout=2) as r:
            _SELF_IP_CACHE = r.read().decode().strip()
    except Exception:
        _SELF_IP_CACHE = ""
    return _SELF_IP_CACHE


# ─── Entrypoint ──────────────────────────────────────────────

def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Pontifex keyex host front end")
    p.add_argument("--port", type=int, default=int(os.environ.get("PONTIFEX_HOST_PORT", "8081")))
    p.add_argument("--bind", default=os.environ.get("PONTIFEX_HOST_BIND", "0.0.0.0"))
    p.add_argument("--bridge-timeout", type=float,
                   default=float(os.environ.get("PONTIFEX_BRIDGE_TIMEOUT", "10")))
    p.add_argument("--rate-limit", type=int,
                   default=int(os.environ.get("PONTIFEX_RATE_LIMIT", "60")))
    p.add_argument("--rate-window", type=float,
                   default=float(os.environ.get("PONTIFEX_RATE_WINDOW", "60")))
    p.add_argument("--sign-cache-ttl", type=float,
                   default=float(os.environ.get("PONTIFEX_SIGN_CACHE_TTL", "60")))
    p.add_argument("--configure-interval", type=float,
                   default=float(os.environ.get("PONTIFEX_CONFIGURE_INTERVAL", "30")))
    # Runtime, untrusted, public config (no secrets):
    p.add_argument("--oracle-registry", default=os.environ.get("KASKAD_ORACLE_REGISTRY", ""))
    p.add_argument("--bridge-entry", default=os.environ.get("KASKAD_BRIDGE_ENTRY", ""))
    p.add_argument("--rh-rpc", action="append",
                   default=_split_env("KASKAD_RH_RPCS"))
    p.add_argument("--asg-tag", default=os.environ.get("KASKAD_ASG_NAME", ""))
    p.add_argument("--region", default=os.environ.get("KASKAD_AWS_REGION", ""))
    p.add_argument("--eif-bucket", default=os.environ.get("KASKAD_EIF_BUCKET", ""))
    p.add_argument("--no-config-loop", action="store_true",
                   help="serve HTTP only; skip the configure/approval pusher")
    return p.parse_args(argv)


def _split_env(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    return [u.strip() for u in raw.split(",") if u.strip()]


def main(argv: Optional[list[str]] = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
    )
    args = parse_args(argv)
    ctx = HostContext(args)

    server = ThreadingHTTPServer((args.bind, args.port), PontifexHandler)
    server.daemon_threads = True
    PontifexHandler.ctx = ctx  # type: ignore[attr-defined]

    stop = threading.Event()
    pusher: Optional[ConfigPusher] = None
    if not args.no_config_loop:
        pusher = ConfigPusher(args, stop)
        pusher.start()

    def shutdown(signum: int, _frame: Any) -> None:
        log.info("signal %d received, shutting down", signum)
        stop.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    log.info("listening on %s:%d bridge=CID%d:%d oracle=CID%d:%d config_loop=%s",
             args.bind, args.port, BRIDGE_CID, BRIDGE_API_PORT,
             ORACLE_CID, ORACLE_CONFIG_PORT, not args.no_config_loop)
    try:
        server.serve_forever()
    finally:
        stop.set()
        server.server_close()
        if pusher is not None:
            pusher.join(timeout=5)
    log.info("stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
