#!/usr/bin/env python3
"""Relay bridge HTTP to CID17:5004 and replay untrusted enclave config hints.

Readiness reports key installation; diagnostics and attestations stay independent.
Forwarded client identity requires explicitly trusted append-mode proxies.
"""
from __future__ import annotations

import argparse
import enum
import ipaddress
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
from dataclasses import dataclass
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
MAX_REQUEST_FRAME = 64 * 1024        # enclave request cap
MAX_SIGN_BODY = 4096
MAX_NONCE_HEX = 1024                 # NSM nonce: 512 bytes
HTTP_READ_TIMEOUT = 10.0
READINESS_TIMEOUT = 1.0

_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

log = logging.getLogger("pontifex-host")


class EnclaveMethod(str, enum.Enum):
    CONFIGURE = "configure"
    APPROVAL = "approval"
    GET_ATTESTATION = "get_attestation"
    HEALTH = "health"
    READINESS = "readiness"
    SIGN_CLAIM = "sign_claim"


class ReadinessState(str, enum.Enum):
    READY = "ready"
    FETCHING = "fetching"


@dataclass(frozen=True)
class PeerAsg:
    """An oracle ASG whose running instances are RA-TLS peer candidates."""
    region: str
    asg_name: str


def parse_peer_asgs(raw: str) -> list[PeerAsg]:
    """Parse `region:asg[,region:asg...]`; blank entries are skipped."""
    peers = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        region, sep, asg_name = entry.partition(":")
        region, asg_name = region.strip(), asg_name.strip()
        if not sep or not region or not asg_name:
            raise ValueError(f"expected region:asg, got {entry!r}")
        peers.append(PeerAsg(region, asg_name))
    return peers


# ─── VSOCK client ────────────────────────────────────────────

class VsockError(Exception):
    """A VSOCK round-trip failed (transport, timeout, or malformed frame)."""


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _json_object(body: bytes) -> dict[str, Any]:
    value = json.loads(body.decode("utf-8"), parse_constant=_reject_json_constant)
    if not isinstance(value, dict):
        raise ValueError("JSON body must be an object")
    return value


def _set_deadline_timeout(sock: socket.socket, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise socket.timeout("read deadline exceeded")
    sock.settimeout(remaining)


def vsock_call(cid: int, port: int, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
    """One bounded JSON round-trip over VSOCK under a total deadline. Raises VsockError."""
    sock: Optional[socket.socket] = None
    deadline = time.monotonic() + timeout
    try:
        body = json.dumps(payload, allow_nan=False).encode("utf-8")
        if len(body) > MAX_REQUEST_FRAME:
            raise VsockError("oversized request frame")
        sock = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
        _set_deadline_timeout(sock, deadline)
        sock.connect((cid, port))
        _set_deadline_timeout(sock, deadline)
        sock.sendall(FRAME_HEADER.pack(len(body)))
        _set_deadline_timeout(sock, deadline)
        sock.sendall(body)

        header = _recv_exact(sock, FRAME_HEADER.size, deadline)
        (length,) = FRAME_HEADER.unpack(header)
        if length > MAX_FRAME:
            raise VsockError(f"oversized response frame: {length} bytes")
        return _json_object(_recv_exact(sock, length, deadline))
    except ConnectionRefusedError as e:
        raise VsockError("enclave not listening") from e
    except socket.timeout as e:
        raise VsockError("enclave timeout") from e
    except (ValueError, RecursionError) as e:
        raise VsockError("malformed JSON frame") from e
    except OSError as e:
        raise VsockError(str(e)) from e
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _recv_exact(sock: socket.socket, n: int, deadline: float) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        _set_deadline_timeout(sock, deadline)
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
            c = self._clients[ip]
            now = time.monotonic()
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
        self.trusted_proxy_cidrs = args.trusted_proxy_cidrs
        self.rate = RateLimiter(args.rate_limit, args.rate_window)
        self.sign_cache = SignCache(args.sign_cache_ttl)


class PontifexHandler(BaseHTTPRequestHandler):
    ctx: HostContext  # injected on the server instance

    protocol_version = "HTTP/1.1"
    timeout = HTTP_READ_TIMEOUT

    def _client_ip(self) -> str:
        return getattr(self, "_request_client_ip", self.client_address[0])

    def _proxy_client_ip(self) -> str:
        peer = self.client_address[0]
        if not self.ctx.trusted_proxy_cidrs:
            return peer
        peer_ip = ipaddress.ip_address(peer)
        if not any(peer_ip in cidr for cidr in self.ctx.trusted_proxy_cidrs):
            return peer
        forwarded = self.headers.get_all("X-Forwarded-For", [])
        if not forwarded:
            return peer
        if len(forwarded) != 1 or any(c in forwarded[0] for c in "\r\n%"):
            raise ValueError("malformed forwarded chain")
        # ALB append mode puts its observed client last; validate the whole chain.
        clients = [ipaddress.ip_address(token.strip(" \t"))
                   for token in forwarded[0].split(",")]
        return str(clients[-1])

    def _send(self, status: int, data: dict[str, Any]) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if status >= 400:
            self.close_connection = True
            self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _gated(self, *, readiness: bool = False) -> bool:
        self._request_client_ip = self.client_address[0]
        try:
            self._request_client_ip = self._proxy_client_ip()
        except ValueError:
            self._send(400, {"error": "bad_forwarded_for"})
            return False
        if readiness or self.ctx.rate.allow(self._client_ip()):
            return True
        self._send(429, {"error": "rate_limited"})
        return False

    def do_GET(self) -> None:  # noqa: N802
        readiness = self.path in ("/bridge/ready", "/ready")
        if not self._gated(readiness=readiness) or not self._bodyless_get():
            return
        if readiness:
            self._readiness()
            return
        path = self.path.split("?", 1)[0].rstrip("/")
        if path in ("", "/health", "/bridge/health"):
            self._proxy_bridge(EnclaveMethod.HEALTH, {}, ok_key="state")
        elif path in ("/attestation", "/bridge/attestation"):
            self._attestation()
        else:
            self._send(404, {"error": "not_found"})

    def _bodyless_get(self) -> bool:
        lengths = self.headers.get_all("Content-Length", [])
        try:
            if (len(lengths) > 1 or self.headers.get("Transfer-Encoding") is not None
                    or self.headers.defects):
                raise ValueError("ambiguous request framing")
            if lengths:
                raw = lengths[0].strip(" \t")
                if not raw.isascii() or not raw.isdecimal() or int(raw) != 0:
                    raise ValueError("GET body not supported")
        except ValueError:
            self._send(400, {"error": "bad_length"})
            return False
        return True

    def _readiness(self) -> None:
        try:
            resp = vsock_call(
                BRIDGE_CID, BRIDGE_API_PORT, {"method": EnclaveMethod.READINESS.value},
                min(self.ctx.bridge_timeout, READINESS_TIMEOUT),
            )
        except VsockError:
            self._send(503, {"error": "enclave_unreachable"})
            return
        if resp == {"state": ReadinessState.READY.value}:
            self._send(200, resp)
        elif resp == {"state": ReadinessState.FETCHING.value}:
            self._send(503, resp)
        else:
            self._send(503, {"error": "bad_enclave_response"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._gated():
            return
        if self.path.split("?", 1)[0].rstrip("/") in ("/sign", "/bridge/sign"):
            self._sign()
        else:
            self._send(404, {"error": "not_found"})

    def _attestation(self) -> None:
        payload: dict[str, Any] = {}
        query = self.path.split("?", 1)
        if len(query) == 2:
            for part in query[1].split("&"):
                if part == "nonce" or part.startswith("nonce="):
                    nonce = part[len("nonce="):]
                    if ("nonce" in payload or len(nonce) > MAX_NONCE_HEX
                            or len(nonce) % 2 or not _HEX_RE.fullmatch(nonce)):
                        self._send(400, {"error": "bad_nonce"})
                        return
                    payload["nonce"] = nonce
        self._proxy_bridge(EnclaveMethod.GET_ATTESTATION, payload, ok_key="attestation")

    def _read_body(self, length: int) -> bytes:
        deadline = time.monotonic() + self.timeout
        body = bytearray()
        try:
            while len(body) < length:
                _set_deadline_timeout(self.connection, deadline)
                chunk = self.rfile.read1(length - len(body))
                if not chunk:
                    raise ValueError("incomplete request body")
                body.extend(chunk)
        finally:
            self.connection.settimeout(self.timeout)
        return bytes(body)

    def _sign(self) -> None:
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or self.headers.get("Transfer-Encoding") is not None:
            self._send(400, {"error": "bad_length"})
            return
        try:
            raw_length = lengths[0].strip()
            if not raw_length.isascii() or not raw_length.isdecimal():
                raise ValueError("non-decimal content length")
            length = int(raw_length)
        except ValueError:
            self._send(400, {"error": "bad_length"})
            return
        if length <= 0 or length > MAX_SIGN_BODY:
            self._send(400, {"error": "bad_length"})
            return
        try:
            req = _json_object(self._read_body(length))
        except socket.timeout:
            self._send(408, {"error": "request_timeout"})
            return
        except (ValueError, RecursionError):
            self._send(400, {"error": "bad_json"})
            return

        recipient = req.get("recipient")
        if not isinstance(recipient, str) or not _ADDR_RE.fullmatch(recipient):
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

        if not isinstance(resp, dict):
            self._send(502, {"error": "bad_enclave_response"})
            return
        if "error" in resp:
            if not isinstance(resp["error"], str) or not resp["error"]:
                self._send(502, {"error": "bad_enclave_response"})
                return
            # sign_claim refusal path — pass the enclave's code through as 409.
            self._send(409, resp)
            return
        if not (all(isinstance(resp.get(key), str) and resp[key]
                    for key in ("signature", "cumulativeBurned", "signer"))
                and all(type(resp.get(key)) is int and resp[key] >= 0
                        for key in ("deadline", "igraBlock"))):
            self._send(502, {"error": "bad_enclave_response"})
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
        if not isinstance(resp, dict):
            self._send(503, {"error": "bad_enclave_response"})
        elif "error" in resp:
            if isinstance(resp["error"], str) and resp["error"]:
                self._send(503, resp)
            else:
                self._send(503, {"error": "bad_enclave_response"})
        elif not isinstance(resp.get(ok_key), str) or not resp[ok_key]:
            self._send(503, {"error": "bad_enclave_response"})
        else:
            self._send(200, resp)

    def log_message(self, fmt: str, *fmt_args: Any) -> None:  # noqa: A002
        log.info("http %s - %s", self._client_ip(), fmt % fmt_args)


# ─── Config push loop ────────────────────────────────────────

class ConfigPusher(threading.Thread):
    """Replay config and approval hints each cycle; enclaves validate them.

    Peer hints come from EC2 (own ASG + cross-region peer ASGs); owner-signed
    approvals come from S3 in the artifact region.
    """

    def __init__(self, args: argparse.Namespace, stop: threading.Event) -> None:
        super().__init__(name="config-pusher", daemon=True)
        self._stop_event = stop
        self._interval = args.configure_interval
        self._enclave_timeout = args.bridge_timeout
        self._asg_tag = args.asg_tag
        self._region = args.region
        self._peer_asgs = args.peer_asgs
        self._artifact_region = args.artifact_region or args.region
        self._eif_bucket = args.eif_bucket
        self._registry = args.oracle_registry
        self._entry = args.bridge_entry
        self._rh_rpcs = args.rh_rpc

    def run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._tick()
            except Exception as e:  # never let the loop die
                log.error("config tick failed: %s", e)
            self._stop_event.wait(self._interval)

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
        # Replay each cycle: enclave approvals are volatile and deduplicated.
        for key in self._list_s3(f"s3://{self._eif_bucket}/approvals/"):
            if not key.endswith(".json"):
                continue
            try:
                blob = self._read_s3(f"s3://{self._eif_bucket}/{key}")
                if blob is None:
                    continue
                approval = json.loads(blob)
            except (ValueError, RecursionError):
                log.warning("approval %s not JSON, skipping", key)
                continue
            if not isinstance(approval, dict):
                log.warning("approval %s not an object, skipping", key)
                continue
            try:
                resp = vsock_call(ORACLE_CID, ORACLE_CONFIG_PORT, {
                    **approval,
                    "method": EnclaveMethod.APPROVAL.value,
                }, self._enclave_timeout)
                log.info("approval %s accepted=%s", key,
                         isinstance(resp, dict) and resp.get("accepted") is True)
            except VsockError as e:
                log.info("approval %s deferred (oracle not ready): %s", key, e)

    # AWS access via the instance role, shelled to the CLI (stdlib-only host).

    def _discover_oracle_ips(self) -> list[str]:
        asgs = [PeerAsg(self._region, self._asg_tag)] if self._asg_tag else []
        found: list[str] = []
        for asg in asgs + self._peer_asgs:
            ips = self._asg_private_ips(asg)
            if ips is None:
                log.warning("peer discovery failed region=%s asg=%s",
                            asg.region or "-", asg.asg_name)
                continue
            found.extend(ips)
        # Cross-host oracle peers only (self excluded); each fronts oracle RA-TLS
        # on :8443. The bridge reaches its co-located oracle via 127.0.0.1.
        self_ip = self._self_ip() if found else ""
        return list(dict.fromkeys(ip for ip in found if ip != self_ip))

    def _asg_private_ips(self, asg: PeerAsg) -> Optional[list[str]]:
        """Running instances' private IPs, or None if the region lookup failed."""
        out = self._aws([
            "ec2", "describe-instances",
            "--filters",
            f"Name=tag:aws:autoscaling:groupName,Values={asg.asg_name}",
            "Name=instance-state-name,Values=running",
            "--query", "Reservations[].Instances[].PrivateIpAddress",
            "--output", "json",
        ], asg.region)
        if out is None:
            return None
        try:
            ips = json.loads(out)
        except (ValueError, RecursionError):
            return None
        if not isinstance(ips, list):
            return None
        return [ip for ip in ips if isinstance(ip, str)]

    def _self_ip(self) -> str:
        return _instance_private_ip()

    def _list_s3(self, uri: str) -> list[str]:
        out = self._aws(["s3", "ls", uri, "--recursive"], self._artifact_region)
        if out is None:
            return []
        keys = []
        for line in out.splitlines():
            parts = line.split()
            if parts:
                keys.append(parts[-1])
        return keys

    def _read_s3(self, uri: str) -> Optional[str]:
        return self._aws(["s3", "cp", uri, "-"], self._artifact_region)

    def _aws(self, cmd: list[str], region: str) -> Optional[str]:
        full = ["aws"] + cmd
        if region:
            full += ["--region", region]
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
    p.add_argument("--trusted-proxy-cidrs", type=_parse_proxy_cidrs,
                   default=os.environ.get("PONTIFEX_TRUSTED_PROXY_CIDRS", ""),
                   help="comma-separated append-mode proxy CIDRs; empty uses direct peer IPs")
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
    p.add_argument("--peer-asgs", type=parse_peer_asgs,
                   default=os.environ.get("KASKAD_PEER_ASGS", ""),
                   help="comma-separated region:asg oracle ASGs discovered beside --asg-tag")
    p.add_argument("--artifact-region", default=os.environ.get("KASKAD_ARTIFACT_REGION", ""),
                   help="region of --eif-bucket; empty uses --region")
    p.add_argument("--eif-bucket", default=os.environ.get("KASKAD_EIF_BUCKET", ""))
    p.add_argument("--no-config-loop", action="store_true",
                   help="serve HTTP only; skip the configure/approval pusher")
    return p.parse_args(argv)


def _parse_proxy_cidrs(value: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    if not value:
        return ()
    try:
        return tuple(ipaddress.ip_network(cidr.strip()) for cidr in value.split(","))
    except ValueError as e:
        raise argparse.ArgumentTypeError("expected comma-separated proxy CIDRs") from e


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
