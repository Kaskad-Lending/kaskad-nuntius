#!/usr/bin/env python3
"""Operator tool: read the oracle enclave's get_diagnostics over VSOCK (or TCP for a
local run) and print it as raw JSON or as tables. Never exposed over HTTP.

Exit status: 0 on a diagnostics reply, 1 on any transport, protocol or enclave error.
"""

import argparse
import json
import socket
import struct
import sys
import time

AF_VSOCK = 40
ENCLAVE_CID = 16
VSOCK_PORT = 5001
METHOD = "get_diagnostics"
# The enclave caps the reply at 256 KiB.
DEFAULT_MAX_BYTES = 256 * 1024
DEFAULT_TIMEOUT = 10.0
DEFAULT_EVENTS = 20


class DiagError(Exception):
    """The enclave could not be read or did not return diagnostics."""


def tcp_address(text):
    """Parse host:port (IPv6 in brackets) for argparse."""
    host, sep, port = text.rpartition(":")
    host = host.strip("[]")
    if not sep or not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise argparse.ArgumentTypeError(f"expected host:port, got {text!r}")
    return host, int(port)


def connect(args, timeout):
    if args.tcp:
        return socket.create_connection(args.tcp, timeout=timeout)
    sock = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((args.cid, args.port))
    except BaseException:
        sock.close()
        raise
    return sock


def recv_exact(sock, n, deadline):
    data = bytearray()
    while len(data) < n:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout()
        sock.settimeout(remaining)
        chunk = sock.recv(min(n - len(data), 65536))
        if not chunk:
            raise DiagError(f"connection closed after {len(data)} of {n} bytes")
        data += chunk
    return bytes(data)


def fetch(args):
    """Raw reply bytes of one framed get_diagnostics request."""
    deadline = time.monotonic() + args.timeout
    request = json.dumps({"method": METHOD}).encode()
    try:
        with connect(args, args.timeout) as sock:
            sock.sendall(struct.pack(">I", len(request)) + request)
            (length,) = struct.unpack(">I", recv_exact(sock, 4, deadline))
            if length > args.max_bytes:
                raise DiagError(f"reply of {length} bytes exceeds --max-bytes {args.max_bytes}")
            return recv_exact(sock, length, deadline)
    except socket.timeout:
        raise DiagError(f"no reply within {args.timeout:g}s") from None
    except OSError as e:
        raise DiagError(f"cannot reach the enclave: {e}") from None


def parse(raw):
    """The diagnostics object of a reply; DiagError for anything else."""
    try:
        reply = json.loads(raw)
    except ValueError as e:
        raise DiagError(f"reply is not JSON: {e}") from None
    if not isinstance(reply, dict):
        raise DiagError("reply is not a JSON object")
    if reply.get("status") != "ok" or not isinstance(reply.get("diagnostics"), dict):
        raise DiagError(f"enclave answered: {reply.get('error', 'no diagnostics')}")
    return reply["diagnostics"]


def age(seconds):
    return "never" if seconds is None else f"{seconds:.1f}s"


def outcome(last):
    if not last:
        return "-"
    if last.get("outcome") == "ok":
        return "ok"
    status = last.get("http_status")
    return f"{last.get('class')} {status}" if status else str(last.get("class"))


def skip(reason):
    if not reason:
        return "-"
    details = " ".join(f"{k}={v}" for k, v in reason.items() if k != "reason")
    return f"{reason['reason']} {details}".strip()


def field(key, value):
    if isinstance(value, float) and key.endswith("_bps"):
        return f"{value:.1f}"
    return json.dumps(value) if isinstance(value, (dict, list, str)) else value


def table(header, rows):
    widths = [max(len(str(cell)) for cell in column) for column in zip(header, *rows)]
    return ["  ".join(str(cell).ljust(w) for cell, w in zip(row, widths)).rstrip()
            for row in [header, *rows]]


def render(diag, events=DEFAULT_EVENTS):
    """Human-readable report of one diagnostics object."""
    cycles = diag.get("cycles", {})
    lines = [
        f"uptime {age(diag.get('uptime_s'))}  cycles {cycles.get('count')}  "
        f"last {cycles.get('last_ms')} ms  max {cycles.get('max_ms')} ms "
        f"over {cycles.get('window')}",
        "",
    ]
    assets = diag.get("assets", {})
    lines += table(
        ["ASSET", "PATH", "SIGNED", "SKIPPED", "SIGNED_AGE", "SOURCES", "LAST_SKIP"],
        [[name, (a.get("last_cycle") or {}).get("path", "-"), a.get("signed"), a.get("skipped"),
          age(a.get("since_signed_s")), a.get("last_signed_sources") or "-",
          skip(a.get("last_skip"))]
         for name, a in assets.items()],
    )
    polled = [(name, source, s) for name, a in assets.items()
              for source, s in a.get("sources", {}).items() if s.get("ok") or s.get("failed")]
    unpolled = sum(len(a.get("sources", {})) for a in assets.values()) - len(polled)
    lines.append("")
    lines += table(
        ["ASSET", "SOURCE", "LAST", "CONSEC_FAILS", "OK_AGE", "MS", "ATTEMPTS"],
        [[name, source, outcome(s.get("last")), s.get("consecutive_failures"),
          age(s.get("since_ok_s")),
          "-" if s.get("last_duration_ms") is None else s["last_duration_ms"],
          "-" if s.get("last_attempts") is None else s["last_attempts"]]
         for name, source, s in polled],
    )
    if unpolled:
        # Order-book (cob) assets sign without a REST fetch, so their sources stay unpolled.
        lines.append(f"{unpolled} configured sources not polled yet (cob assets skip REST)")
    paused = [[host, h.get("paused_for_s"), h.get("last_cause"), h.get("last_http_status"),
               h.get("pauses"), h.get("suppressed")]
              for host, h in diag.get("hosts", {}).items() if h.get("pauses")]
    if paused:
        lines.append("")
        lines += table(["HOST", "PAUSED_FOR_S", "CAUSE", "STATUS", "PAUSES", "SUPPRESSED"],
                       [[c if c is not None else "-" for c in row] for row in paused])
    ethrpc = diag.get("ethrpc", {})
    round_ = ethrpc.get("last_round")
    if round_:
        lines += ["", f"VUSD NAV rounds {ethrpc.get('rounds')}  last: accepted "
                      f"{round_.get('accepted')} in {round_.get('duration_ms')} ms, "
                      f"{age(round_.get('age_s'))} ago"]
        lines += table(
            ["OPERATOR", "OUTCOME", "DETAIL"],
            [[name, o.get("outcome"),
              " ".join(f"{k}={v}" for k, v in o.items() if k not in ("outcome", "age_s"))]
             for name, o in ethrpc.get("operators", {}).items()],
        )
    recent = diag.get("events", [])[-events:] if events > 0 else []
    lines += ["", f"events: {len(diag.get('events', []))} kept, "
                  f"{diag.get('events_dropped', 0)} dropped, "
                  f"{diag.get('events_truncated', 0)} left out of this reply"]
    for event in recent:
        fields = " ".join(f"{k}={field(k, v)}" for k, v in event.items()
                          if k not in ("age_s", "event") and v is not None)
        lines.append(f"  -{age(event.get('age_s'))} {event.get('event')} {fields}".rstrip())
    return "\n".join(lines)


def arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tcp", type=tcp_address, metavar="HOST:PORT",
                        help="read over TCP (a local run) instead of VSOCK")
    parser.add_argument("--cid", type=int, default=ENCLAVE_CID, help="enclave VSOCK CID")
    parser.add_argument("--port", type=int, default=VSOCK_PORT, help="enclave VSOCK port")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="seconds for the whole exchange")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES,
                        help="largest reply accepted")
    parser.add_argument("--json", action="store_true", help="print the reply as received")
    parser.add_argument("--events", type=int, default=DEFAULT_EVENTS,
                        help="recent events to show in the table view")
    args = parser.parse_args(argv)
    if args.timeout <= 0 or args.max_bytes <= 0:
        parser.error("--timeout and --max-bytes must be positive")
    return args


def main(argv=None):
    args = arguments(argv)
    try:
        raw = fetch(args)
        diag = parse(raw)
    except DiagError as e:
        print(f"oracle_diag: {e}", file=sys.stderr)
        return 1
    print(raw.decode() if args.json else render(diag, args.events))
    return 0


if __name__ == "__main__":
    sys.exit(main())
