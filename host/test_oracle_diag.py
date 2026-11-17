"""Tests for the oracle_diag operator tool: framing, limits, errors and the table view."""

import contextlib
import io
import json
import socket
import struct
import threading
import unittest
from unittest import mock

import oracle_diag

DIAG = {
    "uptime_s": 61.2,
    "cycles": {"count": 4, "last_ms": 15400, "max_ms": 23600, "window": 4},
    "assets": {
        "HEMI/USD": {
            "signed": 4, "skipped": 0, "last_skip": None, "since_signed_s": 2.5,
            "last_signed_sources": 4, "last_price": 0.01,
            "last_cycle": {"path": "rest", "responders": 4, "outliers": [], "skip": None},
            "sources": {
                "binance": {"ok": 4, "failed": 0, "consecutive_failures": 0,
                            "last": {"outcome": "ok"}, "since_ok_s": 2.6,
                            "last_duration_ms": 180, "last_attempts": 1},
            },
        },
        "BTC/USD": {
            "signed": 4, "skipped": 0, "last_skip": None, "since_signed_s": 1.0,
            "last_signed_sources": 12,
            "last_cycle": {"path": "cob", "responders": 12, "outliers": [], "skip": None},
            "sources": {
                "okx": {"ok": 0, "failed": 0, "consecutive_failures": 0, "last": None,
                        "since_ok_s": None, "last_duration_ms": None, "last_attempts": None},
            },
        },
        "USDT/USD": {
            "signed": 3, "skipped": 1, "since_signed_s": 20.0, "last_signed_sources": 3,
            "last_skip": {"reason": "quorum_not_met", "have": 2, "need": 3},
            "sources": {
                "kraken": {"ok": 0, "failed": 4, "consecutive_failures": 4,
                           "last": {"outcome": "failed", "class": "client_error",
                                    "http_status": 404, "detail": "HTTP 404 from api.kraken.com"},
                           "since_ok_s": None, "last_duration_ms": 95, "last_attempts": 1},
            },
        },
    },
    "hosts": {
        "api.kraken.com": {"pauses": 0, "suppressed": 0, "paused_for_s": None,
                           "last_cause": None, "last_http_status": None},
        "api.mexc.com": {"pauses": 1, "suppressed": 3, "paused_for_s": 12.0,
                         "last_cause": "rate_limited", "last_http_status": 429},
    },
    "ethrpc": {
        "rounds": 4,
        "last_round": {"accepted": 7, "duration_ms": 640, "age_s": 9.0},
        "operators": {
            "ethrpc_drpc": {"age_s": 9.0, "outcome": "rejected", "reject": "RPC_ERROR",
                            "rpc_code": -32005},
        },
    },
    "events": [
        {"age_s": 30.0, "event": "host_paused", "host": "api.mexc.com",
         "cause": "rate_limited", "http_status": 429, "pause_s": 30.0},
        {"age_s": 3.0, "event": "source_failed", "asset": "USDT/USD", "source": "kraken",
         "class": "client_error", "http_status": 404, "attempts": 1,
         "detail": "HTTP 404 from api.kraken.com"},
        {"age_s": 2.0, "event": "source_failed", "asset": "USDT/USD", "source": "kraken",
         "class": "bad_response", "http_status": None, "attempts": 1, "detail": "pair not found"},
        {"age_s": 1.0, "event": "outlier_dropped", "asset": "USDT/USD", "source": "coingecko",
         "price": 0.999215, "deviation_bps": 3.704278441599863},
    ],
    "events_dropped": 0,
    "events_truncated": 0,
}
REPLY = json.dumps({"status": "ok", "diagnostics": DIAG}).encode()


def frame(body):
    return struct.pack(">I", len(body)) + body


class _Enclave:
    """One-connection TCP stand-in for the enclave socket; records the request."""

    def __init__(self, reply=None, delay=None):
        self.reply = reply
        self.delay = delay
        self.request = None
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.address = "127.0.0.1:%d" % self.listener.getsockname()[1]
        self.release = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        conn, _ = self.listener.accept()
        with conn:
            (length,) = struct.unpack(">I", conn.recv(4))
            self.request = json.loads(conn.recv(length))
            if self.delay:
                self.release.wait(self.delay)
            if self.reply is not None:
                conn.sendall(self.reply)

    def close(self):
        self.release.set()
        self.thread.join(timeout=5)
        self.listener.close()


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = oracle_diag.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class OverTcpTest(unittest.TestCase):
    def exchange(self, reply, *argv, delay=None):
        enclave = _Enclave(reply, delay)
        try:
            return (*run("--tcp", enclave.address, *argv), enclave.request)
        finally:
            enclave.close()

    def test_json_prints_the_reply_as_received(self):
        """--json prints the raw reply and sends exactly one framed get_diagnostics."""
        code, out, _, request = self.exchange(frame(REPLY), "--json")
        self.assertEqual((code, out), (0, REPLY.decode() + "\n"))
        self.assertEqual(request, {"method": "get_diagnostics"})

    def test_table_lists_each_source_with_outcome_failures_and_age(self):
        """The table view shows asset, source, last outcome, consecutive failures and success age."""
        code, out, _, _ = self.exchange(frame(REPLY))
        self.assertEqual(code, 0)
        rows = [line.split() for line in out.splitlines()]
        self.assertIn(["HEMI/USD", "binance", "ok", "0", "2.6s", "180", "1"], rows)
        self.assertIn(["USDT/USD", "kraken", "client_error", "404", "4", "never", "95", "1"], rows)
        self.assertIn(["USDT/USD", "-", "3", "1", "20.0s", "3", "quorum_not_met", "have=2", "need=3"],
                      rows)
        self.assertIn(["BTC/USD", "cob", "4", "0", "1.0s", "12", "-"], rows)
        self.assertIn(["api.mexc.com", "12.0", "rate_limited", "429", "1", "3"], rows)
        self.assertNotIn("api.kraken.com", [row[0] for row in rows if row])
        self.assertIn('-3.0s source_failed asset="USDT/USD" source="kraken"', out)
        self.assertIn("ethrpc_drpc  rejected  reject=RPC_ERROR rpc_code=-32005", out)

    def test_table_hides_unpolled_sources_and_null_event_fields(self):
        """Never-polled sources are counted, not listed; null fields and long bps are trimmed."""
        _, out, _, _ = self.exchange(frame(REPLY))
        self.assertNotIn("okx", out)
        self.assertIn("1 configured sources not polled yet", out)
        self.assertIn('class="bad_response" attempts=1 detail="pair not found"', out)
        self.assertNotIn("None", out)
        self.assertIn("price=0.999215 deviation_bps=3.7", out)

    def test_events_flag_limits_the_recent_events(self):
        """--events keeps only the newest events."""
        _, out, _, _ = self.exchange(frame(REPLY), "--events", "1")
        self.assertIn("-1.0s outlier_dropped", out)
        self.assertNotIn("source_failed", out)
        self.assertNotIn("host_paused", out)

    def test_an_oversized_reply_is_refused_before_it_is_read(self):
        """A length above --max-bytes fails with exit 1."""
        code, out, err, _ = self.exchange(frame(REPLY), "--max-bytes", str(len(REPLY) - 1))
        self.assertEqual((code, out), (1, ""))
        self.assertIn("exceeds --max-bytes", err)

    def test_a_silent_enclave_times_out(self):
        """No reply within --timeout fails with exit 1."""
        code, _, err, _ = self.exchange(None, "--timeout", "0.2", delay=5)
        self.assertEqual(code, 1)
        self.assertIn("no reply within 0.2s", err)

    def test_bad_replies_fail(self):
        """Truncated, non-JSON, non-object and error replies exit 1."""
        cases = {
            "truncated": struct.pack(">I", 100) + b"{}",
            "closed": b"",
            "garbage": frame(b"{nope"),
            "array": frame(b"[]"),
            "old enclave": frame(b'{"error":"unknown method: get_diagnostics"}'),
            "no diagnostics": frame(b'{"status":"ok"}'),
        }
        for name, reply in cases.items():
            with self.subTest(name):
                code, out, err, _ = self.exchange(reply)
                self.assertEqual((code, out), (1, ""))
                self.assertTrue(err.startswith("oracle_diag: "), err)

    def test_an_unreachable_enclave_fails(self):
        """A refused connection exits 1."""
        listener = socket.create_server(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.close()
        code, _, err = run("--tcp", f"127.0.0.1:{port}", "--timeout", "2")
        self.assertEqual(code, 1)
        self.assertIn("cannot reach the enclave", err)


class ArgumentsTest(unittest.TestCase):
    def test_tcp_address_parses_host_and_port(self):
        """host:port and [v6]:port parse; anything else is a usage error."""
        self.assertEqual(oracle_diag.tcp_address("127.0.0.1:5001"), ("127.0.0.1", 5001))
        self.assertEqual(oracle_diag.tcp_address("[::1]:5001"), ("::1", 5001))
        for bad in ("5001", "host:", ":5001", "host:0", "host:70000", "host:x"):
            with self.subTest(bad):
                with self.assertRaises(oracle_diag.argparse.ArgumentTypeError):
                    oracle_diag.tcp_address(bad)

    def test_usage_errors_exit_2(self):
        """Bad flags exit 2 without touching the network."""
        for argv in (["--tcp", "nope"], ["--timeout", "0"], ["--max-bytes", "-1"]):
            with self.subTest(argv):
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        oracle_diag.main(argv)
                self.assertEqual(raised.exception.code, 2)


class _FakeVsock:
    def __init__(self, replies):
        self.replies = list(replies)
        self.sent = b""
        self.address = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def settimeout(self, t):
        pass

    def connect(self, address):
        self.address = address

    def sendall(self, data):
        self.sent += data

    def recv(self, n):
        return self.replies.pop(0) if self.replies else b""

    def close(self):
        pass


class VsockTest(unittest.TestCase):
    def test_default_reads_cid_16_port_5001_over_vsock(self):
        """Without --tcp the tool dials AF_VSOCK CID 16 port 5001 like pull_api.py."""
        fake = _FakeVsock([struct.pack(">I", len(REPLY)), REPLY])
        families = []

        def make(family, kind):
            families.append((family, kind))
            return fake

        with mock.patch.object(oracle_diag.socket, "socket", make):
            code, out, _ = run("--json")
        self.assertEqual(code, 0)
        self.assertEqual(families, [(40, socket.SOCK_STREAM)])
        self.assertEqual(fake.address, (16, 5001))
        self.assertEqual(fake.sent, frame(b'{"method": "get_diagnostics"}'))
        self.assertEqual(json.loads(out), json.loads(REPLY))


if __name__ == "__main__":
    unittest.main()
