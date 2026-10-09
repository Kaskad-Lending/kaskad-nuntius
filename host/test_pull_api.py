"""Tests for the keyex host pull API: client IP behind ALB/CloudFront and failover statuses."""

import email.message
import http.client
import ipaddress
import json
from pathlib import Path
import socket
import threading
import tracemalloc
import unittest
from unittest import mock

import pull_api

ROOT = Path(__file__).resolve().parent.parent
EDGE = "nuntius.example"


def _headers(xff=(), host=()):
    msg = email.message.Message()
    for v in xff:
        msg["X-Forwarded-For"] = v
    for v in host:
        msg["Host"] = v
    return msg


class _MockHandler:
    def __init__(self, peer, headers=None):
        self.client_address = (peer, 0)
        self.headers = headers if headers is not None else email.message.Message()


class _Base(unittest.TestCase):
    def setUp(self):
        pull_api._VPC_CIDR = ipaddress.ip_network("10.0.0.0/16")
        pull_api.EDGE_HOST = EDGE

    def ip(self, peer, xff=(), host=()):
        return pull_api.get_client_ip(_MockHandler(peer, _headers(xff, host)))


class GetClientIpTest(_Base):
    def test_direct_hit_uses_peer_ignores_xff(self):
        """Peer outside the VPC is the client; its X-Forwarded-For is ignored."""
        self.assertEqual(self.ip("203.0.113.5", ["10.1.1.1"]), "203.0.113.5")

    def test_alb_peer_takes_last_hop(self):
        """Append mode: the last hop is what the ALB observed."""
        self.assertEqual(self.ip("10.0.1.5", ["192.0.2.1, 198.51.100.7, 203.0.113.5"]), "203.0.113.5")

    def test_client_supplied_prefix_cannot_forge_the_bucket(self):
        """A pre-seeded header does not pick the bucket off the edge path."""
        self.assertEqual(self.ip("10.0.1.5", ["1.2.3.4, 203.0.113.5"]), "203.0.113.5")

    def test_duplicate_or_control_chars_fall_back_to_peer(self):
        """Split or injected headers are refused."""
        self.assertEqual(self.ip("10.0.1.5", ["1.2.3.4", "203.0.113.5"]), "10.0.1.5")
        self.assertEqual(self.ip("10.0.1.5", ["203.0.113.5\r\nX-Evil: 1"]), "10.0.1.5")

    def test_missing_empty_or_malformed_xff_falls_back_to_peer(self):
        """No usable chain means the ALB node is the bucket."""
        self.assertEqual(self.ip("10.0.1.5"), "10.0.1.5")
        self.assertEqual(self.ip("10.0.1.5", ["  "]), "10.0.1.5")
        self.assertEqual(self.ip("10.0.1.5", ["not-an-ip, 203.0.113.5"]), "10.0.1.5")
        self.assertEqual(self.ip("10.0.1.5", ["203.0.113.5, not-an-ip"]), "10.0.1.5")

    def test_invalid_peer_string_returned_as_is(self):
        """A non-IP peer does not crash."""
        self.assertEqual(self.ip("not-an-ip"), "not-an-ip")

    def test_ipv6_client_accepted(self):
        """IPv6 hops parse."""
        self.assertEqual(self.ip("10.0.1.5", ["10.0.1.5, 2001:db8::1"]), "2001:db8::1")


class EdgeClientIpTest(_Base):
    CHAIN = ["6.6.6.6, 198.51.100.9, 130.176.0.1"]  # forged, viewer, CloudFront

    def test_edge_host_takes_the_hop_cloudfront_appended(self):
        """Via the edge, the viewer is second to last, not the CloudFront node."""
        self.assertEqual(self.ip("10.0.1.5", self.CHAIN, [EDGE]), "198.51.100.9")
        self.assertEqual(self.ip("10.0.1.5", self.CHAIN, [EDGE.upper()]), "198.51.100.9")

    def test_other_host_keeps_the_last_hop(self):
        """Any other Host gets the ALB-observed hop."""
        self.assertEqual(self.ip("10.0.1.5", self.CHAIN, ["keyex.example"]), "130.176.0.1")

    def test_near_miss_hosts_are_not_edge(self):
        """Port, trailing dot, padding or a second Host never count as the edge."""
        for host in ([EDGE + ":443"], [EDGE + "."], [EDGE + " "], [EDGE, EDGE]):
            with self.subTest(host=host):
                self.assertEqual(self.ip("10.0.1.5", self.CHAIN, host), "130.176.0.1")

    def test_disabled_edge_never_shifts(self):
        """Empty EDGE_HOST keeps the ALB-observed hop for every Host."""
        pull_api.EDGE_HOST = ""
        self.assertEqual(self.ip("10.0.1.5", self.CHAIN, [EDGE]), "130.176.0.1")
        self.assertEqual(self.ip("10.0.1.5", self.CHAIN, [""]), "130.176.0.1")

    def test_edge_from_outside_the_vpc_is_ignored(self):
        """A direct peer cannot claim the edge Host."""
        self.assertEqual(self.ip("203.0.113.5", self.CHAIN, [EDGE]), "203.0.113.5")

    def test_single_hop_edge_keeps_that_hop(self):
        """A one-hop chain has no viewer hop to shift to."""
        self.assertEqual(self.ip("10.0.1.5", ["130.176.0.1"], [EDGE]), "130.176.0.1")


PRICE = {"asset": "ETH/USD", "price": "1", "signature": "0x00"}
REFUSAL = {"error": "Attestation document unavailable — enclave health cannot be verified; refusing to sign",
           "attestation_healthy": False}


class RouteTest(unittest.TestCase):
    def route(self, path, reply):
        calls = []

        def fake(method, asset=None, timeout=10):
            calls.append((method, asset))
            if isinstance(reply, Exception):
                raise reply
            return reply

        with mock.patch.object(pull_api, "query_enclave", fake):
            status, body = pull_api.route(path)
        return status, body, calls

    def test_prices_served(self):
        """Non-empty signed prices are 200, query strings ignored."""
        for path in ("/prices", "/prices/", "/prices?t=1"):
            with self.subTest(path=path):
                self.assertEqual(self.route(path, {"prices": [PRICE], "num_assets": 1})[0], 200)

    def test_prices_empty_or_refused_is_unavailable(self):
        """Empty or refused prices are 503 so the edge fails over."""
        self.assertEqual(self.route("/prices", {"prices": [], "num_assets": 0})[0], 503)
        self.assertEqual(self.route("/prices", REFUSAL)[0], 503)

    def test_single_price_statuses(self):
        """Found is 200, unknown asset 404, signer trouble 503."""
        self.assertEqual(self.route("/prices/ETH/USD", {"price": PRICE})[0], 200)
        self.assertEqual(self.route("/prices/NOPE", {"error": "asset 'NOPE' not found"})[0], 404)
        self.assertEqual(self.route("/prices/ETH/USD", {"error": "signing failed: x"})[0], 503)
        self.assertEqual(self.route("/prices/ETH/USD", REFUSAL)[0], 503)

    def test_encoded_slash_in_either_case(self):
        """%2F and %2f both decode to the pair separator."""
        for path in ("/prices/eth%2fusd", "/prices/ETH%2FUSD"):
            with self.subTest(path=path):
                self.assertEqual(self.route(path, {"price": PRICE})[2], [("get_price", "ETH/USD")])

    def test_attestation_and_health(self):
        """Missing attestation and non-ok health are 503."""
        self.assertEqual(self.route("/attestation", {"attestation_doc": "ab"})[0], 200)
        self.assertEqual(self.route("/attestation", {"error": "Attestation document unavailable"})[0], 503)
        self.assertEqual(self.route("/health", {"status": "ok"})[0], 200)
        self.assertEqual(self.route("/health", {})[0], 503)

    def test_unknown_path_is_404_without_enclave_call(self):
        """Unrouted paths never reach the enclave."""
        status, _, calls = self.route("/nope", {"prices": [PRICE]})
        self.assertEqual((status, calls), (404, []))

    def test_unknown_asset_pattern_matches_the_enclave_source(self):
        """The 404 pattern tracks price_server.rs's get_price miss message."""
        self.assertIn("\"asset '{}' not found\"", (ROOT / "src/price_server.rs").read_text())


class EdgeWiringTest(unittest.TestCase):
    FLEET = ROOT / "infra/modules/nitro-fleet"

    def test_pull_api_edge_host_is_the_name_the_alb_guards(self):
        """EDGE_HOST and every ALB host rule (edge pair + guarded bridge pair) use the same module var."""
        self.assertIn("EDGE_HOST=${edge_domain_name}\n", (self.FLEET / "user-data-prod.sh").read_text())
        self.assertRegex((self.FLEET / "prod.tf").read_text(), r"edge_domain_name\s*=\s*var\.edge_domain_name\n")
        self.assertIn("EnvironmentFile=/etc/kaskad/pull-api.env",
                      (ROOT / "host/systemd/kaskad-pull-api.service").read_text())
        self.assertIn('os.environ.get("EDGE_HOST"', (ROOT / "host/pull_api.py").read_text())
        alb = (self.FLEET / "alb.tf").read_text()
        self.assertEqual(alb.count("host_header { values = [var.edge_domain_name] }"), 4)
        self.assertEqual(alb.count("host_header"), 4)

    def test_edge_only_alb_admits_only_cloudfront_and_refuses_by_default(self):
        """Edge-only: 443 from the CloudFront prefix list, no :80 listener, default 403, guarded bridge."""
        alb = (self.FLEET / "alb.tf").read_text()
        self.assertIn('edge_only     = var.domain_name == "" && local.edge_attached', alb)
        self.assertIn('"com.amazonaws.global.cloudfront.origin-facing"', alb)
        self.assertIn('for_each = local.edge_only ? [] : [80]', alb)
        self.assertIn('count             = var.domain_name == "" && !local.edge_only ? 1 : 0', alb)
        self.assertIn('type             = local.edge_only ? "fixed-response" : "forward"', alb)
        self.assertEqual(alb.count("http_header_name = local.edge_header"), 3)


class _FakeSock:
    def __init__(self, connect_exc=None, replies=()):
        self.connect_exc = connect_exc
        self.replies = list(replies)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def settimeout(self, t):
        pass

    def connect(self, addr):
        if self.connect_exc:
            raise self.connect_exc

    def sendall(self, data):
        pass

    def recv(self, n):
        return self.replies.pop(0) if self.replies else b""


class QueryEnclaveTest(unittest.TestCase):
    def query(self, sock):
        with mock.patch.object(pull_api.socket, "socket", lambda *a: sock):
            return pull_api.query_enclave("health")

    def test_transport_failures_raise(self):
        """Refused, timeout, closed, truncated or garbage replies raise EnclaveUnavailable."""
        frame = (5).to_bytes(4, "big")
        for sock in (_FakeSock(ConnectionRefusedError()), _FakeSock(socket.timeout()),
                     _FakeSock(), _FakeSock(replies=[frame, b"ab"]),
                     _FakeSock(replies=[(3).to_bytes(4, "big"), b"{x}"]),
                     _FakeSock(replies=[(2).to_bytes(4, "big"), b"[]"])):
            with self.subTest(sock=vars(sock)):
                with self.assertRaises(pull_api.EnclaveUnavailable):
                    self.query(sock)

    def test_reply_object_returned(self):
        """A framed JSON object comes back as a dict."""
        body = json.dumps({"status": "ok"}).encode()
        sock = _FakeSock(replies=[len(body).to_bytes(4, "big"), body])
        self.assertEqual(self.query(sock), {"status": "ok"})


class HandlerTest(unittest.TestCase):
    def get(self, path, reply):
        def fake(method, asset=None, timeout=10):
            if isinstance(reply, Exception):
                raise reply
            return reply

        server = pull_api.ThreadingHTTPServer(("127.0.0.1", 0), pull_api.PullAPIHandler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with mock.patch.object(pull_api, "query_enclave", fake):
                conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
                conn.request("GET", path)
                resp = conn.getresponse()
                return resp.status, json.loads(resp.read())
        finally:
            server.shutdown()
            server.server_close()

    def test_enclave_down_is_503_on_the_wire(self):
        """A transport failure reaches the client as 503 with the reason."""
        status, body = self.get("/prices", pull_api.EnclaveUnavailable("enclave not running"))
        self.assertEqual((status, body), (503, {"error": "enclave not running"}))

    def test_prices_served_on_the_wire(self):
        """Signed prices reach the client as 200."""
        self.assertEqual(self.get("/prices", {"prices": [PRICE]})[0], 200)

    def test_handler_sets_a_read_timeout(self):
        """Silent connections are bounded before the semaphore."""
        self.assertEqual(pull_api.PullAPIHandler.timeout, pull_api.HTTP_READ_TIMEOUT)
        self.assertGreater(pull_api.HTTP_READ_TIMEOUT, 0)


class RateLimiterTest(unittest.TestCase):
    def setUp(self):
        self.now = 1000.0
        patch = mock.patch.object(pull_api.time, "monotonic", lambda: self.now)
        patch.start()
        self.addCleanup(patch.stop)

    def test_allows_up_to_limit_then_denies(self):
        """The default budget is 60 per 60s: 60 hits pass, the 61st is denied."""
        rl = pull_api.RateLimiter()
        self.assertEqual([rl.is_allowed("a") for _ in range(61)], [True] * 60 + [False])

    def test_refills_over_time(self):
        """Tokens come back at limit/window per second."""
        rl = pull_api.RateLimiter(limit=2, window=60)
        rl.is_allowed("a")
        rl.is_allowed("a")
        self.assertFalse(rl.is_allowed("a"))
        self.now += 30
        self.assertTrue(rl.is_allowed("a"))

    def test_keys_are_independent(self):
        """One key running dry leaves the others untouched."""
        rl = pull_api.RateLimiter(limit=1, window=60)
        self.assertTrue(rl.is_allowed("a"))
        self.assertFalse(rl.is_allowed("a"))
        self.assertTrue(rl.is_allowed("b"))

    def test_remaining_does_not_create_a_bucket(self):
        """Reading the header value for an unknown key must not grow the table."""
        rl = pull_api.RateLimiter(limit=5, window=60)
        self.assertEqual(rl.remaining("ghost"), 5)
        self.assertEqual(len(rl.clients), 0)

    def test_idle_buckets_are_evicted(self):
        """Buckets idle for a full window are swept on the next hit."""
        rl = pull_api.RateLimiter(limit=5, window=60)
        for n in range(10):
            rl.is_allowed(f"key-{n}")
        self.assertEqual(len(rl.clients), 10)
        self.now += 61
        rl.is_allowed("fresh")
        self.assertEqual(list(rl.clients), ["fresh"])

    def test_eviction_preserves_a_live_bucket(self):
        """A key still inside its window keeps its consumed tokens."""
        rl = pull_api.RateLimiter(limit=5, window=60)
        for _ in range(5):
            rl.is_allowed("busy")
        self.now += 30
        for n in range(10):
            rl.is_allowed(f"other-{n}")
        self.assertIn("busy", rl.clients)
        self.assertEqual(rl.remaining("busy"), 2)

    def test_key_flood_is_bounded_by_max_keys(self):
        """Distinct keys never push the table past the cap."""
        rl = pull_api.RateLimiter(limit=5, window=60, max_keys=100)
        for n in range(5000):
            rl.is_allowed(f"flood-{n}")
        self.assertLessEqual(len(rl.clients), 100)

    def test_denied_request_still_refreshes_last_seen(self):
        """A spammer's bucket stays live instead of being evicted and reset."""
        rl = pull_api.RateLimiter(limit=1, window=60)
        rl.is_allowed("a")
        self.now += 30
        self.assertFalse(rl.is_allowed("a"))
        self.now += 40
        self.assertEqual(rl.remaining("a"), 1)

    def test_memory_stays_bounded_under_key_flood(self):
        """20k distinct keys against a 1k cap hold well under 2 MB."""
        rl = pull_api.RateLimiter(limit=60, window=60, max_keys=1000)
        tracemalloc.start()
        try:
            base = tracemalloc.get_traced_memory()[0]
            for n in range(20_000):
                rl.is_allowed(f"10.{n >> 16 & 255}.{n >> 8 & 255}.{n & 255}")
            used = tracemalloc.get_traced_memory()[0] - base
        finally:
            tracemalloc.stop()
        self.assertEqual(len(rl.clients), 1000)
        self.assertLess(used, 2_000_000)

    def test_cap_evicts_the_oldest_and_keeps_the_newest(self):
        """Past the cap the least recently touched key goes first."""
        rl = pull_api.RateLimiter(limit=5, window=60, max_keys=3)
        for key in ("a", "b", "c", "d"):
            self.now += 1
            rl.is_allowed(key)
        self.assertEqual(list(rl.clients), ["b", "c", "d"])

    def test_touching_a_key_protects_it_from_cap_eviction(self):
        """A fresh hit moves the key to the young end."""
        rl = pull_api.RateLimiter(limit=5, window=60, max_keys=3)
        for key in ("a", "b", "c", "a", "d"):
            self.now += 1
            rl.is_allowed(key)
        self.assertEqual(list(rl.clients), ["c", "a", "d"])

    def test_evicted_key_is_indistinguishable_from_an_idle_one(self):
        """Dropping a bucket idle for a full window changes nothing the client can see."""
        evicted = pull_api.RateLimiter(limit=60, window=60)
        kept = pull_api.RateLimiter(limit=60, window=60)
        for rl in (evicted, kept):
            for _ in range(60):
                rl.is_allowed("a")
        self.now += 61
        evicted.is_allowed("other")
        self.assertNotIn("a", evicted.clients)
        self.assertIn("a", kept.clients)
        for _ in range(61):
            self.assertEqual(evicted.is_allowed("a"), kept.is_allowed("a"))
            self.assertEqual(evicted.remaining("a"), kept.remaining("a"))

    def test_first_hit_reports_limit_minus_one(self):
        """The first request leaves limit - 1 tokens, with no creation-time skew."""
        rl = pull_api.RateLimiter(limit=60, window=60)
        rl.is_allowed("a")
        self.assertEqual(rl.remaining("a"), 59)

    def test_module_limiter_carries_the_default_cap(self):
        """The limiter the handler uses is bounded, not constructed with an unlimited cap."""
        self.assertEqual(pull_api.rate_limiter.max_keys, pull_api.MAX_TRACKED_KEYS)


class LimiterWiringTest(unittest.TestCase):
    """Real HTTP server on loopback: key, 429 body and rate-limit header end to end."""

    ATTACKER = "45.33.32.156"
    EDGE_CHAIN = "1.2.3.4, 93.184.216.34, 130.176.0.1"

    def setUp(self):
        patches = [
            mock.patch.object(pull_api, "_VPC_CIDR", ipaddress.ip_network("127.0.0.0/8")),
            mock.patch.object(pull_api, "EDGE_HOST", EDGE),
            mock.patch.object(pull_api, "rate_limiter", pull_api.RateLimiter()),
            mock.patch.object(pull_api, "query_enclave", lambda method, asset=None, timeout=10: {"status": "ok"}),
            mock.patch.object(pull_api.time, "monotonic", lambda: 1000.0),
            mock.patch.object(pull_api.PullAPIHandler, "log_message", lambda self, fmt, *args: None),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.server = pull_api.ThreadingHTTPServer(("127.0.0.1", 0), pull_api.PullAPIHandler)
        self.server.daemon_threads = True
        self.addCleanup(self.server.server_close)
        thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(self.server.shutdown)

    def get(self, xff=None, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=5)
        try:
            headers = {}
            if xff:
                headers["X-Forwarded-For"] = xff
            if host:
                headers["Host"] = host
            conn.request("GET", "/health", headers=headers)
            resp = conn.getresponse()
            return resp.status, resp.getheader("X-RateLimit-Remaining"), json.loads(resp.read())
        finally:
            conn.close()

    def test_rotating_forged_prefix_exhausts_one_bucket(self):
        """60 requests per window per real key, whatever the caller prepends."""
        codes = [self.get(f"8.8.8.{n % 250}, {self.ATTACKER}")[0] for n in range(62)]
        self.assertEqual(codes, [200] * 60 + [429] * 2)

    def test_limited_response_keeps_its_body_and_header(self):
        """The 429 body and X-RateLimit-Remaining are unchanged."""
        for n in range(60):
            self.get(f"8.8.8.{n}, {self.ATTACKER}")
        status, remaining, body = self.get(f"1.1.1.1, {self.ATTACKER}")
        self.assertEqual((status, remaining), (429, "0"))
        self.assertEqual(body, {"error": "rate limit exceeded", "retry_after": 60})

    def test_edge_viewer_has_a_bucket_of_their_own(self):
        """Through the edge Host the viewer hop is the key, apart from other keys."""
        for n in range(60):
            self.get(f"8.8.8.{n}, {self.ATTACKER}")
        self.assertEqual(self.get(self.EDGE_CHAIN, host=EDGE)[:2], (200, "59"))
        self.assertEqual(self.get(self.EDGE_CHAIN, host=EDGE)[:2], (200, "58"))
        self.assertEqual(list(pull_api.rate_limiter.clients)[-1], "93.184.216.34")

    def test_request_without_xff_is_keyed_on_the_peer(self):
        """No header: the in-VPC peer is the key."""
        self.assertEqual(self.get()[:2], (200, "59"))
        self.assertEqual(list(pull_api.rate_limiter.clients), ["127.0.0.1"])


if __name__ == "__main__":
    unittest.main()
