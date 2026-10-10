"""Tests for the keyex host pull API: client IP behind ALB/CloudFront and failover statuses."""

import email.message
import http.client
import ipaddress
import json
from pathlib import Path
import socket
import threading
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


if __name__ == "__main__":
    unittest.main()
