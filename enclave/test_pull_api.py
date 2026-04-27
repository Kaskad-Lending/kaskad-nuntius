"""Unit tests for `enclave/pull_api.py` real-client-IP resolution.

Run: `python3 -m unittest enclave.test_pull_api`
or:  `python3 enclave/test_pull_api.py`
"""

import ipaddress
import os
import sys
import unittest

# Ensure parent repo dir is on path so we can `import enclave.pull_api`
# regardless of where the test runner is invoked from.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import enclave.pull_api as pull_api  # noqa: E402


class _MockHandler:
    """Minimal stand-in for `BaseHTTPRequestHandler` used by `get_client_ip`."""

    def __init__(self, peer, headers=None):
        self.client_address = (peer, 0)
        self.headers = headers or {}


class GetClientIpTest(unittest.TestCase):
    def setUp(self):
        # Pin the CIDR to the project default so tests aren't perturbed by
        # the runner's `VPC_CIDR` env var.
        pull_api._VPC_CIDR = ipaddress.ip_network("10.0.0.0/16")

    def test_direct_hit_uses_peer_ignores_xff(self):
        """If the TCP peer is OUTSIDE the VPC, X-Forwarded-For is
        spoofable — return the peer verbatim."""
        h = _MockHandler("203.0.113.5", {"X-Forwarded-For": "10.1.1.1"})
        self.assertEqual(pull_api.get_client_ip(h), "203.0.113.5")

    def test_alb_peer_uses_xff(self):
        """ALB-shaped peer (in-VPC) → trust X-Forwarded-For."""
        h = _MockHandler("10.0.1.5", {"X-Forwarded-For": "203.0.113.5"})
        self.assertEqual(pull_api.get_client_ip(h), "203.0.113.5")

    def test_alb_peer_chained_xff_takes_first(self):
        """`client, proxy1, proxy2` — first entry is the real client."""
        h = _MockHandler(
            "10.0.1.5",
            {"X-Forwarded-For": "203.0.113.5, 192.0.2.1, 10.0.1.5"},
        )
        self.assertEqual(pull_api.get_client_ip(h), "203.0.113.5")

    def test_alb_peer_missing_xff_falls_back_to_peer(self):
        h = _MockHandler("10.0.1.5", {})
        self.assertEqual(pull_api.get_client_ip(h), "10.0.1.5")

    def test_alb_peer_empty_xff_falls_back_to_peer(self):
        h = _MockHandler("10.0.1.5", {"X-Forwarded-For": "  "})
        self.assertEqual(pull_api.get_client_ip(h), "10.0.1.5")

    def test_alb_peer_malformed_xff_falls_back_to_peer(self):
        """Malformed first entry — neither IPv4 nor IPv6. Don't accept it."""
        h = _MockHandler(
            "10.0.1.5", {"X-Forwarded-For": "not-an-ip, 192.0.2.1"}
        )
        self.assertEqual(pull_api.get_client_ip(h), "10.0.1.5")

    def test_invalid_peer_string_returned_as_is(self):
        """Pathological peer (e.g. test fixture using a hostname) should
        not crash — return as-is."""
        h = _MockHandler("not-an-ip", {})
        self.assertEqual(pull_api.get_client_ip(h), "not-an-ip")

    def test_alb_xff_with_ipv6_client_accepted(self):
        h = _MockHandler(
            "10.0.1.5", {"X-Forwarded-For": "2001:db8::1, 10.0.1.5"}
        )
        self.assertEqual(pull_api.get_client_ip(h), "2001:db8::1")


if __name__ == "__main__":
    unittest.main()
