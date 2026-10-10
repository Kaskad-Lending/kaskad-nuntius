"""Unit tests for `enclave/pull_api.py` real-client-IP resolution.

Run: `python3 -m unittest enclave.test_pull_api`
or:  `python3 enclave/test_pull_api.py`
"""

import email.message
import ipaddress
import os
import sys
import unittest

# Ensure parent repo dir is on path so we can `import enclave.pull_api`
# regardless of where the test runner is invoked from.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import enclave.pull_api as pull_api  # noqa: E402


def _headers(*values):
    """Real header container: `email.message.Message` is what
    `BaseHTTPRequestHandler.headers` is, duplicates included."""
    msg = email.message.Message()
    for v in values:
        msg["X-Forwarded-For"] = v
    return msg


class _MockHandler:
    """Minimal stand-in for `BaseHTTPRequestHandler` used by `get_client_ip`."""

    def __init__(self, peer, headers=None):
        self.client_address = (peer, 0)
        self.headers = headers if headers is not None else email.message.Message()


class GetClientIpTest(unittest.TestCase):
    def setUp(self):
        # Pin the CIDR to the project default so tests aren't perturbed by
        # the runner's `VPC_CIDR` env var.
        pull_api._VPC_CIDR = ipaddress.ip_network("10.0.0.0/16")

    def test_direct_hit_uses_peer_ignores_xff(self):
        """TCP peer outside the VPC: X-Forwarded-For is spoofable, use the peer."""
        h = _MockHandler("203.0.113.5", _headers("10.1.1.1"))
        self.assertEqual(pull_api.get_client_ip(h), "203.0.113.5")

    def test_alb_peer_uses_xff(self):
        """In-VPC peer (our ALB) with a single hop: that hop is the client."""
        h = _MockHandler("10.0.1.5", _headers("203.0.113.5"))
        self.assertEqual(pull_api.get_client_ip(h), "203.0.113.5")

    def test_alb_peer_chained_xff_takes_last(self):
        """Append mode: the last hop is the address the ALB itself observed."""
        h = _MockHandler("10.0.1.5", _headers("192.0.2.1, 198.51.100.7, 203.0.113.5"))
        self.assertEqual(pull_api.get_client_ip(h), "203.0.113.5")

    def test_client_supplied_prefix_cannot_forge_the_bucket(self):
        """Regression: a caller pre-seeding the header must not pick its own
        rate-limit bucket. The ALB appends what it saw, so only the tail counts."""
        h = _MockHandler("10.0.1.5", _headers("1.2.3.4, 203.0.113.5"))
        self.assertEqual(pull_api.get_client_ip(h), "203.0.113.5")

    def test_duplicate_header_falls_back_to_peer(self):
        """Two X-Forwarded-For headers is a splitting attempt: refuse to parse."""
        h = _MockHandler("10.0.1.5", _headers("1.2.3.4", "203.0.113.5"))
        self.assertEqual(pull_api.get_client_ip(h), "10.0.1.5")

    def test_control_characters_fall_back_to_peer(self):
        h = _MockHandler("10.0.1.5", _headers("203.0.113.5\r\nX-Evil: 1"))
        self.assertEqual(pull_api.get_client_ip(h), "10.0.1.5")

    def test_alb_peer_missing_xff_falls_back_to_peer(self):
        h = _MockHandler("10.0.1.5")
        self.assertEqual(pull_api.get_client_ip(h), "10.0.1.5")

    def test_alb_peer_empty_xff_falls_back_to_peer(self):
        h = _MockHandler("10.0.1.5", _headers("  "))
        self.assertEqual(pull_api.get_client_ip(h), "10.0.1.5")

    def test_malformed_hop_anywhere_falls_back_to_peer(self):
        """One bad hop invalidates the whole chain, not just that entry."""
        h = _MockHandler("10.0.1.5", _headers("not-an-ip, 203.0.113.5"))
        self.assertEqual(pull_api.get_client_ip(h), "10.0.1.5")
        h = _MockHandler("10.0.1.5", _headers("203.0.113.5, not-an-ip"))
        self.assertEqual(pull_api.get_client_ip(h), "10.0.1.5")

    def test_invalid_peer_string_returned_as_is(self):
        """Pathological peer (e.g. a fixture using a hostname) must not crash."""
        h = _MockHandler("not-an-ip")
        self.assertEqual(pull_api.get_client_ip(h), "not-an-ip")

    def test_alb_xff_with_ipv6_client_accepted(self):
        h = _MockHandler("10.0.1.5", _headers("10.0.1.5, 2001:db8::1"))
        self.assertEqual(pull_api.get_client_ip(h), "2001:db8::1")


class HandlerHardeningTest(unittest.TestCase):
    def test_handler_sets_a_read_timeout(self):
        """A silent connection must not hold a thread: the semaphore is only
        acquired once a request line has been parsed."""
        self.assertEqual(pull_api.PullAPIHandler.timeout, pull_api.HTTP_READ_TIMEOUT)
        self.assertGreater(pull_api.HTTP_READ_TIMEOUT, 0)


if __name__ == "__main__":
    unittest.main()
