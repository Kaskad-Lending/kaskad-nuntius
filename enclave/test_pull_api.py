"""Unit tests for `enclave/pull_api.py` — client-IP resolution and rate limiting.

Run: `python3 -m unittest enclave.test_pull_api`
or:  `python3 enclave/test_pull_api.py`
"""

import ipaddress
import os
import sys
import unittest
from email.message import Message
from unittest import mock

# Ensure parent repo dir is on path so we can `import enclave.pull_api`
# regardless of where the test runner is invoked from.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import enclave.pull_api as pull_api  # noqa: E402


class _MockHandler:
    """Minimal stand-in for `BaseHTTPRequestHandler` used by `get_client_ip`."""

    def __init__(self, peer, headers=None):
        self.client_address = (peer, 0)
        self.headers = headers or {}


def _multi_header(*values):
    """Headers object with repeated `X-Forwarded-For` lines, as nginx may emit."""
    msg = Message()
    for value in values:
        msg["X-Forwarded-For"] = value
    return msg


class _TrustModeMixin:
    def _set_trust(self, *cidrs):
        """Point the module at a trusted-proxy list for the duration of a test."""
        nets = tuple(ipaddress.ip_network(c) for c in cidrs)
        mode = (
            pull_api.TrustMode.TRUSTED_CHAIN if nets else pull_api.TrustMode.LEFTMOST
        )
        patches = [
            mock.patch.object(pull_api, "_TRUSTED_PROXIES", nets),
            mock.patch.object(pull_api, "_TRUST_MODE", mode),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)


class GetClientIpTest(_TrustModeMixin, unittest.TestCase):
    def setUp(self):
        # Pin the CIDR to the project default so tests aren't perturbed by
        # the runner's `VPC_CIDR` env var.
        patch = mock.patch.object(
            pull_api, "_VPC_CIDR", ipaddress.ip_network("10.0.0.0/16")
        )
        patch.start()
        self.addCleanup(patch.stop)
        self._set_trust()  # default: legacy leftmost

    # ─── peer handling ───

    def test_direct_hit_uses_peer_ignores_xff(self):
        """TCP peer outside the VPC — X-Forwarded-For is spoofable, use the peer."""
        h = _MockHandler("203.0.113.5", {"X-Forwarded-For": "10.1.1.1"})
        self.assertEqual(pull_api.get_client_ip(h), "203.0.113.5")

    def test_alb_peer_missing_xff_falls_back_to_peer(self):
        h = _MockHandler("10.0.1.5", {})
        self.assertEqual(pull_api.get_client_ip(h), "10.0.1.5")

    def test_alb_peer_empty_xff_falls_back_to_peer(self):
        h = _MockHandler("10.0.1.5", {"X-Forwarded-For": "  "})
        self.assertEqual(pull_api.get_client_ip(h), "10.0.1.5")

    def test_invalid_peer_string_returned_as_is(self):
        """Pathological peer (e.g. a hostname) must not crash."""
        h = _MockHandler("not-an-ip", {})
        self.assertEqual(pull_api.get_client_ip(h), "not-an-ip")

    # ─── legacy leftmost mode ───

    def test_leftmost_mode_takes_first_entry(self):
        h = _MockHandler(
            "10.0.1.5", {"X-Forwarded-For": "203.0.113.5, 192.0.2.1, 10.0.1.5"}
        )
        self.assertEqual(pull_api.get_client_ip(h), "203.0.113.5")

    def test_leftmost_mode_skips_unparseable_first_entry(self):
        """A junk entry is dropped from the chain, not a reason to key on the ALB."""
        h = _MockHandler("10.0.1.5", {"X-Forwarded-For": "not-an-ip, 192.0.2.1"})
        self.assertEqual(pull_api.get_client_ip(h), "192.0.2.1")

    def test_leftmost_mode_all_entries_unparseable_falls_back_to_peer(self):
        h = _MockHandler("10.0.1.5", {"X-Forwarded-For": "junk, also-junk"})
        self.assertEqual(pull_api.get_client_ip(h), "10.0.1.5")

    def test_ipv6_client_accepted(self):
        h = _MockHandler("10.0.1.5", {"X-Forwarded-For": "2001:db8::1, 10.0.1.5"})
        self.assertEqual(pull_api.get_client_ip(h), "2001:db8::1")

    # ─── trusted-chain mode ───
    #
    # These use globally-routable addresses on purpose: `is_private` covers
    # all of RFC 6890, so the 203.0.113.0/24-style documentation ranges are
    # skipped as non-routable hops and would mask what is under test.

    def test_trusted_chain_walks_past_trusted_and_private_hops(self):
        """`client, front nginx, gateway egress` → the client."""
        self._set_trust("49.13.195.55/32")
        h = _MockHandler(
            "10.0.1.5",
            {"X-Forwarded-For": "93.184.216.34, 172.18.0.7, 49.13.195.55"},
        )
        self.assertEqual(pull_api.get_client_ip(h), "93.184.216.34")

    def test_trusted_chain_ignores_forged_prefix_from_direct_caller(self):
        """Attacker forges entries; the ALB appends their true IP on the right."""
        self._set_trust("49.13.195.55/32")
        h = _MockHandler(
            "10.0.1.5",
            {"X-Forwarded-For": "1.1.1.1, 8.8.8.8, 45.33.32.156"},
        )
        self.assertEqual(pull_api.get_client_ip(h), "45.33.32.156")

    def test_trusted_chain_rotating_forgery_lands_on_one_key(self):
        """Rotating the forged prefix must not rotate the rate-limit key."""
        self._set_trust("49.13.195.55/32")
        keys = {
            pull_api.get_client_ip(
                _MockHandler(
                    "10.0.1.5", {"X-Forwarded-For": f"8.8.8.{n}, 45.33.32.156"}
                )
            )
            for n in range(1, 20)
        }
        self.assertEqual(keys, {"45.33.32.156"})

    def test_trusted_chain_cidr_entry_matches(self):
        self._set_trust("49.13.195.0/24")
        h = _MockHandler(
            "10.0.1.5", {"X-Forwarded-For": "93.184.216.34, 49.13.195.200"}
        )
        self.assertEqual(pull_api.get_client_ip(h), "93.184.216.34")

    def test_trusted_chain_all_hops_trusted_uses_rightmost(self):
        """Nothing left to attribute to — key on the authentic rightmost hop."""
        self._set_trust("49.13.195.0/24")
        h = _MockHandler("10.0.1.5", {"X-Forwarded-For": "10.0.0.9, 49.13.195.55"})
        self.assertEqual(pull_api.get_client_ip(h), "49.13.195.55")

    def test_trusted_chain_mixed_families_do_not_raise(self):
        """An IPv6 entry against an IPv4 trusted list is simply untrusted."""
        self._set_trust("49.13.195.0/24")
        h = _MockHandler(
            "10.0.1.5",
            {"X-Forwarded-For": "93.184.216.34, 2606:4700:4700::1111"},
        )
        self.assertEqual(pull_api.get_client_ip(h), "2606:4700:4700::1111")

    def test_repeated_header_lines_form_one_chain(self):
        self._set_trust("49.13.195.55/32")
        h = _MockHandler(
            "10.0.1.5", _multi_header("93.184.216.34, 172.18.0.7", "49.13.195.55")
        )
        self.assertEqual(pull_api.get_client_ip(h), "93.184.216.34")


class RateLimiterTest(unittest.TestCase):
    def setUp(self):
        self.now = 1000.0
        patch = mock.patch.object(pull_api.time, "monotonic", lambda: self.now)
        patch.start()
        self.addCleanup(patch.stop)

    def test_allows_up_to_limit_then_denies(self):
        rl = pull_api.RateLimiter(limit=3, window=60)
        self.assertEqual([rl.is_allowed("a") for _ in range(4)],
                         [True, True, True, False])

    def test_refills_over_time(self):
        rl = pull_api.RateLimiter(limit=2, window=60)
        rl.is_allowed("a")
        rl.is_allowed("a")
        self.assertFalse(rl.is_allowed("a"))
        self.now += 30  # 1 token per 30s at 2/60s
        self.assertTrue(rl.is_allowed("a"))

    def test_keys_are_independent(self):
        rl = pull_api.RateLimiter(limit=1, window=60)
        self.assertTrue(rl.is_allowed("a"))
        self.assertFalse(rl.is_allowed("a"))
        self.assertTrue(rl.is_allowed("b"))

    def test_remaining_does_not_create_a_bucket(self):
        rl = pull_api.RateLimiter(limit=5, window=60)
        self.assertEqual(rl.remaining("ghost"), 5)
        self.assertEqual(len(rl.clients), 0)

    def test_idle_buckets_are_evicted(self):
        rl = pull_api.RateLimiter(limit=5, window=60)
        for n in range(10):
            rl.is_allowed(f"key-{n}")
        self.assertEqual(len(rl.clients), 10)
        self.now += 61
        rl.is_allowed("fresh")
        self.assertEqual(list(rl.clients), ["fresh"])

    def test_eviction_preserves_a_live_bucket(self):
        """A key still inside its window must not lose its consumed tokens."""
        rl = pull_api.RateLimiter(limit=5, window=60)
        for _ in range(5):
            rl.is_allowed("busy")
        self.now += 30
        for n in range(10):
            rl.is_allowed(f"other-{n}")
        self.assertIn("busy", rl.clients)
        self.assertEqual(rl.remaining("busy"), 2)  # 0 + 30s * 5/60

    def test_key_flood_is_bounded_by_max_keys(self):
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
        self.now += 40  # 70s since first hit, only 40s since the denial
        self.assertEqual(rl.remaining("a"), 1)


if __name__ == "__main__":
    unittest.main()
