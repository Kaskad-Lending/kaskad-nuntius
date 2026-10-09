"""Unit tests for `enclave/pull_api.py` — client-IP resolution and rate limiting.

Run: `python3 -m unittest enclave.test_pull_api`
or:  `python3 enclave/test_pull_api.py`
"""

import http.client
import importlib.util
import ipaddress
import json
import os
import sys
import threading
import tracemalloc
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
        rl = pull_api.RateLimiter(limit=5, window=60, max_keys=3)
        for key in ("a", "b", "c", "d"):
            self.now += 1
            rl.is_allowed(key)
        self.assertEqual(list(rl.clients), ["b", "c", "d"])

    def test_touching_a_key_protects_it_from_cap_eviction(self):
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
        evicted.is_allowed("other")  # sweeps "a" out
        self.assertNotIn("a", evicted.clients)
        self.assertIn("a", kept.clients)
        for _ in range(61):
            self.assertEqual(evicted.is_allowed("a"), kept.is_allowed("a"))
            self.assertEqual(evicted.remaining("a"), kept.remaining("a"))

    def test_first_hit_reports_limit_minus_one(self):
        rl = pull_api.RateLimiter(limit=60, window=60)
        rl.is_allowed("a")
        self.assertEqual(rl.remaining("a"), 59)


class TrustedProxiesEnvTest(unittest.TestCase):
    """`TRUSTED_PROXIES` at import time: unset = front hosts, empty = off, else as given."""

    def load(self, **env):
        spec = importlib.util.spec_from_file_location("pull_api_env_probe", pull_api.__file__)
        mod = importlib.util.module_from_spec(spec)
        with mock.patch.dict(os.environ, env):
            if "TRUSTED_PROXIES" not in env:
                os.environ.pop("TRUSTED_PROXIES", None)
            spec.loader.exec_module(mod)
        return mod

    def test_unset_trusts_exactly_the_two_front_hosts(self):
        mod = self.load()
        self.assertIs(mod._TRUST_MODE, mod.TrustMode.TRUSTED_CHAIN)
        self.assertEqual(
            mod._TRUSTED_PROXIES,
            (ipaddress.ip_network("49.13.195.55/32"), ipaddress.ip_network("46.224.136.122/32")),
        )

    def test_empty_turns_the_walk_off(self):
        mod = self.load(TRUSTED_PROXIES="")
        self.assertIs(mod._TRUST_MODE, mod.TrustMode.LEFTMOST)
        self.assertEqual(mod._TRUSTED_PROXIES, ())

    def test_env_replaces_the_defaults(self):
        mod = self.load(TRUSTED_PROXIES="198.51.100.0/24, junk")
        self.assertIs(mod._TRUST_MODE, mod.TrustMode.TRUSTED_CHAIN)
        self.assertEqual(mod._TRUSTED_PROXIES, (ipaddress.ip_network("198.51.100.0/24"),))


class FrontProxyChainTest(_TrustModeMixin, unittest.TestCase):
    """Chains as the ALB sees them from the kaskad.live and testnet.kaskad.live front nginx hosts."""

    PROD, TESTNET = "49.13.195.55", "46.224.136.122"
    VISITOR, ATTACKER = "93.184.216.34", "45.33.32.156"

    def setUp(self):
        patch = mock.patch.object(pull_api, "_VPC_CIDR", ipaddress.ip_network("10.0.0.0/16"))
        patch.start()
        self.addCleanup(patch.stop)
        self._set_trust(*pull_api.DEFAULT_TRUSTED_PROXIES.split(","))

    def ip(self, *xff, peer="10.0.1.5"):
        headers = _multi_header(*xff) if xff else {}
        return pull_api.get_client_ip(_MockHandler(peer, headers))

    def test_visitor_behind_either_front_host_keeps_their_own_key(self):
        for egress in (self.PROD, self.TESTNET):
            with self.subTest(egress=egress):
                self.assertEqual(self.ip(f"{self.VISITOR}, 172.18.0.7, {egress}"), self.VISITOR)

    def test_server_side_caller_on_a_front_host_keys_on_the_egress(self):
        """No visitor in the chain: the host's own scripts share one key, apart from every visitor."""
        self.assertEqual(self.ip(self.PROD), self.PROD)
        self.assertNotEqual(self.ip(self.PROD), self.ip(f"{self.VISITOR}, 172.18.0.7, {self.PROD}"))

    def test_direct_caller_imitating_the_front_shape_keys_on_itself(self):
        self.assertEqual(self.ip(f"8.8.8.8, 172.18.0.7, {self.ATTACKER}"), self.ATTACKER)

    def test_direct_caller_forging_a_trusted_egress_keys_on_itself(self):
        self.assertEqual(self.ip(f"{self.PROD}, {self.TESTNET}, {self.ATTACKER}"), self.ATTACKER)

    def test_forged_prefix_in_repeated_lines_keys_on_the_appended_hop(self):
        """Assumes the ALB appends after the last line; the rollout gate checks it live."""
        self.assertEqual(self.ip("8.8.8.8", f"9.9.9.9, {self.ATTACKER}"), self.ATTACKER)

    def test_peer_outside_the_vpc_ignores_a_trusted_looking_chain(self):
        self.assertEqual(self.ip(f"{self.VISITOR}, {self.PROD}", peer="198.18.0.9"), "198.18.0.9")

    def test_scope_ids_and_percent_escapes_are_never_a_key(self):
        self.assertEqual(self.ip(f"{self.VISITOR}, 2606:4700:4700::1111%eth0"), self.VISITOR)
        self.assertEqual(self.ip(f"{self.VISITOR}, 1.2.3.4%25"), self.VISITOR)

    def test_control_characters_are_never_a_key(self):
        self.assertEqual(self.ip(f"{self.VISITOR}, {self.ATTACKER}\r\nX-Evil: 1"), self.VISITOR)

    def test_unusable_chain_falls_back_to_the_peer(self):
        for xff in ("junk", " , ,", "2606:4700:4700::1111%eth0"):
            with self.subTest(xff=xff):
                self.assertEqual(self.ip(xff), "10.0.1.5")


class HttpWiringTest(unittest.TestCase):
    """Real HTTP server on loopback: key, 429 body and rate-limit header end to end."""

    ATTACKER = "45.33.32.156"
    FRONT_CHAIN = "93.184.216.34, 172.18.0.7, 49.13.195.55"

    def setUp(self):
        patches = [
            mock.patch.object(pull_api, "_VPC_CIDR", ipaddress.ip_network("127.0.0.0/8")),
            mock.patch.object(pull_api, "_TRUSTED_PROXIES", (ipaddress.ip_network("49.13.195.55/32"),)),
            mock.patch.object(pull_api, "_TRUST_MODE", pull_api.TrustMode.TRUSTED_CHAIN),
            mock.patch.object(pull_api, "rate_limiter", pull_api.RateLimiter()),
            mock.patch.object(pull_api, "query_enclave", lambda method, asset=None, timeout=10: {"status": "ok"}),
            mock.patch.object(pull_api.time, "monotonic", lambda: 1000.0),  # no refill mid-test
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

    def get(self, xff=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=5)
        try:
            conn.request("GET", "/health", headers={"X-Forwarded-For": xff} if xff else {})
            resp = conn.getresponse()
            return resp.status, resp.getheader("X-RateLimit-Remaining"), json.loads(resp.read())
        finally:
            conn.close()

    def test_rotating_forged_prefix_exhausts_one_bucket(self):
        codes = [self.get(f"8.8.8.{n % 250}, {self.ATTACKER}")[0] for n in range(62)]
        self.assertEqual(codes, [200] * 60 + [429] * 2)

    def test_limited_response_keeps_its_body_and_header(self):
        for n in range(60):
            self.get(f"8.8.8.{n}, {self.ATTACKER}")
        status, remaining, body = self.get(f"1.1.1.1, {self.ATTACKER}")
        self.assertEqual((status, remaining), (429, "0"))
        self.assertEqual(body, {"error": "rate limit exceeded", "retry_after": 60})

    def test_visitor_behind_the_front_has_a_bucket_of_their_own(self):
        for n in range(60):
            self.get(f"8.8.8.{n}, {self.ATTACKER}")
        self.assertEqual(self.get(self.FRONT_CHAIN)[:2], (200, "59"))
        self.assertEqual(self.get(self.FRONT_CHAIN)[:2], (200, "58"))

    def test_request_without_xff_is_keyed_on_the_peer(self):
        self.assertEqual(self.get()[:2], (200, "59"))
        self.assertEqual(list(pull_api.rate_limiter.clients), ["127.0.0.1"])


class HandlerHardeningTest(unittest.TestCase):
    def test_handler_sets_a_read_timeout(self):
        """A silent connection must not hold a thread: the semaphore is only
        acquired once a request line has been parsed."""
        self.assertEqual(pull_api.PullAPIHandler.timeout, pull_api.HTTP_READ_TIMEOUT)
        self.assertGreater(pull_api.HTTP_READ_TIMEOUT, 0)


if __name__ == "__main__":
    unittest.main()
