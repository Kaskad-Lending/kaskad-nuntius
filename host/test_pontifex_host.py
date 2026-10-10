"""Check approval replay and loopback HTTP using S3/VSOCK mocks."""

import argparse
from contextlib import ExitStack
from dataclasses import dataclass
import enum
import http.client
import io
import ipaddress
import json
import threading
from typing import Any, Optional, TypedDict
import unittest
from unittest.mock import call, patch

import pontifex_host as host


class ApprovalBlob(TypedDict):
    typedData: dict[str, Any]
    signatures: list[str]


class ApprovalReply(TypedDict):
    accepted: bool


def approval_blob(version: int = 1) -> ApprovalBlob:
    return {
        "typedData": {"message": {"version": version}},
        "signatures": ["0x" + "11" * 65],
    }


def pusher_args(**overrides: Any) -> argparse.Namespace:
    fields: dict[str, Any] = {
        "configure_interval": 30,
        "bridge_timeout": 10,
        "asg_tag": "",
        "region": "",
        "peer_asgs": [],
        "artifact_region": "",
        "eif_bucket": "test-eif",
        "oracle_registry": "",
        "bridge_entry": "",
        "rh_rpc": [],
    }
    return argparse.Namespace(**{**fields, **overrides})


def completed(stdout: str) -> Any:
    return host.subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")


class ConfigPusherTest(unittest.TestCase):
    def setUp(self) -> None:
        self.stop_event = threading.Event()
        self.pusher = host.ConfigPusher(pusher_args(), self.stop_event)
        self.key = "approvals/owner.json"
        self.blob = approval_blob()
        mocks = ExitStack()
        self.addCleanup(mocks.close)
        self.aws = mocks.enter_context(patch.object(
            self.pusher, "_aws", side_effect=AssertionError("unexpected AWS call"),
        ))
        self.list_s3 = mocks.enter_context(patch.object(
            self.pusher, "_list_s3", return_value=[self.key],
        ))
        self.read_s3 = mocks.enter_context(patch.object(
            self.pusher, "_read_s3", return_value=json.dumps(self.blob),
        ))
        self.rpc = mocks.enter_context(patch.object(
            host, "vsock_call", return_value={"accepted": True},
        ))
        mocks.enter_context(patch.object(
            host.socket, "socket", side_effect=AssertionError("unexpected socket call"),
        ))

    def approval_call(self, blob: ApprovalBlob) -> Any:
        return call(
            host.ORACLE_CID, host.ORACLE_CONFIG_PORT,
            {**blob, "method": host.EnclaveMethod.APPROVAL.value}, 10,
        )

    def test_running_pusher_stops_and_joins(self) -> None:
        ticked = threading.Event()
        with patch.object(self.pusher, "_tick", side_effect=ticked.set) as tick:
            self.pusher.start()
            try:
                self.assertTrue(ticked.wait(timeout=2))
            finally:
                self.stop_event.set()
                self.pusher.join(timeout=2)
            self.assertFalse(self.pusher.is_alive())
            tick.assert_called_once_with()
        self.aws.assert_not_called()
        self.rpc.assert_not_called()

    def test_accepted_approval_replayed_after_enclave_only_reset(self) -> None:
        installed: set[str] = set()

        def accept(_cid: int, _port: int, payload: dict[str, Any], _timeout: float) -> ApprovalReply:
            installed.add(json.dumps(payload, sort_keys=True))
            return {"accepted": True}

        self.rpc.side_effect = accept
        self.pusher._tick()
        self.pusher._tick()
        self.assertEqual(len(installed), 1)
        installed.clear()
        self.pusher._tick()
        self.assertEqual(len(installed), 1)
        self.assertEqual(self.rpc.call_args_list, [self.approval_call(self.blob)] * 3)
        self.assertEqual(self.read_s3.call_args_list,
                         [call(f"s3://test-eif/{self.key}")] * 3)

    def test_rejection_then_corrected_blob_at_same_key(self) -> None:
        corrected = approval_blob()
        corrected["signatures"].append("0x" + "22" * 65)
        self.read_s3.side_effect = [json.dumps(self.blob), json.dumps(corrected)]
        self.rpc.side_effect = [{"accepted": False, "reason": "insufficient approvals"},
                                {"accepted": True}]
        self.pusher._tick()
        self.pusher._tick()
        self.assertEqual(self.rpc.call_args_list,
                         [self.approval_call(self.blob), self.approval_call(corrected)])

    def test_accepted_blob_updated_at_same_key_is_reread(self) -> None:
        updated = approval_blob(version=2)
        self.read_s3.side_effect = [json.dumps(self.blob), json.dumps(updated)]
        self.pusher._tick()
        self.pusher._tick()
        self.assertEqual(self.rpc.call_args_list,
                         [self.approval_call(self.blob), self.approval_call(updated)])

    def test_transient_vsock_failure_retries_next_cycle(self) -> None:
        self.rpc.side_effect = [host.VsockError("enclave not listening"), {"accepted": True}]
        self.pusher._tick()
        self.pusher._tick()
        self.assertEqual(self.rpc.call_args_list, [self.approval_call(self.blob)] * 2)

    def test_malformed_blob_does_not_block_later_item_or_replacement(self) -> None:
        later_key = "approvals/later.json"
        for malformed in ("{", "null", "[]", '"text"', "42", "true"):
            with self.subTest(blob=malformed):
                self.rpc.reset_mock()
                self.list_s3.side_effect = [[self.key, later_key], [self.key]]
                self.read_s3.side_effect = [malformed, json.dumps(self.blob), json.dumps(self.blob)]
                self.pusher._tick()
                self.pusher._tick()
                self.assertEqual(self.rpc.call_args_list, [self.approval_call(self.blob)] * 2)

    def test_deeply_nested_blob_does_not_block_later_item(self) -> None:
        self.list_s3.return_value = [self.key, "approvals/later.json"]
        self.read_s3.side_effect = ["[" * 2000 + "]" * 2000, json.dumps(self.blob)]
        self.pusher._tick()
        self.rpc.assert_called_once_with(*self.approval_call(self.blob).args)

    def test_invalid_utf8_blob_does_not_block_later_item_or_replacement(self) -> None:
        self.list_s3.side_effect = [[self.key, "approvals/later.json"], [self.key]]
        self.read_s3.side_effect = [
            UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
            json.dumps(self.blob), json.dumps(self.blob),
        ]
        self.pusher._tick()
        self.pusher._tick()
        self.assertEqual(self.rpc.call_args_list, [self.approval_call(self.blob)] * 2)

    def test_unreadable_blob_retries_next_cycle(self) -> None:
        self.read_s3.side_effect = [None, json.dumps(self.blob)]
        self.pusher._tick()
        self.pusher._tick()
        self.rpc.assert_called_once_with(*self.approval_call(self.blob).args)

    def test_malformed_response_does_not_suppress_replay(self) -> None:
        for response in ({}, {"accepted": "true"}, {"error": "bad_request"}, None, []):
            with self.subTest(response=response):
                self.rpc.reset_mock()
                self.rpc.side_effect = [response, {"accepted": True}]
                self.pusher._tick()
                self.pusher._tick()
                self.assertEqual(self.rpc.call_args_list, [self.approval_call(self.blob)] * 2)

    def test_blob_cannot_override_approval_method(self) -> None:
        self.read_s3.return_value = json.dumps({
            **self.blob, "method": host.EnclaveMethod.CONFIGURE.value,
        })
        self.pusher._tick()
        self.rpc.assert_called_once_with(*self.approval_call(self.blob).args)

    def test_empty_pages_do_not_block_later_approval(self) -> None:
        self.list_s3.side_effect = [[], [], [self.key]]
        self.pusher._tick()
        self.pusher._tick()
        self.rpc.assert_not_called()
        self.read_s3.assert_not_called()
        self.pusher._tick()
        self.rpc.assert_called_once_with(*self.approval_call(self.blob).args)
        self.assertEqual(self.list_s3.call_args_list, [call("s3://test-eif/approvals/")] * 3)

    def test_non_json_keys_are_ignored(self) -> None:
        self.list_s3.return_value = ["approvals/", "approvals/owner.txt", self.key]
        self.pusher._tick()
        self.read_s3.assert_called_once_with(f"s3://test-eif/{self.key}")
        self.rpc.assert_called_once_with(*self.approval_call(self.blob).args)

    def test_no_bucket_skips_reads_and_pushes(self) -> None:
        self.pusher._eif_bucket = ""
        self.pusher._tick()
        self.list_s3.assert_not_called()
        self.read_s3.assert_not_called()
        self.rpc.assert_not_called()


class PeerAsgParseTest(unittest.TestCase):
    def test_pairs_keep_order_and_blank_entries_are_skipped(self) -> None:
        """Pairs parse in order; whitespace and blank entries are ignored."""
        self.assertEqual(
            host.parse_peer_asgs(" us-east-1 : kaskad-nitro-us-prod-asg ,, eu-west-1:kaskad-nitro-eu-prod-asg, "),
            [host.PeerAsg("us-east-1", "kaskad-nitro-us-prod-asg"),
             host.PeerAsg("eu-west-1", "kaskad-nitro-eu-prod-asg")],
        )

    def test_empty_input_means_no_peers(self) -> None:
        """Empty or all-blank input yields no peers."""
        for raw in ("", " ", ",", " , ,"):
            with self.subTest(raw=raw):
                self.assertEqual(host.parse_peer_asgs(raw), [])

    def test_malformed_entry_rejected(self) -> None:
        """An entry missing its region or ASG raises ValueError."""
        for raw in ("us-east-1", ":asg", "us-east-1:", " : ", "us-east-1:asg,eu-west-1"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                host.parse_peer_asgs(raw)

    def test_env_reaches_args_and_bad_peer_env_fails_closed(self) -> None:
        """Peer/artifact env vars reach args; a malformed peer list exits 2."""
        with patch.dict(host.os.environ, {
            "KASKAD_PEER_ASGS": "us-east-1:kaskad-nitro-us-prod-asg",
            "KASKAD_ARTIFACT_REGION": "us-east-1",
        }, clear=True):
            args = host.parse_args([])
        self.assertEqual(args.peer_asgs, [host.PeerAsg("us-east-1", "kaskad-nitro-us-prod-asg")])
        self.assertEqual(args.artifact_region, "us-east-1")
        with patch.dict(host.os.environ, {}, clear=True):
            args = host.parse_args([])
        self.assertEqual((args.peer_asgs, args.artifact_region), ([], ""))
        with patch.dict(host.os.environ, {"KASKAD_PEER_ASGS": "us-east-1"}, clear=True), \
                patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as error:
                host.parse_args([])
        self.assertEqual(error.exception.code, 2)


class PeerDiscoveryTest(unittest.TestCase):
    OWN = host.PeerAsg("eu-west-1", "kaskad-nitro-eu-prod-asg")
    PEER = host.PeerAsg("us-east-1", "kaskad-nitro-us-prod-asg")

    def setUp(self) -> None:
        self.pusher = host.ConfigPusher(pusher_args(
            asg_tag=self.OWN.asg_name, region=self.OWN.region,
            peer_asgs=[self.PEER], artifact_region="us-east-1",
        ), threading.Event())
        self.replies: dict[host.PeerAsg, Optional[str]] = {}
        mocks = ExitStack()
        self.addCleanup(mocks.close)
        self.aws = mocks.enter_context(patch.object(self.pusher, "_aws", side_effect=self.fake_aws))
        self.self_ip = mocks.enter_context(patch.object(
            self.pusher, "_self_ip", return_value="10.21.1.5",
        ))
        self.warn = mocks.enter_context(patch.object(host.log, "warning"))

    def fake_aws(self, cmd: list[str], region: str) -> Optional[str]:
        asg_name = cmd[cmd.index("--filters") + 1].rsplit("=", 1)[1]
        return self.replies[host.PeerAsg(region, asg_name)]

    def test_own_then_peer_ips_deduped_without_self(self) -> None:
        """Own-ASG IPs come first, then peers; duplicates and self drop out."""
        self.pusher._peer_asgs = [self.OWN, self.PEER]
        self.replies = {
            self.OWN: json.dumps(["10.21.1.5", "10.21.2.6"]),
            self.PEER: json.dumps(["10.20.1.127", None, "10.20.2.70"]),
        }
        self.assertEqual(self.pusher._discover_oracle_ips(),
                         ["10.21.2.6", "10.20.1.127", "10.20.2.70"])
        self.assertEqual([c.args[1] for c in self.aws.call_args_list],
                         ["eu-west-1", "eu-west-1", "us-east-1"])

    def test_failed_region_does_not_block_others(self) -> None:
        """A failed or garbled region is logged and skipped; the others still count."""
        for broken in (None, "not json", json.dumps({"ip": "10.20.1.127"})):
            with self.subTest(broken=broken):
                self.warn.reset_mock()
                self.replies = {self.OWN: broken, self.PEER: json.dumps(["10.20.1.127"])}
                self.assertEqual(self.pusher._discover_oracle_ips(), ["10.20.1.127"])
                self.replies = {self.OWN: json.dumps(["10.21.2.6"]), self.PEER: broken}
                self.assertEqual(self.pusher._discover_oracle_ips(), ["10.21.2.6"])
                self.assertEqual(self.warn.call_count, 2)

    def test_total_failure_returns_empty_without_imds(self) -> None:
        """Every region failing yields [] and skips the IMDS self lookup."""
        self.replies = {self.OWN: None, self.PEER: None}
        self.assertEqual(self.pusher._discover_oracle_ips(), [])
        self.self_ip.assert_not_called()

    def test_no_asg_and_no_peers_makes_no_calls(self) -> None:
        """Without an own ASG or peers discovery stays idle."""
        self.pusher._asg_tag = ""
        self.pusher._peer_asgs = []
        self.assertEqual(self.pusher._discover_oracle_ips(), [])
        self.aws.assert_not_called()
        self.self_ip.assert_not_called()

    def test_peers_discovered_without_own_asg(self) -> None:
        """Peer ASGs are still queried when the own ASG tag is unset."""
        self.pusher._asg_tag = ""
        self.replies = {self.PEER: json.dumps(["10.20.1.127"])}
        self.assertEqual(self.pusher._discover_oracle_ips(), ["10.20.1.127"])

    def test_configure_push_carries_cross_region_peers(self) -> None:
        """The oracle configure frame lists peers from every region."""
        registry = "0x" + "ab" * 20
        self.pusher._registry = registry
        self.pusher._eif_bucket = ""
        self.replies = {self.OWN: json.dumps(["10.21.2.6"]), self.PEER: json.dumps(["10.20.1.127"])}
        with patch.object(host, "vsock_call", return_value={"ok": True}) as rpc:
            self.pusher._tick()
        rpc.assert_called_once_with(host.ORACLE_CID, host.ORACLE_CONFIG_PORT, {
            "method": host.EnclaveMethod.CONFIGURE.value,
            "registry": registry,
            "rhRpcs": [],
            "oraclePeers": ["10.21.2.6", "10.20.1.127"],
        }, 10)


class AwsRegionTest(unittest.TestCase):
    def test_single_region_describe_argv_unchanged(self) -> None:
        """Without peer config the describe call keeps its exact legacy argv."""
        pusher = host.ConfigPusher(pusher_args(
            asg_tag="kaskad-nitro-us-prod-asg", region="us-east-1",
        ), threading.Event())
        with patch.object(host.subprocess, "run",
                          return_value=completed('["10.20.1.127", "10.20.2.70"]')) as run, \
                patch.object(pusher, "_self_ip", return_value="10.20.1.127"):
            self.assertEqual(pusher._discover_oracle_ips(), ["10.20.2.70"])
        run.assert_called_once_with([
            "aws", "ec2", "describe-instances", "--filters",
            "Name=tag:aws:autoscaling:groupName,Values=kaskad-nitro-us-prod-asg",
            "Name=instance-state-name,Values=running",
            "--query", "Reservations[].Instances[].PrivateIpAddress",
            "--output", "json", "--region", "us-east-1",
        ], capture_output=True, text=True, timeout=15)

    def test_s3_uses_artifact_region_else_host_region(self) -> None:
        """S3 list/read target the artifact region, defaulting to the host region."""
        for artifact, expected in (("us-east-1", "us-east-1"), ("", "eu-west-1")):
            with self.subTest(artifact=artifact):
                pusher = host.ConfigPusher(pusher_args(
                    region="eu-west-1", artifact_region=artifact,
                ), threading.Event())
                with patch.object(host.subprocess, "run", return_value=completed("")) as run:
                    pusher._list_s3("s3://test-eif/approvals/")
                    pusher._read_s3("s3://test-eif/approvals/owner.json")
                self.assertEqual([c.args[0] for c in run.call_args_list], [
                    ["aws", "s3", "ls", "s3://test-eif/approvals/", "--recursive",
                     "--region", expected],
                    ["aws", "s3", "cp", "s3://test-eif/approvals/owner.json", "-",
                     "--region", expected],
                ])


class VsockBoundsTest(unittest.TestCase):
    def test_oversized_response_rejected_before_body_read(self) -> None:
        with patch.object(host.socket, "socket") as socket_factory:
            sock = socket_factory.return_value
            sock.recv.return_value = host.FRAME_HEADER.pack(host.MAX_FRAME + 1)
            with self.assertRaisesRegex(host.VsockError, "oversized response frame"):
                host.vsock_call(
                    host.ORACLE_CID, host.ORACLE_CONFIG_PORT,
                    {**approval_blob(), "method": host.EnclaveMethod.APPROVAL.value}, 10,
                )
            sock.recv.assert_called_once_with(host.FRAME_HEADER.size)
            self.assertTrue(sock.settimeout.call_args_list)
            self.assertTrue(all(0 < c.args[0] <= 10 for c in sock.settimeout.call_args_list))
            sock.close.assert_called_once_with()

    def test_malformed_response_frames_are_transport_errors(self) -> None:
        for body in (b"", b"{", b"null", b"[]", b'"text"', b"42", b"true", b"\xff",
                     b'{"value":NaN}', b'{"value":Infinity}'):
            with self.subTest(body=body), patch.object(host.socket, "socket") as factory:
                sock = factory.return_value
                sock.recv.side_effect = [host.FRAME_HEADER.pack(len(body)), body]
                with self.assertRaisesRegex(host.VsockError, "malformed JSON frame"):
                    host.vsock_call(host.BRIDGE_CID, host.BRIDGE_API_PORT, {}, 10)
                sock.close.assert_called_once_with()

    def test_fragmented_response_is_reassembled(self) -> None:
        body = b'{"state":"ready"}'
        header = host.FRAME_HEADER.pack(len(body))
        with patch.object(host.socket, "socket") as factory:
            sock = factory.return_value
            sock.recv.side_effect = [header[:1], header[1:], body[:2], body[2:]]
            self.assertEqual(host.vsock_call(host.BRIDGE_CID, host.BRIDGE_API_PORT, {}, 10),
                             {"state": "ready"})
            self.assertEqual(sock.recv.call_args_list,
                             [call(4), call(3), call(len(body)), call(len(body) - 2)])
            sock.close.assert_called_once_with()

    def test_truncated_response_is_rejected(self) -> None:
        with patch.object(host.socket, "socket") as factory:
            sock = factory.return_value
            sock.recv.side_effect = [host.FRAME_HEADER.pack(10), b"{}", b""]
            with self.assertRaisesRegex(host.VsockError, "closed mid-frame"):
                host.vsock_call(host.BRIDGE_CID, host.BRIDGE_API_PORT, {}, 10)
            sock.close.assert_called_once_with()

    def test_oversized_request_is_rejected_before_connect(self) -> None:
        with patch.object(host.socket, "socket") as factory:
            with self.assertRaisesRegex(host.VsockError, "oversized request frame"):
                host.vsock_call(host.BRIDGE_CID, host.BRIDGE_API_PORT,
                                {"data": "x" * host.MAX_REQUEST_FRAME}, 10)
            factory.assert_not_called()

    def test_trickled_response_cannot_extend_total_deadline(self) -> None:
        elapsed = 0.0

        def recv(_length: int) -> bytes:
            nonlocal elapsed
            elapsed += 0.4
            return b"\x00"

        with patch.object(host.socket, "socket") as factory, \
                patch.object(host.time, "monotonic", side_effect=lambda: elapsed):
            sock = factory.return_value
            sock.recv.side_effect = recv
            with self.assertRaisesRegex(host.VsockError, "enclave timeout"):
                host.vsock_call(host.BRIDGE_CID, host.BRIDGE_API_PORT, {}, 1)
            self.assertEqual(sock.recv.call_count, 3)
            sock.close.assert_called_once_with()

    def test_socket_failure_is_a_transport_error(self) -> None:
        with patch.object(host.socket, "socket", side_effect=OSError("unavailable")):
            with self.assertRaisesRegex(host.VsockError, "unavailable"):
                host.vsock_call(host.BRIDGE_CID, host.BRIDGE_API_PORT, {}, 10)


class RateLimiterTest(unittest.TestCase):
    def test_new_client_receives_its_first_token(self) -> None:
        limiter = host.RateLimiter(1, 60)
        with patch.object(host.time, "monotonic", side_effect=[1.0, 2.0, 3.0]):
            self.assertTrue(limiter.allow("198.51.100.1"))
            self.assertFalse(limiter.allow("198.51.100.1"))


class TrustedProxyConfigTest(unittest.TestCase):
    def test_default_is_direct_mode(self) -> None:
        with patch.dict(host.os.environ, {}, clear=True):
            self.assertEqual(host.parse_args([]).trusted_proxy_cidrs, ())

    def test_env_is_validated_and_cli_can_override_or_disable(self) -> None:
        with patch.dict(host.os.environ, {
            "PONTIFEX_TRUSTED_PROXY_CIDRS": "10.0.0.0/16, 2001:db8::/32",
        }, clear=True):
            self.assertEqual(host.parse_args([]).trusted_proxy_cidrs,
                             (ipaddress.ip_network("10.0.0.0/16"),
                              ipaddress.ip_network("2001:db8::/32")))
            self.assertEqual(host.parse_args(["--trusted-proxy-cidrs", "127.0.0.0/8"])
                             .trusted_proxy_cidrs, (ipaddress.ip_network("127.0.0.0/8"),))
            self.assertEqual(host.parse_args(["--trusted-proxy-cidrs", ""]).trusted_proxy_cidrs, ())

    def test_invalid_proxy_config_fails_closed(self) -> None:
        for value in ("not-a-cidr", "10.0.0.1/16", "10.0.0.0/33", "10.0.0.0/16,", ",", " "):
            with self.subTest(value=value), patch.dict(host.os.environ, {
                "PONTIFEX_TRUSTED_PROXY_CIDRS": value,
            }, clear=True), patch("sys.stderr", new_callable=io.StringIO):
                with self.assertRaises(SystemExit) as error:
                    host.parse_args([])
                self.assertEqual(error.exception.code, 2)


class HttpMethod(str, enum.Enum):
    GET = "GET"
    POST = "POST"
    HEAD = "HEAD"
    PUT = "PUT"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"


class ClaimGrant(TypedDict):
    signature: str
    cumulativeBurned: str
    deadline: int
    signer: str
    igraBlock: int


@dataclass(frozen=True)
class HttpResult:
    status: int
    body: bytes
    headers: dict[str, str]

    def json(self) -> dict[str, Any]:
        return json.loads(self.body)


class BridgeHttpTest(unittest.TestCase):
    def setUp(self) -> None:
        mocks = ExitStack()
        self.addCleanup(mocks.close)
        self.rpc = mocks.enter_context(patch.object(host, "vsock_call"))
        mocks.enter_context(patch.object(
            host.ConfigPusher, "_aws", side_effect=AssertionError("unexpected AWS call"),
        ))
        mocks.enter_context(patch.object(
            host, "_instance_private_ip", side_effect=AssertionError("unexpected IMDS call"),
        ))
        mocks.enter_context(patch.object(host.log, "info"))
        mocks.enter_context(patch.object(host.log, "warning"))
        self.ctx = host.HostContext(argparse.Namespace(
            bridge_timeout=0.5, rate_limit=1000, rate_window=60, sign_cache_ttl=60,
            trusted_proxy_cidrs=(),
        ))

        class Handler(host.PontifexHandler):
            timeout = 0.15

        Handler.ctx = self.ctx
        self.server = host.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True,
        )
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.recipient = "0x" + "ab" * 20
        self.grant: ClaimGrant = {
            "signature": "0x" + "11" * 65,
            "cumulativeBurned": "1000000000000000000",
            "deadline": 2000000000,
            "signer": "0x" + "22" * 20,
            "igraBlock": 123,
        }

    def stop_server(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.assertFalse(self.thread.is_alive())

    def connection(self) -> http.client.HTTPConnection:
        return http.client.HTTPConnection(*self.server.server_address, timeout=2)

    def request(self, method: HttpMethod, path: str, body: Optional[bytes] = None,
                headers: Optional[dict[str, str]] = None) -> HttpResult:
        conn = self.connection()
        try:
            conn.request(method.value, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            return HttpResult(resp.status, resp.read(), dict(resp.getheaders()))
        finally:
            conn.close()

    def raw_request(self, headers: list[tuple[str, str]], body: bytes = b"",
                    shutdown_write: bool = False, *, method: HttpMethod = HttpMethod.POST,
                    path: str = "/bridge/sign") -> HttpResult:
        conn = self.connection()
        try:
            conn.putrequest(method.value, path)
            for name, value in headers:
                conn.putheader(name, value)
            conn.endheaders(body)
            if shutdown_write:
                conn.sock.shutdown(host.socket.SHUT_WR)
            resp = conn.getresponse()
            return HttpResult(resp.status, resp.read(), dict(resp.getheaders()))
        finally:
            conn.close()

    def sign_body(self, recipient: Optional[str] = None) -> bytes:
        return json.dumps({"recipient": recipient or self.recipient}).encode()

    def test_health_aliases_and_root_only_call_bridge_health(self) -> None:
        self.rpc.return_value = {"state": "ready"}
        for path in ("/", "/health", "/health/", "/bridge/health", "/bridge/health/?unused=1"):
            with self.subTest(path=path):
                result = self.request(HttpMethod.GET, path)
                self.assertEqual(result.status, 200)
                self.assertEqual(result.json(), {"state": "ready"})
                self.rpc.assert_called_with(host.BRIDGE_CID, host.BRIDGE_API_PORT,
                                            {"method": host.EnclaveMethod.HEALTH.value}, 0.5)

    def test_readiness_aliases_call_only_fixed_snapshot_method(self) -> None:
        self.rpc.return_value = {"state": "ready"}
        self.ctx.bridge_timeout = 10
        for path in ("/bridge/ready", "/ready"):
            with self.subTest(path=path):
                result = self.request(HttpMethod.GET, path)
                self.assertEqual(result.status, 200)
                self.assertEqual(result.json(), {"state": "ready"})
                self.rpc.assert_called_with(host.BRIDGE_CID, host.BRIDGE_API_PORT,
                                            {"method": host.EnclaveMethod.READINESS.value},
                                            host.READINESS_TIMEOUT)

    def test_fetching_is_not_ready(self) -> None:
        self.rpc.return_value = {"state": "fetching"}
        result = self.request(HttpMethod.GET, "/bridge/ready")
        self.assertEqual(result.status, 503)
        self.assertEqual(result.json(), {"state": "fetching"})

    def test_readiness_requires_exact_response_shape(self) -> None:
        for response in (None, [], {}, {"state": "unknown"}, {"state": True},
                         {"state": "ready", "error": "not_ready"},
                         {"state": "ready", "extra": True}, {"error": "not_ready"}):
            with self.subTest(response=response):
                self.rpc.return_value = response
                result = self.request(HttpMethod.GET, "/bridge/ready")
                self.assertEqual(result.status, 503)
                self.assertEqual(result.json(), {"error": "bad_enclave_response"})

    def test_readiness_paths_are_exact_and_other_requests_are_gated(self) -> None:
        with patch.object(self.ctx.rate, "allow", return_value=True) as allow:
            for path in ("/bridge/ready/", "/bridge/ready?nonce=00", "/bridge/ready/extra",
                         "/ready/", "/ready?method=health"):
                with self.subTest(path=path):
                    self.assertEqual(self.request(HttpMethod.GET, path).status, 404)
            self.assertEqual(allow.call_count, 5)
        self.rpc.assert_not_called()

    def test_readiness_bypasses_quota_but_not_diagnostics_or_attestation(self) -> None:
        self.ctx.trusted_proxy_cidrs = (ipaddress.ip_network("127.0.0.0/8"),)
        self.rpc.return_value = {"state": "ready"}
        with patch.object(self.ctx.rate, "allow", return_value=False) as allow:
            for path in ("/bridge/ready", "/ready"):
                self.assertEqual(self.request(HttpMethod.GET, path).status, 200)
            allow.assert_not_called()
            for method, path in ((HttpMethod.GET, "/bridge/health"),
                                 (HttpMethod.GET, "/bridge/attestation"),
                                 (HttpMethod.POST, "/bridge/sign")):
                self.assertEqual(self.request(method, path).status, 429)
            self.assertEqual(allow.call_args_list, [call("127.0.0.1")] * 3)
        self.assertEqual(self.rpc.call_count, 2)

    def test_fetching_diagnostics_and_pre_enrollment_attestation_remain_available(self) -> None:
        self.rpc.side_effect = [{"state": "fetching"}, {"attestation": "0xaabb"}]
        self.assertEqual(self.request(HttpMethod.GET, "/bridge/health").status, 200)
        self.assertEqual(self.request(HttpMethod.GET, "/bridge/attestation").status, 200)
        self.assertEqual([c.args[2] for c in self.rpc.call_args_list],
                         [{"method": host.EnclaveMethod.HEALTH.value},
                          {"method": host.EnclaveMethod.GET_ATTESTATION.value}])

    def test_attestation_aliases_forward_optional_nonce(self) -> None:
        self.rpc.return_value = {"attestation": "0xaabb"}
        for path in ("/attestation", "/bridge/attestation"):
            for query, nonce in (("", None), ("?nonce=aAbB", "aAbB"),
                                 ("/?unused=1&nonce=00", "00")):
                with self.subTest(path=path, query=query):
                    result = self.request(HttpMethod.GET, path + query)
                    self.assertEqual(result.status, 200)
                    expected = {"method": host.EnclaveMethod.GET_ATTESTATION.value}
                    if nonce is not None:
                        expected["nonce"] = nonce
                    self.rpc.assert_called_with(host.BRIDGE_CID, host.BRIDGE_API_PORT,
                                                expected, 0.5)

    def test_bad_nonces_are_rejected_without_enclave_call(self) -> None:
        queries = ("nonce=", "nonce", "nonce=z0", "nonce=0x00", "nonce=abc",
                   "nonce=00&nonce=11", "nonce=" + "aa" * 513, "nonce=%00")
        for path in ("/attestation", "/bridge/attestation"):
            for query in queries:
                with self.subTest(path=path, query=query[:40]):
                    result = self.request(HttpMethod.GET, path + "?" + query)
                    self.assertEqual(result.status, 400)
                    self.assertEqual(result.json(), {"error": "bad_nonce"})
        self.rpc.assert_not_called()

    def test_sign_aliases_share_cache_and_normalize_recipient(self) -> None:
        self.rpc.return_value = self.grant
        result = self.request(HttpMethod.POST, "/bridge/sign", self.sign_body("0x" + "AB" * 20))
        self.assertEqual(result.status, 200)
        self.assertEqual(result.json(), self.grant)
        result = self.request(HttpMethod.POST, "/sign/", self.sign_body())
        self.assertEqual(result.status, 200)
        self.assertEqual(result.json(), {**self.grant, "cached": True})
        self.rpc.assert_called_once_with(host.BRIDGE_CID, host.BRIDGE_API_PORT,
                                         {"method": host.EnclaveMethod.SIGN_CLAIM.value,
                                          "recipient": self.recipient}, 0.5)

    def test_non_object_or_malformed_sign_json_is_rejected(self) -> None:
        for path in ("/sign", "/bridge/sign"):
            for body in (b"[]", b"null", b"42", b"true", b'"text"', b"{", b"\xff",
                         b'{"recipient":NaN}'):
                with self.subTest(path=path, body=body):
                    result = self.request(HttpMethod.POST, path, body)
                    self.assertEqual(result.status, 400)
                    self.assertEqual(result.json(), {"error": "bad_json"})
        self.rpc.assert_not_called()

    def test_invalid_recipient_is_rejected(self) -> None:
        for recipient in (None, 1, [], "", "0x1234", self.recipient + "\n"):
            with self.subTest(recipient=recipient):
                result = self.request(HttpMethod.POST, "/bridge/sign",
                                      json.dumps({"recipient": recipient}).encode())
                self.assertEqual(result.status, 400)
                self.assertEqual(result.json(), {"error": "bad_recipient"})
        self.rpc.assert_not_called()

    def test_bad_lengths_and_transfer_encoding_close_without_body_read(self) -> None:
        cases = [[], [("Content-Length", "0")], [("Content-Length", "-1")],
                 [("Content-Length", "invalid")], [("Content-Length", "+2")],
                 [("Content-Length", "1_0")], [("Content-Length", str(host.MAX_SIGN_BODY + 1))],
                 [("Content-Length", "2"), ("Content-Length", "2")],
                 [("Content-Length", "2"), ("Transfer-Encoding", "chunked")]]
        for headers in cases:
            with self.subTest(headers=headers):
                result = self.raw_request(headers)
                self.assertEqual(result.status, 400)
                self.assertEqual(result.json(), {"error": "bad_length"})
                self.assertEqual(result.headers["Connection"], "close")
        self.rpc.assert_not_called()

    def test_get_body_framing_is_rejected_before_enclave_call(self) -> None:
        cases = [[("Content-Length", value)] for value in
                 ("1", "-1", "+0", "0, 0", "invalid", "", "0.0", "0\r\n 0")]
        cases += [[("Content-Length", "0"), ("Content-Length", "0")],
                  [("Content-Length", "0"), ("Content-Length", "1")],
                  [("Transfer-Encoding", "chunked")], [("Transfer-Encoding", "")],
                  [("Content-Length", "0"), ("Transfer-Encoding", "identity")],
                  [("Content-Length ", "1")]]
        for path in ("/bridge/health", "/bridge/attestation", "/bridge/ready"):
            for headers in cases:
                with self.subTest(path=path, headers=headers):
                    result = self.raw_request(headers, method=HttpMethod.GET, path=path)
                    self.assertEqual(result.status, 400)
                    self.assertEqual(result.json(), {"error": "bad_length"})
                    self.assertEqual(result.headers["Connection"], "close")
        self.rpc.assert_not_called()

    def test_get_body_cannot_become_a_second_persistent_request(self) -> None:
        body = self.sign_body()
        embedded = (b"POST /bridge/sign HTTP/1.1\r\nHost: localhost\r\nContent-Length: "
                    + str(len(body)).encode() + b"\r\n\r\n" + body)
        self.rpc.return_value = {"state": "ready", "attestation": "0xaabb", **self.grant}
        for path in ("/", "/health", "/bridge/health", "/attestation", "/bridge/attestation",
                     "/ready", "/bridge/ready"):
            for framing in (f"Content-Length: {len(embedded)}", "Transfer-Encoding: chunked",
                            "Content-Length: 0\r\nContent-Length: 1"):
                with self.subTest(path=path, framing=framing):
                    request = (f"GET {path} HTTP/1.1\r\nHost: localhost\r\n"
                               f"{framing}\r\n\r\n").encode() + embedded
                    with host.socket.create_connection(self.server.server_address, timeout=2) as sock:
                        sock.sendall(request)
                        response = bytearray()
                        while True:
                            try:
                                chunk = sock.recv(4096)
                            except ConnectionResetError:
                                break
                            if not chunk:
                                break
                            response.extend(chunk)
                    self.assertTrue(response.startswith(b"HTTP/1.1 400 "), response)
                    self.assertIn(b"Connection: close\r\n", response)
                    self.assertEqual(response.count(b"HTTP/1.1 "), 1)
                    self.assertEqual(json.loads(response.partition(b"\r\n\r\n")[2]),
                                     {"error": "bad_length"})
        self.rpc.assert_not_called()

    def test_bodyless_gets_keep_connection_usable(self) -> None:
        for headers in ({}, {"Content-Length": "0"}, {"Content-Length": "00"}):
            with self.subTest(headers=headers):
                self.rpc.reset_mock()
                self.rpc.side_effect = [{"state": "ready"}, {"attestation": "0xaabb"}]
                conn = self.connection()
                try:
                    conn.request(HttpMethod.GET.value, "/bridge/health", headers=headers)
                    response = conn.getresponse()
                    self.assertEqual(response.status, 200)
                    response.read()
                    original_socket = conn.sock
                    self.assertIsNotNone(original_socket)
                    conn.request(HttpMethod.GET.value, "/bridge/attestation")
                    response = conn.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(json.loads(response.read()), {"attestation": "0xaabb"})
                    self.assertIs(conn.sock, original_socket)
                    self.assertEqual(self.rpc.call_count, 2)
                finally:
                    conn.close()

    def test_incomplete_body_is_rejected(self) -> None:
        result = self.raw_request([("Content-Length", "20")], b"{}", shutdown_write=True)
        self.assertEqual(result.status, 400)
        self.rpc.assert_not_called()

    def test_stalled_body_times_out(self) -> None:
        result = self.raw_request([("Content-Length", "20")], b"{")
        self.assertEqual(result.status, 408)
        self.assertEqual(result.json(), {"error": "request_timeout"})
        self.rpc.assert_not_called()

    def test_trickled_body_cannot_extend_total_deadline(self) -> None:
        conn = self.connection()
        stop = threading.Event()
        try:
            conn.putrequest(HttpMethod.POST.value, "/bridge/sign")
            conn.putheader("Content-Length", "4096")
            conn.endheaders()

            def drip() -> None:
                while not stop.wait(0.02):
                    try:
                        conn.send(b" ")
                    except OSError:
                        break

            sender = threading.Thread(target=drip, daemon=True)
            sender.start()
            try:
                resp = conn.getresponse()
                self.assertEqual(resp.status, 408)
                self.assertEqual(json.loads(resp.read()), {"error": "request_timeout"})
            finally:
                stop.set()
                sender.join(timeout=2)
        finally:
            conn.close()
        self.rpc.assert_not_called()

    def test_unrecognized_paths_and_wrong_methods_stay_404(self) -> None:
        paths = ("/bridge", "/bridge/claim", "/bridge/configure", "/bridge/approval",
                 "/bridge/control", "/bridge/sign_claim", "/configure", "/approval",
                 "/keyex_health", "/control5005", "/bridge/health/extra", "/other")
        cases = [(method, path) for path in paths for method in (HttpMethod.GET, HttpMethod.POST)]
        cases += [(HttpMethod.GET, "/sign"), (HttpMethod.GET, "/bridge/sign"),
                  (HttpMethod.POST, "/health"), (HttpMethod.POST, "/bridge/health"),
                  (HttpMethod.POST, "/attestation"), (HttpMethod.POST, "/bridge/attestation"),
                  (HttpMethod.POST, "/ready"), (HttpMethod.POST, "/bridge/ready")]
        for method, path in cases:
            with self.subTest(method=method, path=path):
                result = self.request(method, path, b"{}" if method == HttpMethod.POST else None)
                self.assertEqual(result.status, 404)
                self.assertEqual(result.json(), {"error": "not_found"})
        self.rpc.assert_not_called()

    def test_unsupported_http_methods_do_not_dispatch(self) -> None:
        for method in (HttpMethod.HEAD, HttpMethod.PUT, HttpMethod.DELETE, HttpMethod.OPTIONS):
            for path in ("/health", "/bridge/health", "/bridge/sign"):
                with self.subTest(method=method, path=path):
                    self.assertEqual(self.request(method, path).status, 501)
        self.rpc.assert_not_called()

    def test_transport_failures_map_to_gateway_errors(self) -> None:
        for error in ("enclave timeout", "malformed JSON frame", "oversized response frame"):
            self.rpc.side_effect = host.VsockError(error)
            for method, path, status in ((HttpMethod.GET, "/bridge/health", 503),
                                         (HttpMethod.GET, "/bridge/attestation", 503),
                                         (HttpMethod.GET, "/bridge/ready", 503),
                                         (HttpMethod.POST, "/bridge/sign", 502)):
                with self.subTest(error=error, path=path):
                    result = self.request(method, path,
                                          self.sign_body() if method == HttpMethod.POST else None)
                    self.assertEqual(result.status, status)
                    self.assertEqual(result.json(), {"error": "enclave_unreachable"})
        self.assertTrue(all(c.args[:2] == (host.BRIDGE_CID, host.BRIDGE_API_PORT)
                            for c in self.rpc.call_args_list))

    def test_bad_proxy_response_shapes_are_not_success(self) -> None:
        for path, field in (("/bridge/health", "state"), ("/bridge/attestation", "attestation")):
            for response in (None, [], "text", {}, {field: []}, {field: ""}, {"error": None}):
                with self.subTest(path=path, response=response):
                    self.rpc.return_value = response
                    result = self.request(HttpMethod.GET, path)
                    self.assertEqual(result.status, 503)
                    self.assertEqual(result.json(), {"error": "bad_enclave_response"})

    def test_bad_sign_response_is_not_cached(self) -> None:
        responses = [None, [], "text", {}, {"signature": "0x11"}, {"error": False},
                     {**self.grant, "deadline": True}, {**self.grant, "igraBlock": -1},
                     {**self.grant, "signature": []}, {**self.grant, "cumulativeBurned": 1}]
        for response in responses:
            with self.subTest(response=response):
                self.rpc.return_value = response
                result = self.request(HttpMethod.POST, "/bridge/sign", self.sign_body())
                self.assertEqual(result.status, 502)
                self.assertEqual(result.json(), {"error": "bad_enclave_response"})
                self.assertIsNone(self.ctx.sign_cache.get(self.recipient))
        self.rpc.return_value = self.grant
        self.assertEqual(self.request(HttpMethod.POST, "/sign", self.sign_body()).status, 200)
        self.assertEqual(self.rpc.call_count, len(responses) + 1)

    def test_coded_enclave_refusals_are_preserved(self) -> None:
        self.rpc.return_value = {"error": "not_ready"}
        for method, path, status in ((HttpMethod.GET, "/bridge/health", 503),
                                     (HttpMethod.GET, "/bridge/attestation", 503),
                                     (HttpMethod.POST, "/bridge/sign", 409)):
            result = self.request(method, path,
                                  self.sign_body() if method == HttpMethod.POST else None)
            self.assertEqual(result.status, status)
            self.assertEqual(result.json(), {"error": "not_ready"})
        self.assertIsNone(self.ctx.sign_cache.get(self.recipient))

    def test_untrusted_forwarded_headers_do_not_change_client_identity(self) -> None:
        self.rpc.return_value = {"state": "ready"}
        for cidrs in ((), (ipaddress.ip_network("10.0.0.0/16"),)):
            with self.subTest(cidrs=cidrs):
                self.ctx.trusted_proxy_cidrs = cidrs
                self.ctx.rate = host.RateLimiter(1, 3600)
                first = self.request(HttpMethod.GET, "/bridge/health",
                                     headers={"X-Forwarded-For": "198.51.100.1"})
                second = self.request(HttpMethod.GET, "/bridge/health",
                                      headers={"X-Forwarded-For": "198.51.100.2"})
                self.assertEqual((first.status, second.status), (200, 429))
                self.assertEqual(set(self.ctx.rate._clients), {"127.0.0.1"})

    def test_direct_mode_ignores_malformed_forwarded_headers(self) -> None:
        self.rpc.return_value = {"state": "ready"}
        result = self.raw_request([("X-Forwarded-For", "not-an-ip"),
                                   ("X-Forwarded-For", ",")],
                                  method=HttpMethod.GET, path="/bridge/health")
        self.assertEqual(result.status, 200)

    def test_trusted_proxy_uses_rightmost_client_per_keepalive_request(self) -> None:
        self.ctx.trusted_proxy_cidrs = (ipaddress.ip_network("127.0.0.0/8"),)
        self.ctx.rate = host.RateLimiter(1, 3600)
        self.rpc.return_value = {"state": "ready"}
        conn = self.connection()
        try:
            conn.connect()
            original_socket = conn.sock
            for chain, status in (("192.0.2.1, 198.51.100.1", 200),
                                  ("192.0.2.1, 198.51.100.2", 200),
                                  ("192.0.2.200, 198.51.100.1", 429)):
                with self.subTest(chain=chain):
                    self.assertIs(conn.sock, original_socket)
                    conn.request(HttpMethod.GET.value, "/bridge/health",
                                 headers={"X-Forwarded-For": chain})
                    response = conn.getresponse()
                    self.assertEqual(response.status, status)
                    response.read()
        finally:
            conn.close()
        self.assertEqual(set(self.ctx.rate._clients), {"198.51.100.1", "198.51.100.2"})
        self.assertEqual(self.rpc.call_count, 2)

    def test_trusted_proxy_normalizes_ipv6_client_identity(self) -> None:
        self.ctx.trusted_proxy_cidrs = (ipaddress.ip_network("127.0.0.0/8"),)
        self.ctx.rate = host.RateLimiter(1, 3600)
        self.rpc.return_value = {"state": "ready"}
        first = self.request(HttpMethod.GET, "/bridge/health", headers={
            "X-Forwarded-For": "192.0.2.1,\t2001:0DB8:0000:0000:0000:0000:0000:0001 ",
        })
        second = self.request(HttpMethod.GET, "/bridge/health", headers={
            "X-Forwarded-For": "2001:db8::1",
        })
        self.assertEqual((first.status, second.status), (200, 429))
        self.assertEqual(set(self.ctx.rate._clients), {"2001:db8::1"})

    def test_trusted_peer_without_forwarded_header_uses_peer_identity(self) -> None:
        self.ctx.trusted_proxy_cidrs = (ipaddress.ip_network("127.0.0.0/8"),)
        self.rpc.return_value = {"state": "ready"}
        with patch.object(self.ctx.rate, "allow", return_value=True) as allow:
            self.assertEqual(self.request(HttpMethod.GET, "/bridge/health").status, 200)
            allow.assert_called_once_with("127.0.0.1")

    def test_trusted_proxy_rejects_malformed_chains_before_quota_or_enclave(self) -> None:
        self.ctx.trusted_proxy_cidrs = (ipaddress.ip_network("127.0.0.0/8"),)
        cases = [[("X-Forwarded-For", chain)] for chain in (
            "", " ", "unknown, 198.51.100.1", "198.51.100.1,", ",198.51.100.1",
            "192.0.2.1,,198.51.100.1", "192.0.2.1:1234", "[2001:db8::1]:1234",
            "[2001:db8::1]", "2001:db8::1%eth0", "127.1", "2130706433",
            "192.0.2.1\r\n , 198.51.100.1",
        )]
        cases.append([("X-Forwarded-For", "192.0.2.1"),
                      ("X-Forwarded-For", "198.51.100.1")])
        with patch.object(self.ctx.rate, "allow") as allow:
            for method, path in ((HttpMethod.GET, "/bridge/health"),
                                 (HttpMethod.GET, "/bridge/ready"),
                                 (HttpMethod.POST, "/bridge/sign")):
                for headers in cases:
                    with self.subTest(method=method, path=path, headers=headers):
                        result = self.raw_request(headers, method=method, path=path)
                        self.assertEqual(result.status, 400)
                        self.assertEqual(result.json(), {"error": "bad_forwarded_for"})
                        self.assertEqual(result.headers["Connection"], "close")
            allow.assert_not_called()
        self.rpc.assert_not_called()

    def test_aliases_use_existing_rate_limiter(self) -> None:
        self.rpc.return_value = {"state": "ready"}
        with patch.object(self.ctx.rate, "allow", side_effect=[True, False]) as allow:
            self.assertEqual(self.request(HttpMethod.GET, "/bridge/health").status, 200)
            result = self.request(HttpMethod.GET, "/health")
            self.assertEqual(result.status, 429)
            self.assertEqual(result.json(), {"error": "rate_limited"})
            self.assertEqual(allow.call_args_list, [call("127.0.0.1")] * 2)
        self.assertEqual(self.rpc.call_count, 1)


if __name__ == "__main__":
    unittest.main()
