"""Check key-preserving attestation publication and scheduled refresh."""

import configparser
import json
import os
from pathlib import Path
import subprocess
from typing import TypedDict
import unittest
from unittest.mock import patch

import genesis_capture as capture


class AttestationReply(TypedDict):
    attestation: str
    signer: str
    pcr0: str


def attestation(payload: str) -> AttestationReply:
    return {
        "attestation": payload,
        "signer": "0x" + "11" * 20,
        "pcr0": "0x" + "22" * 48,
    }


class GenesisCaptureTest(unittest.TestCase):
    def setUp(self):
        capture._log_lines.clear()
        self.env = patch.dict(os.environ, {"KASKAD_EIF_BUCKET": "test-eif"})
        self.env.start()
        self.addCleanup(self.env.stop)

    @patch.object(capture, "imds_instance_id", return_value="i-test")
    @patch.object(capture, "s3_put")
    @patch.object(capture, "vsock_call")
    def test_repeated_capture_refreshes_doc_without_key_mutation(self, rpc, upload, _iid):
        first, second = attestation("0xaabb"), attestation("0xccdd")
        rpc.side_effect = [{"state": "waiting_registration"}, first,
                           {"state": "waiting_registration"}, second]
        self.assertEqual(capture.main(), 0)
        self.assertEqual(capture.main(), 0)
        documents = [json.loads(c.args[0]) for c in upload.call_args_list
                     if c.args[2] == "genesis/i-test.json"]
        self.assertEqual([d["attestation"] for d in documents], ["0xaabb", "0xccdd"])
        self.assertEqual(documents[0]["signer"], documents[1]["signer"])
        self.assertEqual([c.args[2] for c in rpc.call_args_list],
                         [{"method": "keyex_health"}, {"method": "get_attestation"}] * 2)

    @patch.object(capture.time, "sleep")
    @patch.object(capture, "imds_instance_id", return_value="i-test")
    @patch.object(capture, "s3_put")
    @patch.object(capture, "vsock_call")
    def test_retries_unready_enclave_before_publishing(self, rpc, upload, _iid, sleep):
        rpc.side_effect = [{"state": "fetching"}, {"error": "not ready"},
                           {"state": "waiting_registration"}, attestation("0xaabb")]
        self.assertEqual(capture.main(), 0)
        self.assertEqual(sleep.call_count, 1)
        self.assertEqual(sum(c.args[2] == "genesis/i-test.json"
                             for c in upload.call_args_list), 1)

    @patch.object(capture, "imds_instance_id", return_value="i-test")
    @patch.object(capture, "s3_put", side_effect=subprocess.CalledProcessError(1, "aws"))
    @patch.object(capture, "vsock_call",
                  side_effect=[{"state": "waiting_registration"}, attestation("0xaabb")])
    def test_upload_failure_is_not_success(self, _rpc, _upload, _iid):
        with self.assertRaises(subprocess.CalledProcessError):
            capture.main()

    def test_service_can_run_again_after_completion(self):
        config = configparser.ConfigParser()
        config.read(Path(__file__).parent / "systemd/kaskad-genesis-capture.service")
        service = config["Service"]
        self.assertEqual(service["Type"], "oneshot")
        self.assertFalse(service.getboolean("RemainAfterExit", fallback=False))
        self.assertEqual(service["TimeoutStartSec"], "20min")

    def test_timer_is_recurring_and_enabled_by_bootstrap(self):
        root = Path(__file__).resolve().parent.parent
        config = configparser.ConfigParser()
        config.read(root / "host/systemd/kaskad-genesis-capture.timer")
        self.assertEqual(config["Timer"]["OnUnitInactiveSec"], "10min")
        self.assertEqual(config["Timer"]["Unit"], "kaskad-genesis-capture.service")
        script = (root / "infra/live/us-east-1-nitro/user-data-prod.sh").read_text()
        self.assertIn("systemctl enable --now kaskad-genesis-capture.timer", script)
        self.assertIn("host/systemd/kaskad-genesis-capture.timer", script)


if __name__ == "__main__":
    unittest.main()
