"""Check that boot runs an EIF only when it matches its git pin, with no KMS anywhere."""

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
USER_DATA = ROOT / "infra/modules/nitro-fleet/user-data-prod.sh"
PIN_FILE = ROOT / "infra/live/eif-release.json"
HEX96 = re.compile(r"^[0-9a-f]{96}$")
KMS_USE = re.compile(r"\baws\s+kms\b|\bkms:|KMS_RELEASE_ALIAS|kms_release")

AWS_STUB = """#!/bin/bash
echo "$*" >> "$AWS_LOG"
[ "$1 $2" = "s3 cp" ] || exit 2
cp "$FIXTURE" "$4"
"""

NITRO_STUB = """#!/bin/bash
echo "$*" >> "$NITRO_LOG"
printf '{"Measurements":{"PCR0":"%s"}}\\n' "$FAKE_PCR0"
"""


@dataclass
class BootRun:
    returncode: int
    output: str
    aws_calls: list[str]
    nitro_calls: list[str]


def fetch_pinned_source() -> str:
    text = USER_DATA.read_text()
    start = text.index("fetch_pinned() {")
    end = text.index("\n}\n", start) + 3
    return text[start:end].replace("$${", "${")


def boot(pin_sha: str, pin_pcr0: str, served: bytes, measured_pcr0: str) -> BootRun:
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        (d / "bin").mkdir()
        for name, body in (("aws", AWS_STUB), ("nitro-cli", NITRO_STUB)):
            (d / "bin" / name).write_text(body)
            (d / "bin" / name).chmod(0o755)
        (d / "served.eif").write_bytes(served)
        script = (
            "set -euo pipefail\n"
            f"BUCKET=test-bucket\nARTIFACT_REGION=us-east-1\nKASKAD_DIR={d}/kaskad\n"
            'mkdir -p "$KASKAD_DIR"\n'
            + fetch_pinned_source()
            + 'fetch_pinned oracle "$PIN_SHA" "$PIN_PCR0"\n'
        )
        env = {
            "PATH": f"{d}/bin:/usr/bin:/bin",
            "AWS_LOG": str(d / "aws.log"),
            "NITRO_LOG": str(d / "nitro.log"),
            "FIXTURE": str(d / "served.eif"),
            "FAKE_PCR0": measured_pcr0,
            "PIN_SHA": pin_sha,
            "PIN_PCR0": pin_pcr0,
        }
        result = subprocess.run(["bash", "-c", script], env=env,
                                capture_output=True, text=True, timeout=10)

        def lines(name: str) -> list[str]:
            path = d / name
            return path.read_text().splitlines() if path.exists() else []

        return BootRun(result.returncode, result.stdout + result.stderr,
                       lines("aws.log"), lines("nitro.log"))


class FetchPinnedTest(unittest.TestCase):
    EIF = b"pinned enclave image"
    SHA = hashlib.sha384(EIF).hexdigest()
    PCR0 = "ab" * 48

    def test_matching_image_boots_from_content_address(self):
        """Matching sha384 + PCR0 passes and fetches eif/<sha384>.eif from the artifact region."""
        run = boot(self.SHA, self.PCR0, self.EIF, self.PCR0)
        self.assertEqual(run.returncode, 0, run.output)
        self.assertIn("oracle EIF matches pin", run.output)
        self.assertEqual(len(run.aws_calls), 1)
        self.assertIn(f"s3://test-bucket/eif/{self.SHA}.eif", run.aws_calls[0])
        self.assertIn("--region us-east-1", run.aws_calls[0])

    def test_swapped_bytes_are_refused_before_measuring(self):
        """Bytes that do not hash to the pin are fatal; nitro-cli is never consulted."""
        run = boot(self.SHA, self.PCR0, b"attacker image", self.PCR0)
        self.assertEqual(run.returncode, 1, run.output)
        self.assertIn("FATAL: oracle sha384", run.output)
        self.assertEqual(run.nitro_calls, [])

    def test_wrong_measurement_is_refused(self):
        """Pinned bytes with a different PCR0 are fatal."""
        run = boot(self.SHA, self.PCR0, self.EIF, "cd" * 48)
        self.assertEqual(run.returncode, 1, run.output)
        self.assertIn("FATAL: oracle PCR0", run.output)

    def test_empty_pin_is_refused_without_fetching(self):
        """An empty or malformed pin is fatal before any S3 call."""
        for sha, pcr0 in (("", ""), (self.SHA, ""), (self.SHA.upper(), self.PCR0)):
            with self.subTest(sha=sha[:8], pcr0=pcr0[:8]):
                run = boot(sha, pcr0, self.EIF, self.PCR0)
                self.assertEqual(run.returncode, 1, run.output)
                self.assertIn("pin malformed", run.output)
                self.assertEqual(run.aws_calls, [])


class NoKmsTest(unittest.TestCase):
    def test_boot_build_and_ci_never_touch_kms(self):
        """No KMS call, action or alias in prod boot, its IAM, the build script or CI."""
        for rel in ("infra/modules/nitro-fleet/user-data-prod.sh",
                    "infra/modules/nitro-fleet/iam.tf",
                    "infra/modules/nitro-fleet/prod.tf",
                    "infra/modules/nitro-fleet/variables.tf",
                    "host/build-eif.sh",
                    ".github/workflows/build-eif.yml"):
            with self.subTest(file=rel):
                self.assertIsNone(KMS_USE.search((ROOT / rel).read_text()))

    def test_nitro_terraform_declares_no_kms(self):
        """No aws_kms_* resource or data source in the nitro module or its roots."""
        dirs = ("infra/modules/nitro-fleet", "infra/live/us-east-1-nitro",
                "infra/live/eu-west-1-nitro", "infra/live/nuntius-edge")
        for tf in (p for d in dirs for p in sorted((ROOT / d).glob("*.tf"))):
            with self.subTest(file=str(tf.relative_to(ROOT))):
                self.assertNotRegex(tf.read_text(), r'"aws_kms_')

    def test_boot_fetches_both_images_by_pin(self):
        """user-data boots each enclave through fetch_pinned with its template pin."""
        text = USER_DATA.read_text()
        self.assertIn('fetch_pinned oracle "${oracle_sha384}" "${oracle_pcr0}"', text)
        self.assertIn('fetch_pinned pontifex "${pontifex_sha384}" "${pontifex_pcr0}"', text)
        self.assertNotIn("latest.eif", text)


class PinFileTest(unittest.TestCase):
    def test_pin_file_is_well_formed_and_read_by_both_regions(self):
        """eif-release.json pins the oracle by 96-hex sha384 + PCR0 and both roots load it."""
        pins = json.loads(PIN_FILE.read_text())
        self.assertRegex(pins["oracle"]["sha384"], HEX96)
        self.assertRegex(pins["oracle"]["pcr0"], HEX96)
        for root in ("us-east-1-nitro", "eu-west-1-nitro"):
            with self.subTest(root=root):
                main = (ROOT / "infra/live" / root / "main.tf").read_text()
                self.assertIn('file("${path.module}/../eif-release.json")', main)
                self.assertIn("oracle_eif         = local.eif_release.oracle", main)


if __name__ == "__main__":
    unittest.main()
