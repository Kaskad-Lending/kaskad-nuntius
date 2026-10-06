"""Check the real build pipeline's exit and publication gates."""

from pathlib import Path
import re
import subprocess
import tempfile
import unittest


class BuildPipelineTest(unittest.TestCase):
    def run_pipeline(self, fail_command: str):
        source = (Path(__file__).parent / "build-eif.sh").read_text()
        pipeline = source[source.index('BUILD_LOG="$(mktemp '):]
        prefix = '''set -euo pipefail
IMAGES=(oracle:Dockerfile.oracle pontifex:Dockerfile.pontifex)
S3=s3://test-only
COMMIT=test-only
aws() { return 0; }
build_one() {
  printf 'BUILD:%s\\n' "$1"
  if [ "$1" = "$FAIL_COMMAND" ]; then return 37; fi
  printf '{"sha384":"%s-sha","pcr0":"%s-pcr0"}\\n' "$1" "$1" > "$WORK/$1.pin.json"
}
publish_host_bundle() {
  printf 'HOST_BUNDLE\\n'
  if [ "$FAIL_COMMAND" = host ]; then return 38; fi
}
'''
        with tempfile.TemporaryDirectory() as work:
            return subprocess.run(["bash", "-c", prefix + pipeline],
                                  env={"PATH": "/usr/bin:/bin", "FAIL_COMMAND": fail_command,
                                       "WORK": work},
                                  capture_output=True, text=True, timeout=10)

    def test_first_failure_prevents_second_build_and_publication(self):
        result = self.run_pipeline("oracle")
        self.assertEqual(result.returncode, 37, result.stdout + result.stderr)
        self.assertNotIn("BUILD:pontifex", result.stdout)
        self.assertNotIn("HOST_BUNDLE", result.stdout)
        self.assertNotIn("built + published", result.stdout)
        self.assertNotIn("pins for", result.stdout)
        self.assertIn("build log:", result.stdout)

    def test_second_failure_prevents_publication(self):
        result = self.run_pipeline("pontifex")
        self.assertEqual(result.returncode, 37, result.stdout + result.stderr)
        self.assertNotIn("HOST_BUNDLE", result.stdout)
        self.assertNotIn("built + published", result.stdout)
        self.assertNotIn("pins for", result.stdout)

    def test_host_publication_failure_is_not_success(self):
        result = self.run_pipeline("host")
        self.assertEqual(result.returncode, 38, result.stdout + result.stderr)
        self.assertNotIn("built + published", result.stdout)
        self.assertNotIn("pins for", result.stdout)

    def test_success_requires_both_images_and_host_bundle(self):
        result = self.run_pipeline("")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("BUILD:oracle", result.stdout)
        self.assertIn("BUILD:pontifex", result.stdout)
        self.assertIn("HOST_BUNDLE", result.stdout)
        self.assertIn("built + published", result.stdout)

    def test_success_prints_a_pin_per_image(self):
        result = self.run_pipeline("")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        tail = result.stdout[result.stdout.index("pins for infra/live/eif-release.json"):]
        self.assertIn('"oracle-sha"', tail)
        self.assertIn('"pontifex-pcr0"', tail)


class HostBundleTest(unittest.TestCase):
    ROOT = Path(__file__).resolve().parent.parent

    def published(self) -> dict[str, str]:
        source = (self.ROOT / "host/build-eif.sh").read_text()
        start = source.index("publish_host_bundle() {")
        func = source[start:source.index("\n}\n", start) + 3]
        script = ('retry() { shift 2; "$@"; }\naws() { printf "%s\\n" "$*"; }\n'
                  "S3=s3://b\nREL_SUFFIX=-mainnet\n" + func + "publish_host_bundle\n")
        out = subprocess.run(["bash", "-c", script], env={"PATH": "/usr/bin:/bin"},
                             capture_output=True, text=True, timeout=10, check=True).stdout
        calls = [line.split() for line in out.splitlines() if line.startswith("s3 cp ")]
        return {dst.removeprefix("s3://b/host-mainnet/"): src for *_, src, dst in calls}

    def test_bundle_ships_the_nitro_pull_api_fork(self):
        """The bundle publishes host/pull_api.py; enclave/pull_api.py stays Igra's."""
        self.assertEqual(self.published()["pull_api.py"], "host/pull_api.py")

    def test_every_file_boot_fetches_is_published(self):
        """Each host script user-data fetches has a source in the bundle."""
        user_data = (self.ROOT / "infra/modules/nitro-fleet/user-data-prod.sh").read_text()
        fetched = set(re.findall(r'host\$\{eif_release_suffix\}/(\w+\.py)"', user_data))
        published = self.published()
        self.assertGreaterEqual(len(fetched), 4)
        for name in fetched:
            with self.subTest(name=name):
                self.assertEqual(published.get(name), f"host/{name}")
                self.assertTrue((self.ROOT / "host" / name).is_file())


if __name__ == "__main__":
    unittest.main()
