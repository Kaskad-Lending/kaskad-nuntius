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


ROOT = Path(__file__).resolve().parent.parent
BUILD_SH = ROOT / "host/build-eif.sh"
STUBS = 'retry() { shift 2; "$@"; }\naws() { printf "%s\\n" "$*"; }\n'


def shell_func(name: str) -> str:
    source = BUILD_SH.read_text()
    start = source.index(f"{name}() {{")
    return source[start:source.index("\n}\n", start) + 3]


def run_bash(script: str, **env: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", "-c", script], env={"PATH": "/usr/bin:/bin", **env},
                          capture_output=True, text=True, timeout=10)


class HostBundleTest(unittest.TestCase):
    ROOT = ROOT

    def calls(self, mirrors: str = "") -> list[list[str]]:
        script = (STUBS + f"S3=s3://b\nREL_SUFFIX=-mainnet\nMIRRORS=({mirrors})\n"
                  + shell_func("put_boot") + shell_func("publish_host_bundle") + "publish_host_bundle\n")
        result = run_bash(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        return [line.split() for line in result.stdout.splitlines() if line.startswith("s3 cp ")]

    def published(self, bucket: str = "s3://b", mirrors: str = "") -> dict[str, str]:
        prefix = f"{bucket}/host-mainnet/"
        return {dst.removeprefix(prefix): src
                for *_, src, dst in self.calls(mirrors) if dst.startswith(prefix)}

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

    def test_host_bundle_reaches_every_mirror_in_its_region(self):
        """Each host file lands in the release bucket and in the mirror, with --region of the mirror."""
        calls = self.calls("m1@eu-west-1")
        primary = self.published(mirrors="m1@eu-west-1")
        mirror = {dst.removeprefix("s3://m1/host-mainnet/"): (src, " ".join(argv))
                  for *argv, src, dst in calls if dst.startswith("s3://m1/")}
        self.assertEqual(set(mirror), set(primary))
        for name, (src, argv) in mirror.items():
            with self.subTest(name=name):
                self.assertEqual(src, primary[name])
                self.assertIn("--region eu-west-1", argv)


class MirrorTest(unittest.TestCase):
    def parse(self, value: str) -> subprocess.CompletedProcess:
        source = BUILD_SH.read_text()
        start = source.index("MIRRORS=()")
        block = source[start:source.index("\ndone\n", start) + 6]
        return run_bash("set -euo pipefail\n" + block + 'printf "%s\\n" "${MIRRORS[@]}"\n',
                        EIF_MIRRORS=value)

    def test_mirror_list_parses_bucket_at_region(self):
        """EIF_MIRRORS splits on whitespace into bucket@region entries; empty means none."""
        r = self.parse(" kaskad-nitro-eu-eif@eu-west-1  other.bucket@ap-southeast-2 ")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.split(), ["kaskad-nitro-eu-eif@eu-west-1", "other.bucket@ap-southeast-2"])
        self.assertEqual(self.parse("").stdout.split(), [])

    def test_malformed_mirror_is_fatal(self):
        """An entry that is not bucket@region stops the release before any upload."""
        for bad in ("kaskad-nitro-eu-eif", "bb@", "@eu-west-1", "BB@eu-west-1", "bb@eu-west", "*"):
            with self.subTest(bad=bad):
                r = self.parse(bad)
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("is not bucket@region", r.stderr)

    def test_eif_goes_to_the_release_bucket_then_every_mirror(self):
        """put_boot copies one artifact under the same key to the release bucket and each mirror."""
        script = (STUBS + "S3=s3://b\nMIRRORS=(m1@eu-west-1 m2@us-west-2)\n"
                  + shell_func("put_boot") + "put_boot /w/o.eif eif/abc.eif\n")
        self.assertEqual(run_bash(script).stdout.splitlines(), [
            "s3 cp /w/o.eif s3://b/eif/abc.eif",
            "s3 cp --region eu-west-1 /w/o.eif s3://m1/eif/abc.eif",
            "s3 cp --region us-west-2 /w/o.eif s3://m2/eif/abc.eif",
        ])
        self.assertIn('put_boot "$eif" "eif/$sha.eif"', BUILD_SH.read_text())


class MirrorWiringTest(unittest.TestCase):
    @staticmethod
    def default(tf: str, var: str) -> str:
        return re.search(rf'variable "{var}" \{{[^}}]*default\s*=\s*([^\n]+)', tf).group(1).strip()

    def test_release_mirrors_the_bucket_the_eu_fleet_boots_from(self):
        """CI mirrors to the EU root's bucket@region, and the US builder may write that bucket."""
        eu = (ROOT / "infra/live/eu-west-1-nitro/variables.tf").read_text()
        bucket = self.default(eu, "eif_bucket_name").strip('"')
        region = self.default(eu, "aws_region").strip('"')
        workflow = (ROOT / ".github/workflows/build-eif.yml").read_text()
        self.assertIn(f'echo "EIF_MIRRORS={bucket}@{region}"', workflow)
        self.assertIn("EIF_MIRRORS='\"${EIF_MIRRORS}\"'", workflow)
        us = (ROOT / "infra/live/us-east-1-nitro/variables.tf").read_text()
        self.assertIn(f'"{bucket}"', self.default(us, "eif_mirror_buckets"))

    def test_eu_fleet_boots_from_its_own_bucket(self):
        """The EU fleet reads boot artifacts from its own bucket in its own region."""
        main = (ROOT / "infra/live/eu-west-1-nitro/main.tf").read_text()
        self.assertIn("eif_bucket_name    = module.eif_bucket.bucket", main)
        self.assertNotIn("local.us.eif_bucket", main)
        self.assertNotIn("artifact_region", main)


if __name__ == "__main__":
    unittest.main()
