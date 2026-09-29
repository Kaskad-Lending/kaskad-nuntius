"""Check the real build pipeline's exit and publication gates."""

from pathlib import Path
import subprocess
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
}
publish_host_bundle() {
  printf 'HOST_BUNDLE\\n'
  if [ "$FAIL_COMMAND" = host ]; then return 38; fi
}
'''
        return subprocess.run(["bash", "-c", prefix + pipeline],
                              env={"PATH": "/usr/bin:/bin", "FAIL_COMMAND": fail_command},
                              capture_output=True, text=True, timeout=10)

    def test_first_failure_prevents_second_build_and_publication(self):
        result = self.run_pipeline("oracle")
        self.assertEqual(result.returncode, 37, result.stdout + result.stderr)
        self.assertNotIn("BUILD:pontifex", result.stdout)
        self.assertNotIn("HOST_BUNDLE", result.stdout)
        self.assertNotIn("built + signed + published", result.stdout)
        self.assertIn("build log:", result.stdout)

    def test_second_failure_prevents_publication(self):
        result = self.run_pipeline("pontifex")
        self.assertEqual(result.returncode, 37, result.stdout + result.stderr)
        self.assertNotIn("HOST_BUNDLE", result.stdout)
        self.assertNotIn("built + signed + published", result.stdout)

    def test_host_publication_failure_is_not_success(self):
        result = self.run_pipeline("host")
        self.assertEqual(result.returncode, 38, result.stdout + result.stderr)
        self.assertNotIn("built + signed + published", result.stdout)

    def test_success_requires_both_images_and_host_bundle(self):
        result = self.run_pipeline("")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("BUILD:oracle", result.stdout)
        self.assertIn("BUILD:pontifex", result.stdout)
        self.assertIn("HOST_BUNDLE", result.stdout)
        self.assertIn("built + signed + published", result.stdout)


if __name__ == "__main__":
    unittest.main()
