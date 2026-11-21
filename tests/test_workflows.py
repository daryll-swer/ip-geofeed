"""Check trust-boundary wiring without a GitHub runner or YAML dependency."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / ".github/workflows"


class WorkflowTests(unittest.TestCase):
    def test_offline_job_never_calls_live_entrypoint_and_pins_checkout(self):
        config = (ROOT / "validate.yml").read_text()
        self.assertIn("\n  validate:\n", config)
        self.assertIn("scripts/validate_geofeed.py", config)
        self.assertIn("-m unittest discover -s tests", config)
        self.assertNotIn("check_authority.py", config)
        self.assertNotIn("issues: write", config)
        self.assertTrue(all(re.search(r"@[a-f0-9]{40}(?: |$)", line)
                            for line in config.splitlines() if "uses:" in line))

    def test_only_trusted_publisher_job_has_write_permissions(self):
        config = (ROOT / "live-audit.yml").read_text()
        live, publisher = config.split("\n  publish-issue:\n", 1)
        self.assertIn("30 6 * * 6", live)
        self.assertIn("cancel-in-progress: true", live)
        self.assertIn('"$GITHUB_EVENT_NAME" != pull_request', live)
        self.assertNotIn("issues: write", live)
        self.assertNotIn("pull_request_target", config)
        self.assertIn("github.ref == 'refs/heads/main'", publisher)
        self.assertIn("github.repository == 'daryll-swer/ip-geofeed'", publisher)
        self.assertIn("needs: live", publisher)
        self.assertIn("cancel-in-progress: false", publisher)
        self.assertIn("scripts/update_issue.py --apply", publisher)
        self.assertEqual(config.count("issues: write"), 1)
        self.assertTrue(all(re.search(r"@[a-f0-9]{40}(?: |$)", line)
                            for line in config.splitlines() if "uses:" in line))
