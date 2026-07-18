"""Tests for vault_engagement_status superseded lane (FIX-PASS Gap 3).

Verifies:
  1. ENGAGEMENT_LANE_DIRS includes "superseded" and "held".
  2. _engagement_lane_classify("superseded", ...) returns "superseded".
  3. vault_engagement_status walks a workspace with submissions/superseded/foo.md
     and returns lane_counts with a "superseded" entry.
"""

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


SUPERSEDED_FIXTURE = """\
# Sample superseded finding

- Title: Test finding superseded by upstream dupe
- Internal Name: TEST-SUPER-001
- Severity: Critical
- Status: superseded — closed dupe of #77043
- Target: spark

Body content omitted.
"""


class TestVaultEngagementStatusIncludesSuperseded(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ves-super-")
        self.root = Path(self.tmp.name)
        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir(parents=True)
        self.audits_root = self.root / "audits"
        self.audits_root.mkdir(parents=True)
        self.workspace = self.audits_root / "test-engagement"
        super_dir = self.workspace / "submissions" / "superseded"
        super_dir.mkdir(parents=True)
        (super_dir / "test-finding-CRITICAL.md").write_text(
            SUPERSEDED_FIXTURE, encoding="utf-8"
        )
        # Also seed a paste_ready file to confirm both lanes are surfaced.
        pr_dir = self.workspace / "submissions" / "paste_ready"
        pr_dir.mkdir(parents=True)
        (pr_dir / "live-finding-HIGH.md").write_text(
            "- Title: live\n- Severity: High\n- Status: filed\n",
            encoding="utf-8",
        )
        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_engagement_lane_dirs_constant(self):
        self.assertIn("superseded", vault_mcp_server.ENGAGEMENT_LANE_DIRS)
        self.assertIn("held", vault_mcp_server.ENGAGEMENT_LANE_DIRS)

    def test_classify_superseded(self):
        self.assertEqual(
            vault_mcp_server._engagement_lane_classify("superseded", "foo.md"),
            "superseded",
        )
        self.assertEqual(
            vault_mcp_server._engagement_lane_classify("held", "bar.md"),
            "held",
        )

    def test_engagement_status_lane_counts_includes_superseded(self):
        result = self.vault.vault_engagement_status(
            audits_root=str(self.audits_root),
            engagement_path=str(self.workspace),
        )
        engagements = result.get("engagements", [])
        self.assertEqual(len(engagements), 1)
        lane_counts = engagements[0].get("lane_counts", {})
        self.assertIn(
            "superseded",
            lane_counts,
            f"lane_counts missing 'superseded' entry: {lane_counts}",
        )
        self.assertGreaterEqual(lane_counts["superseded"], 1)
        # paste_ready is also visible — sanity
        self.assertIn("paste_ready", lane_counts)


if __name__ == "__main__":
    unittest.main()
