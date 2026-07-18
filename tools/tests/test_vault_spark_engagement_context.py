"""Tests for vault_spark_engagement_context MCP callable.

Tier-C #1 (PR #658) — verifies the Spark engagement state surface
exposed via vault-mcp-server.py.

v1.1 additions (iter-8 S2 lane): latest_filed_lead, closed_dupes_count,
pending_originality_check.
"""

import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_spark", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = load_module()


def _make_vault(tmp_root: Path) -> object:
    """Return a VaultQuery bound to a minimal vault under tmp_root."""
    vault_dir = tmp_root / "obsidian-vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    return vault_mcp_server.VaultQuery(vault_dir, tmp_root)


def _write_finding(path: Path, *, title: str, status: str,
                   severity: str | None = None) -> None:
    """Write a minimal finding .md file with optional Severity header."""
    path.parent.mkdir(parents=True, exist_ok=True)
    body = [f"# {title}", "", f"Status: **{status}**"]
    if severity:
        body.append(f"Severity: {severity}")
    body.append("")
    body.append("Body content omitted.")
    path.write_text("\n".join(body) + "\n", encoding="utf-8")


class TestVaultSparkEngagementContextLeadParsing(unittest.TestCase):
    """Test 1: callable returns lead with severity=Critical from Severity: header."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-spark-ctx-")
        root = Path(self.tmp.name)
        self.workspace = root / "spark"
        self.workspace.mkdir()
        # Create a paste_ready finding with Severity: Critical header.
        _write_finding(
            self.workspace / "submissions" / "paste_ready" / "spark-coop-exit-CRITICAL.md",
            title="Chain-watcher bypass leads to funds loss",
            status="SUBMITTED 2026-05-06",
            severity="Critical",
        )
        # Create a staging finding — severity parsed from filename suffix.
        _write_finding(
            self.workspace / "submissions" / "staging" / "spark-claim-path-HIGH.md",
            title="Claim path guard gap",
            status="CANDIDATE",
        )
        self.vault = _make_vault(root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_lead_severity_from_header(self):
        result = self.vault.vault_spark_engagement_context(
            workspace_path=str(self.workspace)
        )
        self.assertEqual(result["schema"], vault_mcp_server.SPARK_ENGAGEMENT_CONTEXT_SCHEMA)
        self.assertEqual(result["kind"], "spark_engagement_context")
        # At least the paste_ready finding should appear.
        leads = result["leads"]
        self.assertGreater(len(leads), 0)
        paste_lead = next(
            (l for l in leads if "spark-coop-exit-CRITICAL.md" in l["filename"]), None
        )
        self.assertIsNotNone(paste_lead, "paste_ready CRITICAL finding not found in leads")
        self.assertEqual(paste_lead["severity"], "critical")
        self.assertEqual(paste_lead["lane"], "paste_ready")

    def test_lead_severity_from_filename_suffix(self):
        result = self.vault.vault_spark_engagement_context(
            workspace_path=str(self.workspace)
        )
        leads = result["leads"]
        staging_lead = next(
            (l for l in leads if "spark-claim-path-HIGH.md" in l["filename"]), None
        )
        self.assertIsNotNone(staging_lead, "staging HIGH finding not found in leads")
        self.assertEqual(staging_lead["severity"], "high")
        self.assertEqual(staging_lead["lane"], "staging")


class TestVaultSparkEngagementContextMissingWorkspace(unittest.TestCase):
    """Test 2: missing workspace returns graceful empty payload (not crash)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-spark-ctx-miss-")
        self.vault = _make_vault(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_missing_workspace_returns_empty_envelope(self):
        bogus = Path(self.tmp.name) / "does_not_exist" / "spark"
        result = self.vault.vault_spark_engagement_context(
            workspace_path=str(bogus)
        )
        # Must not crash; must return graceful envelope.
        self.assertEqual(result["error"], "workspace_not_found")
        self.assertEqual(result["leads"], [])
        self.assertIsNone(result["originality_sha_range"])
        self.assertIsNone(result["submissions_index_path"])
        self.assertEqual(result["engagement_status"], {"status": "unknown"})
        # pack_id and pack_hash must still be present.
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)


class TestVaultSparkEngagementContextEmptySubmissions(unittest.TestCase):
    """Test 3: workspace exists but empty submissions dir returns empty leads list."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-spark-ctx-empty-")
        root = Path(self.tmp.name)
        self.workspace = root / "spark"
        (self.workspace / "submissions" / "paste_ready").mkdir(parents=True)
        self.vault = _make_vault(root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_empty_submissions_returns_empty_leads(self):
        result = self.vault.vault_spark_engagement_context(
            workspace_path=str(self.workspace)
        )
        self.assertEqual(result["leads"], [])
        self.assertEqual(result["leads_returned"], 0)
        self.assertIsNone(result["originality_sha_range"])
        self.assertIsNone(result["submissions_index_path"])


class TestVaultSparkEngagementContextPackIdAlwaysPresent(unittest.TestCase):
    """Test 4: context_pack_id and context_pack_hash always present."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-spark-ctx-pack-")
        root = Path(self.tmp.name)
        self.workspace = root / "spark"
        self.workspace.mkdir()
        # Populate originality_sha_range.json and engagement_status.json.
        auditooor_dir = self.workspace / ".auditooor"
        auditooor_dir.mkdir()
        (auditooor_dir / "originality_sha_range.json").write_text(
            json.dumps({"from_sha": "abc123", "to_sha": "def456"}), encoding="utf-8"
        )
        (auditooor_dir / "engagement_status.json").write_text(
            json.dumps({"status": "active", "leads": 2}), encoding="utf-8"
        )
        # SUBMISSIONS.md
        (self.workspace / "submissions").mkdir()
        (self.workspace / "submissions" / "SUBMISSIONS.md").write_text(
            "# Submissions\n\n| ID | Status |\n|---|---|\n| LEAD 1 | SUBMITTED |\n",
            encoding="utf-8",
        )
        self.vault = _make_vault(root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_pack_id_and_hash_always_present(self):
        result = self.vault.vault_spark_engagement_context(
            workspace_path=str(self.workspace)
        )
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)
        self.assertTrue(result["context_pack_id"].startswith(
            vault_mcp_server.SPARK_ENGAGEMENT_CONTEXT_SCHEMA + ":"
        ))
        self.assertEqual(len(result["context_pack_hash"]), 64)

    def test_originality_sha_range_loaded(self):
        result = self.vault.vault_spark_engagement_context(
            workspace_path=str(self.workspace)
        )
        self.assertIsNotNone(result["originality_sha_range"])
        self.assertEqual(result["originality_sha_range"]["from_sha"], "abc123")

    def test_submissions_index_path_populated(self):
        result = self.vault.vault_spark_engagement_context(
            workspace_path=str(self.workspace)
        )
        self.assertIsNotNone(result["submissions_index_path"])
        self.assertTrue(result["submissions_index_path"].endswith("SUBMISSIONS.md"))

    def test_engagement_status_loaded(self):
        result = self.vault.vault_spark_engagement_context(
            workspace_path=str(self.workspace)
        )
        self.assertEqual(result["engagement_status"]["status"], "active")
        self.assertEqual(result["engagement_status"]["leads"], 2)

    def test_pack_hash_stable_across_calls(self):
        """Same inputs must produce identical pack_hash (deterministic)."""
        first = self.vault.vault_spark_engagement_context(
            workspace_path=str(self.workspace)
        )
        second = self.vault.vault_spark_engagement_context(
            workspace_path=str(self.workspace)
        )
        self.assertEqual(first["context_pack_hash"], second["context_pack_hash"])
        self.assertEqual(first["context_pack_id"], second["context_pack_id"])

    def test_call_dispatch_routes_correctly(self):
        """Verify the call() dispatcher routes vault_spark_engagement_context."""
        result = self.vault.call(
            "vault_spark_engagement_context",
            {"workspace_path": str(self.workspace)},
        )
        self.assertIn("context_pack_id", result)
        self.assertNotIn("error", result, f"Unexpected error in dispatch result: {result}")

    def test_tool_schema_registered(self):
        """Verify vault_spark_engagement_context appears in TOOL_SCHEMAS."""
        names = [t["name"] for t in vault_mcp_server.TOOL_SCHEMAS]
        self.assertIn("vault_spark_engagement_context", names)


class TestVaultSparkEngagementContextLatestFiledLead(unittest.TestCase):
    """v1.1 Test: latest_filed_lead returns highest-severity SUBMITTED row from SUBMISSIONS.md."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-spark-lfl-")
        root = Path(self.tmp.name)
        self.workspace = root / "spark"
        (self.workspace / "submissions").mkdir(parents=True)
        # Write a SUBMISSIONS.md with two submitted rows (Critical + High).
        subs_content = (
            "<!-- AUDITOOOR_TRACKER_MANAGED_START -->\n"
            "| Cantina # | Date | Severity | Status | Title |\n"
            "|---:|---|---|---|---|\n"
            "| — | 2026-05-08 | High | Filed (escalated 2026-05-07) | High-severity finding title |\n"
            "| — | 2026-05-06 | Critical | Submitted 2026-05-06 | Critical chain-watcher bypass |\n"
            "| — | 2026-05-10 | Critical | Closed dupe (team aware) | Dupe row should be excluded |\n"
            "<!-- AUDITOOOR_TRACKER_MANAGED_END -->\n"
        )
        (self.workspace / "submissions" / "SUBMISSIONS.md").write_text(
            subs_content, encoding="utf-8"
        )
        self.vault = _make_vault(root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_latest_filed_lead_returns_critical(self):
        """Should pick the Critical row, not the High row."""
        result = self.vault.vault_spark_engagement_context(
            workspace_path=str(self.workspace)
        )
        lead = result.get("latest_filed_lead")
        self.assertIsNotNone(lead, "latest_filed_lead should not be None")
        self.assertEqual(lead["severity"], "critical")
        self.assertIn("chain-watcher", lead["title"].lower())

    def test_latest_filed_lead_excludes_closed_dupes(self):
        """Rows with 'closed dupe' in status should NOT be returned as latest_filed_lead."""
        result = self.vault.vault_spark_engagement_context(
            workspace_path=str(self.workspace)
        )
        lead = result.get("latest_filed_lead")
        self.assertIsNotNone(lead)
        # The dupe row title should not be the result.
        self.assertNotIn("dupe row", lead["title"].lower())

    def test_latest_filed_lead_none_when_no_submissions(self):
        """Returns None when SUBMISSIONS.md has no filed/submitted rows."""
        # Overwrite with only dupe rows.
        (self.workspace / "submissions" / "SUBMISSIONS.md").write_text(
            "| — | 2026-05-10 | Critical | Closed dupe | Some dupe |\n",
            encoding="utf-8",
        )
        result = self.vault.vault_spark_engagement_context(
            workspace_path=str(self.workspace)
        )
        self.assertIsNone(result.get("latest_filed_lead"))

    def test_v1_keys_still_present(self):
        """Back-compat: all v1 keys still present alongside v1.1 additions."""
        result = self.vault.vault_spark_engagement_context(
            workspace_path=str(self.workspace)
        )
        for key in ("leads", "leads_returned", "limit", "originality_sha_range",
                    "submissions_index_path", "engagement_status",
                    "context_pack_id", "context_pack_hash", "schema", "kind"):
            self.assertIn(key, result, f"v1 key '{key}' missing from v1.1 result")
        # v1.1 keys
        for key in ("latest_filed_lead", "closed_dupes_count", "pending_originality_check"):
            self.assertIn(key, result, f"v1.1 key '{key}' missing from result")


class TestVaultSparkEngagementContextClosedDupesCount(unittest.TestCase):
    """v1.1 Test: closed_dupes_count counts .md files in submissions/superseded/."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-spark-dupe-")
        root = Path(self.tmp.name)
        self.workspace = root / "spark"
        superseded = self.workspace / "submissions" / "superseded"
        superseded.mkdir(parents=True)
        # Write 3 .md files + 1 .hash sidecar (should not be counted).
        for i in range(1, 4):
            (superseded / f"spark-dupe-{i}-CRITICAL.md").write_text(
                f"# Dupe {i}\n\nStatus: closed\n", encoding="utf-8"
            )
        (superseded / "spark-dupe-1-CRITICAL.md.hash").write_text(
            "abc123", encoding="utf-8"
        )
        self.vault = _make_vault(root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_closed_dupes_count_correct(self):
        result = self.vault.vault_spark_engagement_context(
            workspace_path=str(self.workspace)
        )
        self.assertEqual(result["closed_dupes_count"], 3,
                         "Expected exactly 3 .md files in superseded/")

    def test_closed_dupes_count_zero_when_empty(self):
        """superseded/ dir is empty → count=0."""
        # Remove all files.
        superseded = self.workspace / "submissions" / "superseded"
        for f in superseded.iterdir():
            f.unlink()
        result = self.vault.vault_spark_engagement_context(
            workspace_path=str(self.workspace)
        )
        self.assertEqual(result["closed_dupes_count"], 0)

    def test_closed_dupes_count_zero_when_no_superseded_dir(self):
        """No superseded/ dir at all → count=0."""
        superseded = self.workspace / "submissions" / "superseded"
        import shutil
        shutil.rmtree(str(superseded))
        result = self.vault.vault_spark_engagement_context(
            workspace_path=str(self.workspace)
        )
        self.assertEqual(result["closed_dupes_count"], 0)


class TestVaultSparkEngagementContextPendingOriginalityCheck(unittest.TestCase):
    """v1.1 Test: pending_originality_check detects escalated leads needing origin-check."""

    _RECENT_MTIME_OFFSET = -3 * 24 * 3600  # 3 days ago → within 7-day window
    _OLD_MTIME_OFFSET = -10 * 24 * 3600    # 10 days ago → outside 7-day window

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-spark-orig-")
        root = Path(self.tmp.name)
        self.workspace = root / "spark"
        self.paste_ready = self.workspace / "submissions" / "paste_ready"
        self.paste_ready.mkdir(parents=True)
        self.vault = _make_vault(root)

    def tearDown(self):
        self.tmp.cleanup()

    def _write_lead(self, filename: str, status: str, mtime_offset: float) -> Path:
        """Write a paste_ready lead file with a given status and mtime."""
        path = self.paste_ready / filename
        _write_finding(path, title="Test lead", status=status, severity="Critical")
        # Set mtime relative to now.
        new_time = time.time() + mtime_offset
        os.utime(str(path), (new_time, new_time))
        return path

    def test_escalated_recent_sets_pending_true(self):
        """ESCALATED + recent file → pending_originality_check=True."""
        self._write_lead(
            "spark-lead-CRITICAL.md",
            "SUBMITTED 2026-05-06 + ESCALATED BY TRIAGER 2026-05-07",
            self._RECENT_MTIME_OFFSET,
        )
        result = self.vault.vault_spark_engagement_context(
            workspace_path=str(self.workspace)
        )
        self.assertTrue(result["pending_originality_check"],
                        "Expected pending_originality_check=True for recent ESCALATED lead")

    def test_escalated_old_file_sets_pending_false(self):
        """ESCALATED but file is older than 7 days → pending_originality_check=False."""
        self._write_lead(
            "spark-old-lead-CRITICAL.md",
            "SUBMITTED 2026-04-20 + ESCALATED BY TRIAGER 2026-04-21",
            self._OLD_MTIME_OFFSET,
        )
        result = self.vault.vault_spark_engagement_context(
            workspace_path=str(self.workspace)
        )
        self.assertFalse(result["pending_originality_check"],
                         "Expected pending_originality_check=False for old ESCALATED lead")

    def test_status_checked_marker_clears_pending(self):
        """ESCALATED + STATUS-CHECKED → pending_originality_check=False."""
        self._write_lead(
            "spark-checked-CRITICAL.md",
            "SUBMITTED 2026-05-06 + ESCALATED BY TRIAGER 2026-05-07 + STATUS-CHECKED 2026-05-08",
            self._RECENT_MTIME_OFFSET,
        )
        result = self.vault.vault_spark_engagement_context(
            workspace_path=str(self.workspace)
        )
        self.assertFalse(result["pending_originality_check"],
                         "STATUS-CHECKED marker should clear pending_originality_check")

    def test_no_escalated_leads_pending_false(self):
        """No ESCALATED leads → pending_originality_check=False."""
        self._write_lead(
            "spark-normal-CRITICAL.md",
            "SUBMITTED 2026-05-06",
            self._RECENT_MTIME_OFFSET,
        )
        result = self.vault.vault_spark_engagement_context(
            workspace_path=str(self.workspace)
        )
        self.assertFalse(result["pending_originality_check"])

    def test_schema_is_v1_1(self):
        """Schema constant must reflect v1.1 bump."""
        result = self.vault.vault_spark_engagement_context(
            workspace_path=str(self.workspace)
        )
        self.assertIn("v1.1", result["schema"],
                      f"Expected v1.1 in schema, got {result['schema']!r}")


if __name__ == "__main__":
    unittest.main()
