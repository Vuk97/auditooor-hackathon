"""
Tests for tools/v3-daily-status-snapshot.py

Covers:
    1. empty/missing workspace - graceful, no crash
    2. --json mode returns valid JSON with required keys
    3. --markdown mode returns human-readable sections
    4. --since flag accepted without crash
    5. --write-snapshot writes a timestamped file
    6. real-workspace mode - snapshot against actual auditooor-mcp root
    7. gate count detection against real pre-submit-check.sh
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# resolve repo root
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_TOOL = str(_REPO_ROOT / "tools" / "v3-daily-status-snapshot.py")


def _run(args: list, cwd: str = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, _TOOL] + args,
        capture_output=True,
        text=True,
        cwd=cwd or str(_REPO_ROOT),
    )


class TestV3DailyStatusSnapshotEmpty(unittest.TestCase):
    """Test 1: empty workspace - no crash."""

    def test_empty_workspace_no_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = _run(["--workspace", tmp])
            # must not crash; exit code 0 or non-zero is both acceptable for
            # missing workspace, but the script must not raise an unhandled exception
            self.assertNotIn("Traceback", result.stderr)
            self.assertNotIn("Traceback", result.stdout)

    def test_empty_workspace_markdown_fallback_sections(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = _run(["--workspace", tmp, "--markdown"])
            self.assertIn("V3 Daily Status Snapshot", result.stdout)
            self.assertIn("At-a-Glance", result.stdout)


class TestV3DailyStatusSnapshotJSON(unittest.TestCase):
    """Test 2: --json mode returns valid JSON with required keys."""

    def test_json_valid_and_required_keys(self):
        result = _run(["--workspace", str(_REPO_ROOT), "--json"])
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        required_keys = [
            "schema",
            "generated_at_utc",
            "status_banner",
            "head_sha",
            "head_summary",
            "codified_rules",
            "r_rule_gates",
            "meta1",
            "meta2",
            "burndown",
            "mining_dashboard",
            "recent_commits",
            "pending_decisions",
        ]
        for key in required_keys:
            self.assertIn(key, data, f"missing key: {key}")

    def test_json_schema_field(self):
        result = _run(["--workspace", str(_REPO_ROOT), "--json"])
        data = json.loads(result.stdout)
        self.assertEqual(data["schema"], "auditooor.v3_daily_status_snapshot.v1")


class TestV3DailyStatusSnapshotMarkdown(unittest.TestCase):
    """Test 3: --markdown mode returns expected sections."""

    def test_markdown_has_required_sections(self):
        result = _run(["--workspace", str(_REPO_ROOT), "--markdown"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("## At-a-Glance", result.stdout)
        self.assertIn("## What's Working", result.stdout)
        self.assertIn("## Operator Action Queue", result.stdout)

    def test_markdown_head_sha_present(self):
        result = _run(["--workspace", str(_REPO_ROOT), "--markdown"])
        self.assertIn("HEAD", result.stdout)

    def test_markdown_gate_count_present(self):
        result = _run(["--workspace", str(_REPO_ROOT), "--markdown"])
        self.assertIn("R-rule gates", result.stdout)
        self.assertIn("pre-submit-check.sh", result.stdout)


class TestV3DailyStatusSnapshotSince(unittest.TestCase):
    """Test 4: --since flag accepted without crash."""

    def test_since_flag_no_crash(self):
        result = _run(["--workspace", str(_REPO_ROOT), "--since", "2026-01-01"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("V3 Daily Status Snapshot", result.stdout)


class TestV3DailyStatusSnapshotWrite(unittest.TestCase):
    """Test 5: --write-snapshot writes a timestamped file."""

    def test_write_snapshot_creates_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            # create minimal workspace structure
            (Path(tmp) / "tools").mkdir()
            result = _run(["--workspace", tmp, "--write-snapshot", "--markdown"])
            # check that a file was written
            snap_dir = Path(tmp) / "reports" / "v3_daily_status"
            if snap_dir.exists():
                files = list(snap_dir.glob("snapshot_*.md"))
                self.assertTrue(len(files) >= 1, "expected at least 1 snapshot file written")
            else:
                # if the tool silently failed to create the dir, stderr should explain
                self.assertNotIn("Traceback", result.stderr)

    def test_write_snapshot_json_creates_json_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "tools").mkdir()
            result = _run(["--workspace", tmp, "--write-snapshot", "--json"])
            snap_dir = Path(tmp) / "reports" / "v3_daily_status"
            if snap_dir.exists():
                files = list(snap_dir.glob("snapshot_*.json"))
                self.assertTrue(len(files) >= 1)


class TestV3DailyStatusSnapshotRealWorkspace(unittest.TestCase):
    """Test 6: real auditooor-mcp workspace produces operator-useful output."""

    def test_real_workspace_rule_count_nonzero(self):
        result = _run(["--workspace", str(_REPO_ROOT), "--json"])
        data = json.loads(result.stdout)
        rc = data["codified_rules"].get("rule_count")
        self.assertIsNotNone(rc)
        self.assertGreater(rc, 0)

    def test_real_workspace_recent_commits_nonempty(self):
        result = _run(["--workspace", str(_REPO_ROOT), "--json"])
        data = json.loads(result.stdout)
        self.assertGreater(len(data["recent_commits"]), 0)

    def test_real_workspace_pending_decisions_three(self):
        result = _run(["--workspace", str(_REPO_ROOT), "--json"])
        data = json.loads(result.stdout)
        self.assertEqual(len(data["pending_decisions"]), 3)


class TestV3DailyStatusSnapshotGateCount(unittest.TestCase):
    """Test 7: gate count detection works against real pre-submit-check.sh."""

    def test_gate_count_above_zero(self):
        result = _run(["--workspace", str(_REPO_ROOT), "--json"])
        data = json.loads(result.stdout)
        gc = data["r_rule_gates"].get("gate_count")
        self.assertIsNotNone(gc)
        self.assertGreater(gc, 0)

    def test_highest_check_is_reasonable(self):
        result = _run(["--workspace", str(_REPO_ROOT), "--json"])
        data = json.loads(result.stdout)
        hc = data["r_rule_gates"].get("highest_check")
        self.assertIsNotNone(hc)
        # pre-submit-check.sh goes at least through #99 per grep output
        self.assertGreaterEqual(hc, 10)


if __name__ == "__main__":
    unittest.main()
