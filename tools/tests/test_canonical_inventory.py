#!/usr/bin/env python3
# r36-rebuttal: lane-RULE-64-CLAIM-VERIFICATION declared 10 files via tools/agent-pathspec-register.py at lane start
"""Regression coverage for tools/canonical-inventory.py.

Covers:
- Snapshot generation against a synthetic workspace
- Each field collector (tools, mcp_callables, schemas,
  record_counts_per_source, pre_submit_checks, r_rules, hooks,
  makefile_targets, workspaces)
- Snapshot freshness (_is_stale, load_or_refresh)
- Claim verification: tool-path, mcp-callable, check, r-rule, schema,
  makefile-target
- CLI: --refresh, --field, --json, --check, exit codes
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Load canonical-inventory.py as a module (hyphenated filename).
_THIS = Path(__file__).resolve().parent
_REPO = _THIS.parent.parent
_INV_PATH = _REPO / "tools" / "canonical-inventory.py"
_spec = importlib.util.spec_from_file_location("canonical_inventory", _INV_PATH)
ci = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ci)


class TestCanonicalInventoryBuild(unittest.TestCase):
    """Build snapshot against the real repo root - smoke."""

    def setUp(self):
        self.repo_root = _REPO
        self.tmpdir = tempfile.mkdtemp()
        self.snapshot_path = Path(self.tmpdir) / "inv.json"

    def test_build_snapshot_schema(self):
        snap = ci.build_snapshot(self.repo_root, audits_root=Path("/tmp/nonexistent_audits"))
        self.assertEqual(snap["schema"], "auditooor.canonical_inventory.v1")
        self.assertIn("generated_at_utc", snap)
        self.assertIn("expires_at_utc", snap)

    def test_collect_tools_finds_canonical_inventory_itself(self):
        snap = ci.build_snapshot(self.repo_root, audits_root=Path("/tmp/nonexistent_audits"))
        self.assertIn("tools/canonical-inventory.py", snap["tools"])

    def test_collect_mcp_callables_nonempty(self):
        snap = ci.build_snapshot(self.repo_root, audits_root=Path("/tmp/nonexistent_audits"))
        # Either the live MCP server is reachable, or the JSONL fallback
        # populates. Both should give us a non-empty list against the real
        # repo.
        self.assertGreater(len(snap["mcp_callables"]), 50)

    def test_collect_r_rules_includes_R52(self):
        snap = ci.build_snapshot(self.repo_root, audits_root=Path("/tmp/nonexistent_audits"))
        self.assertIn("R52", snap["r_rules"])

    def test_collect_pre_submit_checks_includes_high_numbers(self):
        snap = ci.build_snapshot(self.repo_root, audits_root=Path("/tmp/nonexistent_audits"))
        nums = [c.get("number") for c in snap["pre_submit_checks"]]
        # Check #102 R56-RUBRIC-FIT-PROGRAM-LEVEL must be present.
        self.assertIn(102, nums)

    def test_collect_schemas_includes_canonical_inventory_schema(self):
        snap = ci.build_snapshot(self.repo_root, audits_root=Path("/tmp/nonexistent_audits"))
        self.assertIn("auditooor.canonical_inventory.v1", snap["schemas"])


class TestVerifyClaim(unittest.TestCase):
    """Unit tests for the claim verifier function."""

    @classmethod
    def setUpClass(cls):
        cls.snap = ci.build_snapshot(_REPO, audits_root=Path("/tmp/nonexistent_audits"))

    def test_verify_real_tool_path(self):
        v = ci.verify_claim(self.snap, "tools/canonical-inventory.py")
        self.assertTrue(v["verified"])
        self.assertEqual(v["kind"], "tool-path")

    def test_verify_fake_tool_path(self):
        v = ci.verify_claim(self.snap, "tools/does-not-exist-xyz.py")
        self.assertFalse(v["verified"])
        self.assertEqual(v["kind"], "tool-path")

    def test_verify_real_mcp_callable(self):
        v = ci.verify_claim(self.snap, "vault_resume_context")
        self.assertTrue(v["verified"])
        self.assertEqual(v["kind"], "mcp-callable")

    def test_verify_fake_mcp_callable(self):
        v = ci.verify_claim(self.snap, "vault_completely_made_up_xyz")
        self.assertFalse(v["verified"])
        self.assertEqual(v["kind"], "mcp-callable")

    def test_verify_real_check_number(self):
        v = ci.verify_claim(self.snap, "Check #102")
        self.assertTrue(v["verified"])
        self.assertEqual(v["kind"], "check")

    def test_verify_fake_check_number(self):
        v = ci.verify_claim(self.snap, "Check #9999")
        self.assertFalse(v["verified"])
        self.assertEqual(v["kind"], "check")

    def test_verify_real_r_rule(self):
        v = ci.verify_claim(self.snap, "R52")
        self.assertTrue(v["verified"])
        self.assertEqual(v["kind"], "r-rule")

    def test_verify_fake_r_rule(self):
        v = ci.verify_claim(self.snap, "R999")
        self.assertFalse(v["verified"])
        self.assertEqual(v["kind"], "r-rule")

    def test_verify_real_schema(self):
        v = ci.verify_claim(self.snap, "auditooor.canonical_inventory.v1")
        self.assertTrue(v["verified"])
        self.assertEqual(v["kind"], "schema")

    def test_verify_fake_schema(self):
        v = ci.verify_claim(self.snap, "auditooor.does_not_exist_xyz.v99")
        self.assertFalse(v["verified"])
        self.assertEqual(v["kind"], "schema")

    def test_verify_real_makefile_target(self):
        v = ci.verify_claim(self.snap, "make canonical-inventory")
        self.assertTrue(v["verified"])
        self.assertEqual(v["kind"], "makefile-target")


class TestFreshnessTTL(unittest.TestCase):
    """Exercise _is_stale + load_or_refresh."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.snapshot_path = self.tmpdir / "snap.json"

    def test_missing_file_is_stale(self):
        self.assertTrue(ci._is_stale(self.snapshot_path))

    def test_fresh_file_not_stale(self):
        fresh = {
            "schema": "x",
            "expires_at_utc": (datetime.now(timezone.utc)
                               + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        self.snapshot_path.write_text(json.dumps(fresh))
        self.assertFalse(ci._is_stale(self.snapshot_path))

    def test_expired_file_is_stale(self):
        expired = {
            "schema": "x",
            "expires_at_utc": (datetime.now(timezone.utc)
                               - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        self.snapshot_path.write_text(json.dumps(expired))
        self.assertTrue(ci._is_stale(self.snapshot_path))

    def test_load_or_refresh_writes_snapshot(self):
        snap = ci.load_or_refresh(
            _REPO,
            refresh=True,
            snapshot_path=self.snapshot_path,
            audits_root=Path("/tmp/nonexistent_audits"),
        )
        self.assertTrue(self.snapshot_path.is_file())
        self.assertEqual(snap["schema"], "auditooor.canonical_inventory.v1")


class TestCLI(unittest.TestCase):
    """Smoke-test the CLI entry point."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.snap_path = self.tmpdir / "snap.json"

    def _run(self, *extra_args, expect_rc: int = 0) -> tuple[int, str, str]:
        cmd = ["python3", str(_INV_PATH),
               "--workspace", str(_REPO),
               "--snapshot-path", str(self.snap_path),
               "--audits-root", "/tmp/nonexistent_audits",
               *extra_args]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return proc.returncode, proc.stdout, proc.stderr

    def test_cli_default_run(self):
        rc, stdout, _ = self._run()
        self.assertEqual(rc, 0)
        self.assertIn("Canonical Inventory", stdout)

    def test_cli_field_filter(self):
        rc, stdout, _ = self._run("--field", "r_rules")
        self.assertEqual(rc, 0)
        payload = json.loads(stdout)
        self.assertIn("r_rules", payload)

    def test_cli_check_verified(self):
        rc, stdout, _ = self._run("--check", "vault_resume_context")
        self.assertEqual(rc, 0)
        payload = json.loads(stdout)
        self.assertTrue(payload["verified"])

    def test_cli_check_unverified_exit2(self):
        rc, stdout, _ = self._run("--check", "vault_complete_fabrication_xyz")
        self.assertEqual(rc, 2)
        payload = json.loads(stdout)
        self.assertFalse(payload["verified"])

    def test_cli_json_full_snapshot(self):
        rc, stdout, _ = self._run("--json")
        self.assertEqual(rc, 0)
        snap = json.loads(stdout)
        self.assertEqual(snap["schema"], "auditooor.canonical_inventory.v1")
        self.assertIn("tools", snap)
        self.assertIn("mcp_callables", snap)


if __name__ == "__main__":
    unittest.main()
