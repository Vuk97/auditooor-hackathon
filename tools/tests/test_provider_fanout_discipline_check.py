"""tests for tools/provider-fanout-discipline-check.py

Covers:
  - Clean workspace with persisted packets + complete calibration rows -> pass
  - Workspace with provider KEEP lacking local verification -> fail/warn + gap
  - Calibration row missing local_verification_accepted -> flagged
  - Schema field presence
  - Graceful handling of workspace with no provider activity (pass-not-applicable)
  - dispatch_audit.jsonl model field gap detection
  - No crash on missing/empty workspace inputs
"""
from __future__ import annotations

import datetime as dt
import importlib.util
import json
import sys
import unittest
from pathlib import Path
import tempfile
import os


def _load_tool():
    tool_path = Path(__file__).resolve().parent.parent / "provider-fanout-discipline-check.py"
    spec = importlib.util.spec_from_file_location("provider_fanout_discipline_check", str(tool_path))
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {tool_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


tool = _load_tool()


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_json(path: Path, obj) -> None:
    _write(path, json.dumps(obj, indent=2) + "\n")


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


class TestSchemaFields(unittest.TestCase):
    """Schema and constant sanity checks."""

    def test_schema_constant(self):
        self.assertEqual(tool.SCHEMA, "auditooor.provider_fanout_discipline_check.v1")

    def test_approved_artifact_roots_non_empty(self):
        self.assertGreater(len(tool.APPROVED_ARTIFACT_ROOTS), 0)
        self.assertIn("agent_outputs/provider_packets", tool.APPROVED_ARTIFACT_ROOTS)
        self.assertIn(".auditooor/provider_assist", tool.APPROVED_ARTIFACT_ROOTS)
        self.assertIn(".auditooor/provider_fanout", tool.APPROVED_ARTIFACT_ROOTS)

    def test_keep_verdicts_includes_canonical(self):
        self.assertIn("KEEP_FOR_LOCAL_VERIFICATION", tool.KEEP_VERDICTS)

    def test_calibration_required_fields_non_empty(self):
        self.assertIn("provider", tool.CALIBRATION_REQUIRED_FIELDS)
        self.assertIn("task_type", tool.CALIBRATION_REQUIRED_FIELDS)
        self.assertIn("verdict", tool.CALIBRATION_REQUIRED_FIELDS)


class TestPassNotApplicable(unittest.TestCase):
    """Workspace with no provider activity at all - should pass gracefully."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.ws = Path(self.tmpdir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_empty_workspace_does_not_crash(self):
        result = tool.run_check(self.ws)
        self.assertIn("schema", result)
        self.assertEqual(result["schema"], tool.SCHEMA)
        self.assertIn("verdict", result)
        # Empty workspace - no artifacts, no calibration => warn or pass-not-applicable
        # artifact_persistence should be warn (no approved roots)
        self.assertIn(result["verdict_summary"]["artifact_persistence"], ("warn", "pass", "pass-not-applicable"))

    def test_empty_workspace_schema_keys_present(self):
        result = tool.run_check(self.ws)
        for key in ("schema", "generated_at_utc", "workspace", "calibration_log",
                    "verdict", "verdict_summary", "gap_count", "gaps", "sub_results",
                    "lane7_acceptance_bar"):
            self.assertIn(key, result, f"Missing top-level key: {key}")

    def test_empty_workspace_calibration_pass_not_applicable(self):
        fake_cal = self.ws / "cal.jsonl"
        # Don't create the file - empty
        result = tool.run_check(self.ws, calibration_log_path=fake_cal)
        cal_verdict = result["verdict_summary"]["calibration_field_coverage"]
        self.assertIn(cal_verdict, ("pass-not-applicable", "pass"))

    def test_no_provider_activity_keep_check_pass_not_applicable(self):
        result = tool.run_check(self.ws)
        keep_verdict = result["verdict_summary"]["keep_local_verification"]
        self.assertIn(keep_verdict, ("pass-not-applicable", "pass"))


class TestArtifactPersistence(unittest.TestCase):
    """Check (a): artifact persistence."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.ws = Path(self.tmpdir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_provider_packets_dir_found(self):
        approved = self.ws / "agent_outputs" / "provider_packets"
        approved.mkdir(parents=True)
        _write(approved / "dummy.json", '{"advisory_only": true}')
        result = tool.run_check(self.ws)
        self.assertEqual(result["verdict_summary"]["artifact_persistence"], "pass")

    def test_provider_assist_dir_found(self):
        approved = self.ws / ".auditooor" / "provider_assist"
        approved.mkdir(parents=True)
        _write(approved / "dummy.json", '{"advisory_only": true}')
        result = tool.run_check(self.ws)
        self.assertEqual(result["verdict_summary"]["artifact_persistence"], "pass")

    def test_auditooor_provider_fanout_dir_found(self):
        approved = self.ws / ".auditooor" / "provider_fanout"
        _write(approved / "campaign" / "result.md", "provider result")
        result = tool.run_check(self.ws, calibration_log_path=self.ws / "missing_cal.jsonl")
        self.assertEqual(result["verdict_summary"]["artifact_persistence"], "pass")
        self.assertTrue(result["provider_artifacts_present"])
        self.assertIn(
            str(approved.resolve()),
            result["sub_results"]["artifact_persistence"]["found_approved_roots"],
        )

    def test_no_approved_dir_yields_warn_not_crash(self):
        # No approved dir at all
        result = tool.run_check(self.ws)
        self.assertIn(result["verdict_summary"]["artifact_persistence"], ("warn", "pass-not-applicable"))

    def test_found_approved_roots_populated(self):
        approved = self.ws / "agent_outputs" / "provider_packets"
        approved.mkdir(parents=True)
        result = tool.run_check(self.ws)
        # Resolve to handle macOS /var -> /private/var symlink
        resolved = str(approved.resolve())
        self.assertIn(
            resolved,
            result["sub_results"]["artifact_persistence"]["found_approved_roots"]
        )


class TestCalibrationFieldCoverage(unittest.TestCase):
    """Check (b): calibration log field coverage."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.ws = Path(self.tmpdir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _cal_path(self) -> Path:
        return self.ws / "cal.jsonl"

    def test_complete_rows_still_flag_local_verification_accepted_absent(self):
        """Even 'complete' rows will flag local_verification_accepted as absent
        because the existing schema does not declare it."""
        rows = [
            {
                "ts": "2026-05-19T00:00:00Z",
                "provider": "kimi",
                "task_type": "source-extraction",
                "task_ref": "PR #1",
                "verdict": "TRUE",
                "model": "kimi-for-coding",
                "evidence": "verified via rg",
            }
        ]
        _write_jsonl(self._cal_path(), rows)
        result = tool.run_check(self.ws, calibration_log_path=self._cal_path())
        cal = result["sub_results"]["calibration_field_coverage"]
        # Should fail because local_verification_accepted is absent
        self.assertEqual(cal["verdict"], "fail")
        gaps_text = " ".join(cal["gaps"])
        self.assertIn("local_verification_accepted", gaps_text)

    def test_row_with_local_verification_accepted_no_gap_for_that_field(self):
        """Row that explicitly carries local_verification_accepted avoids that gap."""
        rows = [
            {
                "ts": "2026-05-19T00:00:00Z",
                "provider": "kimi",
                "task_type": "source-extraction",
                "task_ref": "PR #1",
                "verdict": "TRUE",
                "model": "kimi-for-coding",
                "local_verification_accepted": True,
                "evidence": "rg confirmed",
            }
        ]
        _write_jsonl(self._cal_path(), rows)
        result = tool.run_check(self.ws, calibration_log_path=self._cal_path())
        cal = result["sub_results"]["calibration_field_coverage"]
        gaps_text = " ".join(cal["gaps"])
        # local_verification_accepted gap should NOT appear since field is present
        self.assertNotIn("gap:calibration-field-absent:local_verification_accepted", gaps_text)

    def test_missing_model_flagged(self):
        rows = [
            {
                "ts": "2026-05-19T00:00:00Z",
                "provider": "kimi",
                "task_type": "source-extraction",
                "task_ref": "PR #1",
                "verdict": "TRUE",
                # model absent
            }
        ]
        _write_jsonl(self._cal_path(), rows)
        result = tool.run_check(self.ws, calibration_log_path=self._cal_path())
        cal = result["sub_results"]["calibration_field_coverage"]
        gaps_text = " ".join(cal["gaps"])
        self.assertIn("model", gaps_text)

    def test_empty_calibration_pass_not_applicable(self):
        _write(self._cal_path(), "")
        result = tool.run_check(self.ws, calibration_log_path=self._cal_path())
        self.assertIn(
            result["verdict_summary"]["calibration_field_coverage"],
            ("pass-not-applicable", "pass")
        )

    def test_row_count_reported(self):
        rows = [
            {
                "ts": "2026-05-19T00:00:00Z",
                "provider": "kimi",
                "task_type": "source-extraction",
                "task_ref": "PR #1",
                "verdict": "TRUE",
                "model": "kimi-for-coding",
            }
        ] * 5
        _write_jsonl(self._cal_path(), rows)
        result = tool.run_check(self.ws, calibration_log_path=self._cal_path())
        cal = result["sub_results"]["calibration_field_coverage"]
        self.assertEqual(cal["row_count"], 5)


class TestKeepLocalVerification(unittest.TestCase):
    """Check (c): provider KEEP without local verification is flagged."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.ws = Path(self.tmpdir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write_dispatch_audit(self, output_file: Path, status: str = "DISPATCHED") -> Path:
        audit_dir = self.ws / "agent_outputs" / "provider_packets" / "testslice"
        audit_path = audit_dir / "dispatch_audit.jsonl"
        # CAP-012b: use a RECENT ts so KEEP-missing rows are classified
        # newly-emitted (the hard-fail path these tests exercise), not stale.
        recent_ts = (
            dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)
        ).isoformat().replace("+00:00", "Z")
        row = {
            "ts": recent_ts,
            "tool": "dispatch-preflight.py",
            "template_id": "adversarial-kill",
            "prompt_path": str(self.ws / "prompt.md"),
            "prompt_sha256": "abc123",
            "status": status,
            "provider_output_path": str(output_file),
            "dispatch_rc": 0,
            "task_type": "adversarial-kill",
            "workspace": str(self.ws),
            "workspace_source": "cli",
        }
        _write_jsonl(audit_path, [row])
        return audit_path

    def test_keep_without_local_verification_fails(self):
        """Provider output with KEEP_FOR_LOCAL_VERIFICATION and no verification signal."""
        output_file = self.ws / "agent_outputs" / "provider_packets" / "testslice" / "out.minimax.adversarial-kill.out.txt"
        _write(output_file, '{"candidate_id": "c1", "verdict": "KEEP_FOR_LOCAL_VERIFICATION", "reason": "looks risky"}')
        self._write_dispatch_audit(output_file)

        result = tool.run_check(self.ws)
        keep = result["sub_results"]["keep_local_verification"]
        self.assertEqual(keep["verdict"], "fail")
        self.assertGreater(keep["keep_missing_verification_count"], 0)
        gaps_text = " ".join(keep["gaps"])
        self.assertIn("KEEP", gaps_text)
        self.assertIn("local verification", gaps_text.lower())

    def test_keep_with_rg_signal_passes(self):
        """Provider output with KEEP verdict but also has 'rg ' verification signal."""
        output_file = self.ws / "agent_outputs" / "provider_packets" / "testslice" / "out.minimax.adversarial-kill.out.txt"
        content = (
            '{"candidate_id": "c1", "verdict": "KEEP_FOR_LOCAL_VERIFICATION", '
            '"minimum_followup_check": "rg \'transfer_lock\' --type sol", '
            '"local_verification_required": true}'
        )
        _write(output_file, content)
        self._write_dispatch_audit(output_file)

        result = tool.run_check(self.ws)
        keep = result["sub_results"]["keep_local_verification"]
        # minimum_followup_check contains 'rg ' which is a local verification signal
        self.assertIn(keep["verdict"], ("pass", "pass-not-applicable"))
        self.assertEqual(keep["keep_missing_verification_count"], 0)

    def test_no_keep_in_output_passes(self):
        """Provider output with REJECT verdict - no KEEP at all - passes."""
        output_file = self.ws / "agent_outputs" / "provider_packets" / "testslice" / "out.minimax.adversarial-kill.out.txt"
        _write(output_file, '{"candidate_id": "c1", "verdict": "REJECT_FALSE_POSITIVE_RISK", "reason": "no source state"}')
        self._write_dispatch_audit(output_file)

        result = tool.run_check(self.ws)
        keep = result["sub_results"]["keep_local_verification"]
        self.assertNotEqual(keep["verdict"], "fail")
        self.assertEqual(keep["keep_missing_verification_count"], 0)

    def test_non_dispatched_rows_ignored(self):
        """REFUSED rows should not be checked for KEEP."""
        output_file = self.ws / "agent_outputs" / "provider_packets" / "testslice" / "out.minimax.adversarial-kill.out.txt"
        _write(output_file, '{"verdict": "KEEP_FOR_LOCAL_VERIFICATION"}')
        # Write REFUSED status, not DISPATCHED
        self._write_dispatch_audit(output_file, status="REFUSED")

        result = tool.run_check(self.ws)
        keep = result["sub_results"]["keep_local_verification"]
        # REFUSED rows are skipped - no DISPATCHED rows found
        self.assertIn(keep["verdict"], ("pass-not-applicable", "pass"))

    def test_missing_output_file_does_not_crash(self):
        """If the provider_output_path doesn't exist, skip gracefully."""
        output_file = self.ws / "nonexistent_output.txt"
        self._write_dispatch_audit(output_file)

        result = tool.run_check(self.ws)
        self.assertIn("schema", result)
        keep = result["sub_results"]["keep_local_verification"]
        self.assertIn(keep["verdict"], ("pass", "pass-not-applicable"))


class TestDispatchAuditModelField(unittest.TestCase):
    """dispatch_audit.jsonl rows lacking 'model' field should be flagged."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.ws = Path(self.tmpdir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_dispatch_audit_missing_model_flagged(self):
        audit_dir = self.ws / "agent_outputs" / "provider_packets" / "testslice"
        audit_path = audit_dir / "dispatch_audit.jsonl"
        row = {
            "ts": "2026-05-19T00:00:00Z",
            "tool": "dispatch-preflight.py",
            "status": "DISPATCHED",
            "task_type": "adversarial-kill",
            "provider_output_path": str(self.ws / "out.txt"),
            # model field absent
        }
        _write_jsonl(audit_path, [row])
        result = tool.run_check(self.ws)
        dispatch_model = result["sub_results"]["dispatch_audit_model_field"]
        self.assertEqual(dispatch_model["verdict"], "warn")
        self.assertGreater(dispatch_model["rows_missing_model"], 0)
        gaps_text = " ".join(dispatch_model["gaps"])
        self.assertIn("model", gaps_text)

    def test_dispatch_audit_with_model_passes(self):
        audit_dir = self.ws / "agent_outputs" / "provider_packets" / "testslice"
        audit_path = audit_dir / "dispatch_audit.jsonl"
        row = {
            "ts": "2026-05-19T00:00:00Z",
            "status": "DISPATCHED",
            "task_type": "adversarial-kill",
            "model": "MiniMax-M2.7",
            "provider_output_path": str(self.ws / "out.txt"),
        }
        _write_jsonl(audit_path, [row])
        result = tool.run_check(self.ws)
        dispatch_model = result["sub_results"]["dispatch_audit_model_field"]
        self.assertEqual(dispatch_model["verdict"], "pass")
        self.assertEqual(dispatch_model["rows_missing_model"], 0)


class TestProviderArtifactEnforcement(unittest.TestCase):
    """Workspace-scoped enforcement only blocks when provider artifacts exist."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.ws = Path(self.tmpdir)
        self.fake_cal = self.ws / "missing_cal.jsonl"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_empty_workspace_enforce_is_pass_not_applicable(self):
        result = tool.run_check(
            self.ws,
            calibration_log_path=self.fake_cal,
            enforce_if_provider_artifacts=True,
        )
        self.assertEqual(result["verdict"], "pass-not-applicable")
        self.assertFalse(result["provider_artifacts_present"])
        self.assertTrue(result["enforcement"]["requested"])
        self.assertFalse(result["enforcement"]["active"])
        self.assertEqual(result["enforcement"]["blocking_gap_count"], 0)

    def test_enforce_promotes_dispatch_model_warning_to_fail(self):
        campaign = self.ws / ".auditooor" / "provider_fanout" / "campaign"
        output = campaign / "provider_outputs" / "out.txt"
        _write(output, '{"verdict": "REJECT_FALSE_POSITIVE_RISK"}')
        _write_jsonl(campaign / "dispatch_audit.jsonl", [{
            "ts": "2026-05-20T00:00:00Z",
            "status": "DISPATCHED",
            "task_type": "adversarial-kill",
            "provider_output_path": str(output),
        }])

        result = tool.run_check(
            self.ws,
            calibration_log_path=self.fake_cal,
            enforce_if_provider_artifacts=True,
        )
        self.assertTrue(result["provider_artifacts_present"])
        self.assertEqual(result["verdict_summary"]["dispatch_audit_model_field"], "warn")
        self.assertEqual(result["verdict"], "fail")
        self.assertTrue(result["enforcement"]["active"])
        self.assertIn("[dispatch_audit_model_field]", " ".join(result["enforcement"]["blocking_gaps"]))

    def test_enforce_records_keep_missing_verification_as_blocking_gap(self):
        campaign = self.ws / ".auditooor" / "provider_fanout" / "campaign"
        output = campaign / "provider_outputs" / "out.txt"
        _write(output, '{"verdict": "KEEP_FOR_LOCAL_VERIFICATION", "reason": "candidate"}')
        # CAP-012b: recent ts so this KEEP-missing row is newly-emitted (the
        # hard-fail path this test asserts), not stale-legacy (warn).
        recent_ts = (
            dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)
        ).isoformat().replace("+00:00", "Z")
        _write_jsonl(campaign / "dispatch_audit.jsonl", [{
            "ts": recent_ts,
            "status": "DISPATCHED",
            "task_type": "adversarial-kill",
            "model": "MiniMax-M2.7",
            "provider_output_path": str(output),
        }])

        result = tool.run_check(
            self.ws,
            calibration_log_path=self.fake_cal,
            enforce_if_provider_artifacts=True,
        )
        self.assertEqual(result["verdict_summary"]["keep_local_verification"], "fail")
        self.assertGreater(result["enforcement"]["blocking_gap_count"], 0)
        self.assertIn("[keep_local_verification]", " ".join(result["enforcement"]["blocking_gaps"]))


class TestCleanWorkspaceIntegration(unittest.TestCase):
    """Integration: workspace with persisted packets + complete calibration rows."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.ws = Path(self.tmpdir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_complete_workspace_with_local_verification_accepted(self):
        """
        A workspace that has:
        - provider_packets dir (persistence check: pass)
        - calibration rows with ALL Lane-7 fields including local_verification_accepted
        - dispatch audit rows with model field
        - provider output with KEEP + rg signal
        Should produce overall verdict 'pass'.
        """
        # Persistence
        packets_dir = self.ws / "agent_outputs" / "provider_packets" / "slice1"
        packets_dir.mkdir(parents=True)

        # Output file with KEEP + rg verification signal
        output_file = packets_dir / "out.minimax.adversarial-kill.out.txt"
        _write(output_file, (
            '{"candidate_id": "c1", "verdict": "KEEP_FOR_LOCAL_VERIFICATION", '
            '"minimum_followup_check": "rg \'transferFrom\' --type sol", '
            '"local_verification_required": true}'
        ))

        # Dispatch audit with model field
        audit_rows = [{
            "ts": "2026-05-19T00:00:00Z",
            "status": "DISPATCHED",
            "task_type": "adversarial-kill",
            "model": "MiniMax-M2.7",
            "provider_output_path": str(output_file),
            "workspace": str(self.ws),
        }]
        _write_jsonl(packets_dir / "dispatch_audit.jsonl", audit_rows)

        # Calibration rows with ALL fields including local_verification_accepted
        cal_path = self.ws / "cal.jsonl"
        cal_rows = [{
            "ts": "2026-05-19T00:00:00Z",
            "provider": "minimax",
            "task_type": "adversarial-kill",
            "task_ref": "slice1-c1",
            "verdict": "TRUE",
            "model": "MiniMax-M2.7",
            "local_verification_accepted": True,
            "evidence": "rg transferFrom confirmed 3 call sites",
        }]
        _write_jsonl(cal_path, cal_rows)

        result = tool.run_check(self.ws, calibration_log_path=cal_path)

        self.assertEqual(result["verdict_summary"]["artifact_persistence"], "pass")
        self.assertEqual(result["verdict_summary"]["keep_local_verification"], "pass")
        self.assertEqual(result["verdict_summary"]["dispatch_audit_model_field"], "pass")
        # calibration_field_coverage passes since local_verification_accepted is present
        self.assertNotEqual(result["verdict_summary"]["calibration_field_coverage"], "fail")
        # Overall should be pass
        self.assertEqual(result["verdict"], "pass")

    def test_gap_list_itemized_correctly(self):
        """Gaps list should be non-empty and describe the actual gaps."""
        # Calibration with no local_verification_accepted
        cal_path = self.ws / "cal.jsonl"
        _write_jsonl(cal_path, [{
            "ts": "2026-05-19T00:00:00Z",
            "provider": "kimi",
            "task_type": "source-extraction",
            "task_ref": "t1",
            "verdict": "TRUE",
            "model": "kimi-for-coding",
        }])
        result = tool.run_check(self.ws, calibration_log_path=cal_path)
        self.assertGreater(result["gap_count"], 0)
        self.assertGreater(len(result["gaps"]), 0)
        # Each gap should be prefixed with [<check>]
        for gap in result["gaps"]:
            self.assertTrue(gap.startswith("["), f"Gap missing prefix: {gap!r}")


class TestCLIJsonFlag(unittest.TestCase):
    """CLI --json produces valid JSON."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.ws = Path(self.tmpdir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_json_output_is_valid(self):
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = tool.main(["--workspace", str(self.ws), "--json"])
        output = buf.getvalue().strip()
        parsed = json.loads(output)
        self.assertEqual(parsed["schema"], tool.SCHEMA)
        self.assertIn("verdict", parsed)
        self.assertIn("gaps", parsed)
        self.assertIsInstance(rc, int)

    def test_json_enforce_flag_sets_enforcement_fields(self):
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = tool.main([
                "--workspace", str(self.ws),
                "--calibration-log", str(self.ws / "missing_cal.jsonl"),
                "--enforce-if-provider-artifacts",
                "--json",
            ])
        parsed = json.loads(buf.getvalue().strip())
        self.assertEqual(rc, 0)
        self.assertTrue(parsed["enforcement"]["requested"])
        self.assertFalse(parsed["enforcement"]["active"])
        self.assertFalse(parsed["provider_artifacts_present"])


# ---------------------------------------------------------------------------
# CAP-012 (2026-05-24): graceful-degrade when calibration log is dominated
# by legacy-shape rows (lacking BOTH ``model`` AND
# ``local_verification_accepted``). Anchor: the canonical
# `tools/calibration/llm_calibration_log.jsonl` had 559/561 (99.6%) legacy
# rows on 2026-05-24, hard-failing `make audit` despite no actual fanout
# violation. The patch downgrades fail -> warn in this state; operators
# can opt back into hard-fail with --strict-calibration.
# ---------------------------------------------------------------------------


def _write_legacy_only_cal_log(path: Path, n_rows: int = 100) -> None:
    """Write n_rows of legacy-shape calibration rows (no model / no LVA)."""
    rows = []
    for i in range(n_rows):
        rows.append(
            {
                "ts": f"2026-04-22T10:00:{i:02d}Z",
                "provider": "kimi",
                "task_type": "pr-review",
                "task_ref": f"task-{i}",
                "verdict": "TRUE",
                "operator": "claude-supervisor",
                "session_id": "2026-04-25",
                "evidence": "Verified inline.",
            }
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


def _write_modern_only_cal_log(path: Path, n_rows: int = 10) -> None:
    """Write n_rows of fully-populated v2 schema calibration rows."""
    rows = []
    for i in range(n_rows):
        rows.append(
            {
                "ts": f"2026-05-22T10:00:{i:02d}Z",
                "provider": "kimi",
                "model": "kimi-k2",
                "task_type": "pr-review",
                "task_ref": f"task-{i}",
                "verdict": "TRUE",
                "local_verification_accepted": True,
                "operator": "claude-supervisor",
                "evidence": "Verified inline.",
            }
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


class Cap012LegacyCalibrationGracefulDegradeTest(unittest.TestCase):
    """CAP-012: legacy-dominated calibration log must NOT hard-fail audit."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_legacy_only_log_default_mode_emits_warn_not_fail(self) -> None:
        """Calibration log with 100% legacy rows must downgrade to warn."""
        cal_path = self.ws / "cal_legacy.jsonl"
        _write_legacy_only_cal_log(cal_path, n_rows=50)
        rows = tool._load_jsonl(cal_path)
        result = tool._check_calibration_rows(rows, cal_path, strict_calibration=False)
        # CAP-012: legacy-dominated log -> verdict is `warn`, NOT `fail`.
        self.assertEqual(result["verdict"], "warn", f"got {result}")
        self.assertTrue(result["legacy_degraded"])
        self.assertEqual(result["legacy_row_count"], 50)
        self.assertEqual(result["legacy_row_pct"], 100.0)
        self.assertFalse(result["strict_calibration"])
        # The graceful-degrade note should appear in at least one gap row.
        joined_gaps = " ".join(result["gaps"])
        self.assertIn("CAP-012 graceful-degrade", joined_gaps)

    def test_legacy_only_log_strict_mode_fails_closed(self) -> None:
        """--strict-calibration restores the pre-CAP-012 hard-fail."""
        cal_path = self.ws / "cal_legacy.jsonl"
        _write_legacy_only_cal_log(cal_path, n_rows=50)
        rows = tool._load_jsonl(cal_path)
        result = tool._check_calibration_rows(rows, cal_path, strict_calibration=True)
        # Strict mode: verdict is `fail` (the pre-CAP-012 behavior).
        self.assertEqual(result["verdict"], "fail", f"got {result}")
        # legacy_degraded is False because strict_calibration suppresses it.
        self.assertFalse(result["legacy_degraded"])
        self.assertEqual(result["legacy_row_count"], 50)
        self.assertTrue(result["strict_calibration"])

    def test_modern_only_log_passes_clean(self) -> None:
        """A well-populated v2 log must continue to pass (no regression)."""
        cal_path = self.ws / "cal_modern.jsonl"
        _write_modern_only_cal_log(cal_path, n_rows=20)
        rows = tool._load_jsonl(cal_path)
        result = tool._check_calibration_rows(rows, cal_path)
        self.assertEqual(result["verdict"], "pass", f"got {result}")
        self.assertEqual(result["legacy_row_count"], 0)
        self.assertFalse(result["legacy_degraded"])

    def test_mixed_log_treats_legacy_as_warn_not_fail(self) -> None:
        """A log with some modern + lots of legacy rows must NOT hard-fail."""
        cal_path = self.ws / "cal_mixed.jsonl"
        # 5 modern + 45 legacy = 90% legacy (>= threshold).
        # Write modern first, then legacy.
        legacy_path = self.ws / "tmp_legacy.jsonl"
        _write_legacy_only_cal_log(legacy_path, n_rows=45)
        modern_path = self.ws / "tmp_modern.jsonl"
        _write_modern_only_cal_log(modern_path, n_rows=5)
        # Concatenate.
        merged = modern_path.read_text() + legacy_path.read_text()
        cal_path.write_text(merged)
        rows = tool._load_jsonl(cal_path)
        result = tool._check_calibration_rows(rows, cal_path)
        # CAP-012: 90% legacy >= threshold -> downgrade to warn.
        # Verdict is warn (not fail) because legacy rows graceful-degrade
        # AND the non-legacy rows are well-formed.
        self.assertEqual(result["verdict"], "warn", f"got {result}")

    def test_run_check_legacy_log_returns_zero_exit_via_main(self) -> None:
        """End-to-end: legacy-dominated workspace -> rc=0 from main()."""
        # Create workspace with legacy cal log and no provider artifacts.
        cal_path = self.ws / "tools" / "calibration" / "llm_calibration_log.jsonl"
        _write_legacy_only_cal_log(cal_path, n_rows=100)
        # Run via main() -> rc must be 0 (the audit must not block).
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = tool.main([
                "--workspace", str(self.ws),
                "--calibration-log", str(cal_path),
                "--enforce-if-provider-artifacts",
                "--json",
            ])
        # rc=0 means the gate passes (warn is acceptable).
        self.assertEqual(rc, 0, f"expected rc=0 for legacy log, got rc={rc}; stdout={buf.getvalue()[:500]}")
        parsed = json.loads(buf.getvalue().strip())
        # The calibration sub-verdict is warn, not fail.
        self.assertEqual(
            parsed["verdict_summary"]["calibration_field_coverage"], "warn"
        )

    def test_run_check_strict_mode_legacy_log_fails(self) -> None:
        """--strict-calibration restores hard-fail behaviour end-to-end."""
        cal_path = self.ws / "tools" / "calibration" / "llm_calibration_log.jsonl"
        _write_legacy_only_cal_log(cal_path, n_rows=100)
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = tool.main([
                "--workspace", str(self.ws),
                "--calibration-log", str(cal_path),
                "--strict-calibration",
                "--json",
            ])
        # rc != 0 because the calibration sub-check fails in strict mode.
        self.assertNotEqual(rc, 0, f"expected non-zero rc in strict mode, got rc={rc}")
        parsed = json.loads(buf.getvalue().strip())
        self.assertEqual(
            parsed["verdict_summary"]["calibration_field_coverage"], "fail"
        )

    def test_empty_cal_log_still_passes(self) -> None:
        """Empty cal log is pass-not-applicable regardless of strict mode."""
        cal_path = self.ws / "empty.jsonl"
        cal_path.write_text("")
        rows = tool._load_jsonl(cal_path)
        result_default = tool._check_calibration_rows(rows, cal_path)
        self.assertEqual(result_default["verdict"], "pass-not-applicable")
        result_strict = tool._check_calibration_rows(rows, cal_path, strict_calibration=True)
        self.assertEqual(result_strict["verdict"], "pass-not-applicable")

    def test_dispatch_audit_legacy_rows_dont_block_enforcement(self) -> None:
        """CAP-012: partial dispatch_audit model gaps must not hard-block.

        Anchor: hyperbridge dispatch_audit.jsonl had 64/97 (66%) rows
        without `model`. The pre-CAP-012 enforcement code line 592
        `if dispatch_model.get("rows_missing_model", 0) > 0:` upgraded
        the overall verdict to `fail` and made the audit fail rc=1.
        Patch: graceful-degrade unless --strict-calibration AND 100%
        of dispatch rows lack model.
        """
        # Seed a workspace with provider artifacts so enforcement activates.
        provider_dir = self.ws / "agent_outputs" / "provider_packets"
        provider_dir.mkdir(parents=True, exist_ok=True)
        (provider_dir / "packet.txt").write_text("provider output")
        # Seed dispatch_audit with mixed rows: 50% have model, 50% don't.
        da_path = self.ws / "dispatch_audit.jsonl"
        rows = []
        for i in range(10):
            base = {
                "status": "DISPATCHED",
                "ts": f"2026-05-24T10:00:{i:02d}Z",
                "task_type": "pr-review",
            }
            if i % 2 == 0:
                base["model"] = "kimi-k2"
            rows.append(base)
        with da_path.open("w") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
        # Seed a populated cal log to skip calibration-side blocking.
        cal_path = self.ws / "tools" / "calibration" / "llm_calibration_log.jsonl"
        _write_modern_only_cal_log(cal_path, n_rows=5)
        # Default mode: rc=0, overall verdict warn.
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = tool.main([
                "--workspace", str(self.ws),
                "--calibration-log", str(cal_path),
                "--enforce-if-provider-artifacts",
                "--json",
            ])
        self.assertEqual(rc, 0, f"expected rc=0; got rc={rc}; stdout={buf.getvalue()[:500]}")
        parsed = json.loads(buf.getvalue().strip())
        self.assertEqual(parsed["enforcement"]["blocking_gap_count"], 0)

    def test_dispatch_audit_100pct_missing_model_still_blocks(self) -> None:
        """100% of dispatch rows lacking model -> graceful-degrade does NOT fire."""
        provider_dir = self.ws / "agent_outputs" / "provider_packets"
        provider_dir.mkdir(parents=True, exist_ok=True)
        (provider_dir / "packet.txt").write_text("provider output")
        da_path = self.ws / "dispatch_audit.jsonl"
        rows = [
            {"status": "DISPATCHED", "ts": f"2026-05-24T10:00:{i:02d}Z", "task_type": "pr-review"}
            for i in range(5)
        ]
        with da_path.open("w") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
        cal_path = self.ws / "tools" / "calibration" / "llm_calibration_log.jsonl"
        _write_modern_only_cal_log(cal_path, n_rows=5)
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = tool.main([
                "--workspace", str(self.ws),
                "--calibration-log", str(cal_path),
                "--enforce-if-provider-artifacts",
                "--json",
            ])
        # 100% missing model is the hard-fail case (active workflow is
        # not emitting the field at all).
        parsed = json.loads(buf.getvalue().strip())
        # rc != 0 because dispatch_audit_model_field gap-blocks at 100%.
        self.assertEqual(parsed["enforcement"]["blocking_gap_count"], 1, f"got: {parsed}")


# ---------------------------------------------------------------------------
# CAP-012b (2026-07-02): graceful-degrade the keep_local_verification check
# when EVERY KEEP-missing row is a stale legacy mining round (dispatch ts
# older than KEEP_STALE_DAYS). Anchor: the nuva audit's fresh Jun29-Jul02 run
# was blocked by 4 KEEP-missing rows all dated 2026-05-18/05-19 (44+ days old)
# from a superseded `source_mining/2026-05-18_round5_fixed` round. A single
# NEWLY-emitted KEEP-missing row still hard-fails; --strict-calibration
# restores the pre-CAP-012b hard-fail on legacy.
# ---------------------------------------------------------------------------


class Cap012bKeepLegacyStaleTest(unittest.TestCase):
    """CAP-012b: stale-legacy KEEP-missing rows must NOT hard-fail audit."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _seed_keep_missing(self, ts: str, *, subdir: str = "slice") -> Path:
        """Seed a DISPATCHED dispatch_audit row + KEEP output with no verify signal.

        Returns the dispatch_audit path. ``ts`` sets the row timestamp so the
        test controls legacy (old) vs newly-emitted (recent) classification.
        """
        audit_dir = self.ws / "agent_outputs" / "provider_packets" / subdir
        output_file = audit_dir / "out.minimax.adversarial-kill.out.txt"
        _write(
            output_file,
            '{"candidate_id": "c1", "verdict": "KEEP_FOR_LOCAL_VERIFICATION", '
            '"reason": "looks risky"}',
        )
        audit_path = audit_dir / "dispatch_audit.jsonl"
        _write_jsonl(
            audit_path,
            [{
                "ts": ts,
                "status": "DISPATCHED",
                "task_type": "adversarial-kill",
                "provider_output_path": str(output_file),
            }],
        )
        return audit_path

    def _old_ts(self) -> str:
        old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=45)
        return old.isoformat().replace("+00:00", "Z")

    def _recent_ts(self) -> str:
        recent = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=2)
        return recent.isoformat().replace("+00:00", "Z")

    def test_parse_ts_handles_z_suffix(self):
        parsed = tool._parse_ts("2026-05-18T14:22:53.211Z")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.tzinfo, dt.timezone.utc)

    def test_parse_ts_none_on_junk(self):
        self.assertIsNone(tool._parse_ts("not-a-date"))
        self.assertIsNone(tool._parse_ts(None))
        self.assertIsNone(tool._parse_ts(""))

    def test_is_stale_keep_row_old_is_stale(self):
        self.assertTrue(tool._is_stale_keep_row(self._old_ts()))

    def test_is_stale_keep_row_recent_not_stale(self):
        self.assertFalse(tool._is_stale_keep_row(self._recent_ts()))

    def test_is_stale_keep_row_unparseable_treated_as_recent(self):
        # Fail-closed: unknown ts must NOT be treated as legacy.
        self.assertFalse(tool._is_stale_keep_row("junk"))
        self.assertFalse(tool._is_stale_keep_row(None))

    def test_all_legacy_keep_missing_degrades_to_warn(self):
        self._seed_keep_missing(self._old_ts())
        result = tool.run_check(self.ws)
        keep = result["sub_results"]["keep_local_verification"]
        self.assertEqual(keep["verdict"], "warn", f"got {keep}")
        self.assertTrue(keep["keep_legacy_degraded"])
        self.assertEqual(keep["keep_missing_legacy_count"], 1)
        self.assertEqual(keep["keep_missing_recent_count"], 0)
        gaps_text = " ".join(keep["gaps"])
        self.assertIn("legacy-stale", gaps_text)

    def test_recent_keep_missing_still_fails(self):
        self._seed_keep_missing(self._recent_ts())
        result = tool.run_check(self.ws)
        keep = result["sub_results"]["keep_local_verification"]
        self.assertEqual(keep["verdict"], "fail", f"got {keep}")
        self.assertFalse(keep["keep_legacy_degraded"])
        self.assertEqual(keep["keep_missing_recent_count"], 1)

    def test_mixed_legacy_and_recent_fails(self):
        # One legacy + one recent -> the recent row forces a hard-fail.
        self._seed_keep_missing(self._old_ts(), subdir="legacy_slice")
        self._seed_keep_missing(self._recent_ts(), subdir="recent_slice")
        result = tool.run_check(self.ws)
        keep = result["sub_results"]["keep_local_verification"]
        self.assertEqual(keep["verdict"], "fail", f"got {keep}")
        self.assertFalse(keep["keep_legacy_degraded"])
        self.assertEqual(keep["keep_missing_legacy_count"], 1)
        self.assertEqual(keep["keep_missing_recent_count"], 1)

    def test_strict_mode_restores_hard_fail_on_legacy(self):
        self._seed_keep_missing(self._old_ts())
        result = tool.run_check(self.ws, strict_calibration=True)
        keep = result["sub_results"]["keep_local_verification"]
        self.assertEqual(keep["verdict"], "fail", f"got {keep}")
        self.assertFalse(keep["keep_legacy_degraded"])

    def test_legacy_only_keep_not_blocking_under_enforcement(self):
        # Enforcement active + provider artifacts present, but all KEEP-missing
        # rows are legacy -> keep_local_verification must NOT contribute a
        # blocking gap (verdict warn, not fail).
        self._seed_keep_missing(self._old_ts())
        result = tool.run_check(
            self.ws,
            calibration_log_path=self.ws / "missing_cal.jsonl",
            enforce_if_provider_artifacts=True,
        )
        self.assertTrue(result["provider_artifacts_present"])
        self.assertEqual(result["verdict_summary"]["keep_local_verification"], "warn")
        blocking = " ".join(result["enforcement"]["blocking_gaps"])
        self.assertNotIn("[keep_local_verification]", blocking)

    def test_recent_keep_still_blocks_under_enforcement(self):
        self._seed_keep_missing(self._recent_ts())
        result = tool.run_check(
            self.ws,
            calibration_log_path=self.ws / "missing_cal.jsonl",
            enforce_if_provider_artifacts=True,
        )
        self.assertEqual(result["verdict_summary"]["keep_local_verification"], "fail")
        blocking = " ".join(result["enforcement"]["blocking_gaps"])
        self.assertIn("[keep_local_verification]", blocking)


if __name__ == "__main__":
    unittest.main()
