#!/usr/bin/env python3
"""Tests for outcome-ledger-gate.py.

Run:
    python3 -m unittest tools.tests.test_outcome_ledger_gate -v
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Dynamic import (hyphen in filename)
# ---------------------------------------------------------------------------

_TOOLS_DIR = Path(__file__).resolve().parents[1]
_MOD_PATH = _TOOLS_DIR / "outcome-ledger-gate.py"


def _load_module():
    mod_name = "outcome_ledger_gate"
    if mod_name in sys.modules:
        return sys.modules[mod_name]
    spec = importlib.util.spec_from_file_location(mod_name, _MOD_PATH)
    assert spec and spec.loader, f"Cannot find {_MOD_PATH}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod  # register before exec so Optional resolves
    spec.loader.exec_module(mod)
    return mod


_mod = _load_module()

scan_outcomes_file = _mod.scan_outcomes_file
build_gate_report = _mod.build_gate_report
_classify_nrc = _mod._classify_nrc
_is_rejected = _mod._is_rejected
_serialize = _mod._serialize
SCHEMA = _mod.SCHEMA


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _write_outcomes(rows: list[dict], tmp_dir: Path) -> Path:
    """Write a reference/outcomes.jsonl under tmp_dir."""
    ref_dir = tmp_dir / "reference"
    ref_dir.mkdir(parents=True, exist_ok=True)
    p = ref_dir / "outcomes.jsonl"
    with p.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    return p


def _rejected_row(
    row_id: str = "test-001",
    outcome: str = "rejected",
    new_rule_codified=None,
    new_rule_codified_reason: str = "",
    title: str = "Test finding",
) -> dict:
    return {
        "submission_id": row_id,
        "outcome": outcome,
        "outcome_class": "rejected",
        "title": title,
        "new_rule_codified": new_rule_codified,
        "new_rule_codified_reason": new_rule_codified_reason,
    }


def _pending_row(row_id: str = "pending-001") -> dict:
    return {
        "submission_id": row_id,
        "outcome": "pending",
        "outcome_class": "pending",
        "title": "Pending finding",
        "new_rule_codified": None,
    }


# ---------------------------------------------------------------------------
# Unit tests for _classify_nrc
# ---------------------------------------------------------------------------


class TestClassifyNrc(unittest.TestCase):
    def test_none_is_fail(self):
        verdict, note = _classify_nrc(None, "")
        self.assertEqual(verdict, "fail")
        self.assertIn("null/missing", note)

    def test_false_is_fail(self):
        verdict, note = _classify_nrc(False, "")
        self.assertEqual(verdict, "fail")
        self.assertIn("False", note)

    def test_true_is_warn(self):
        verdict, note = _classify_nrc(True, "")
        self.assertEqual(verdict, "warn")
        self.assertIn("legacy bool", note)

    def test_none_string_is_pass(self):
        verdict, note = _classify_nrc("none", "")
        self.assertEqual(verdict, "pass")
        self.assertIn("none", note)

    def test_deferred_with_reason_is_pass(self):
        verdict, note = _classify_nrc("deferred", "R56 needs more evidence")
        self.assertEqual(verdict, "pass")
        self.assertIn("deferred", note)

    def test_deferred_without_reason_is_fail(self):
        verdict, note = _classify_nrc("deferred", "")
        self.assertEqual(verdict, "fail")
        self.assertIn("empty", note)

    def test_rule_id_is_pass(self):
        verdict, note = _classify_nrc("R56-RUBRIC-FIT-PROGRAM-LEVEL", "")
        self.assertEqual(verdict, "pass")
        self.assertIn("R56-RUBRIC-FIT-PROGRAM-LEVEL", note)

    def test_any_nonempty_string_is_pass(self):
        verdict, note = _classify_nrc("R35-DOS-CLASS-REFRAME", "")
        self.assertEqual(verdict, "pass")
        self.assertIn("R35", note)

    def test_empty_string_is_fail(self):
        verdict, note = _classify_nrc("", "")
        self.assertEqual(verdict, "fail")
        self.assertIn("empty string", note)


# ---------------------------------------------------------------------------
# Unit tests for _is_rejected
# ---------------------------------------------------------------------------


class TestIsRejected(unittest.TestCase):
    def test_outcome_rejected(self):
        self.assertTrue(_is_rejected({"outcome": "rejected"}))

    def test_outcome_class_rejected(self):
        self.assertTrue(_is_rejected({"outcome_class": "rejected"}))

    def test_outcome_declined(self):
        self.assertTrue(_is_rejected({"outcome": "declined"}))

    def test_outcome_dupe(self):
        self.assertTrue(_is_rejected({"outcome_class": "dupe"}))

    def test_status_rejected_freeform(self):
        self.assertTrue(_is_rejected({"status": "Rejected (OOS - not in scope)"}))

    def test_pending_not_rejected(self):
        self.assertFalse(_is_rejected({"outcome": "pending"}))

    def test_accepted_not_rejected(self):
        self.assertFalse(_is_rejected({"outcome": "accepted", "outcome_class": "real"}))

    def test_in_review_not_rejected(self):
        self.assertFalse(_is_rejected({"outcome": "in_review", "status": "In Review"}))


# ---------------------------------------------------------------------------
# Integration tests via scan_outcomes_file
# ---------------------------------------------------------------------------


class TestScanOutcomesFile(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_1_clean_all_classified_passes(self):
        """Test 1: all rejections have valid string new_rule_codified -> PASS."""
        rows = [
            _rejected_row("r1", new_rule_codified="none"),
            _rejected_row("r2", new_rule_codified="R56-RUBRIC-FIT-PROGRAM-LEVEL"),
            _rejected_row("r3", new_rule_codified="deferred", new_rule_codified_reason="more evidence needed"),
            _pending_row("p1"),
        ]
        p = _write_outcomes(rows, self.tmp)
        report = scan_outcomes_file(p)
        self.assertEqual(report.rejected_rows, 3)
        self.assertEqual(report.fail_rows, 0)
        self.assertEqual(report.warn_rows, 0)
        self.assertEqual(report.pass_rows, 3)
        self.assertEqual(report.verdict, "pass")

    def test_2_missing_field_on_rejection_fails(self):
        """Test 2: rejected row with new_rule_codified=None -> FAIL."""
        rows = [_rejected_row("r1", new_rule_codified=None)]
        p = _write_outcomes(rows, self.tmp)
        report = scan_outcomes_file(p)
        self.assertEqual(report.fail_rows, 1)
        self.assertEqual(report.verdict, "fail")

    def test_3_none_value_allowed(self):
        """Test 3: 'none' string allowed without reason."""
        rows = [_rejected_row("r1", new_rule_codified="none")]
        p = _write_outcomes(rows, self.tmp)
        report = scan_outcomes_file(p)
        self.assertEqual(report.pass_rows, 1)
        self.assertEqual(report.fail_rows, 0)

    def test_4_deferred_with_reason_allowed(self):
        """Test 4: 'deferred' + reason is allowed."""
        rows = [_rejected_row("r1", new_rule_codified="deferred", new_rule_codified_reason="needs R56 review")]
        p = _write_outcomes(rows, self.tmp)
        report = scan_outcomes_file(p)
        self.assertEqual(report.pass_rows, 1)
        self.assertEqual(report.fail_rows, 0)

    def test_5_rule_id_allowed(self):
        """Test 5: rule-id string is valid."""
        rows = [_rejected_row("r1", new_rule_codified="R35-DOS-CLASS-REFRAME")]
        p = _write_outcomes(rows, self.tmp)
        report = scan_outcomes_file(p)
        self.assertEqual(report.pass_rows, 1)
        self.assertEqual(report.fail_rows, 0)

    def test_6_empty_reason_refused_for_deferred(self):
        """Test 6: 'deferred' without reason fails."""
        rows = [_rejected_row("r1", new_rule_codified="deferred", new_rule_codified_reason="")]
        p = _write_outcomes(rows, self.tmp)
        report = scan_outcomes_file(p)
        self.assertEqual(report.fail_rows, 1)
        self.assertEqual(report.verdict, "fail")

    def test_7_json_schema_validity(self):
        """Test 7: _serialize output is valid JSON and has schema field."""
        rows = [
            _rejected_row("r1", new_rule_codified="none"),
            _rejected_row("r2", new_rule_codified=None),
        ]
        p = _write_outcomes(rows, self.tmp)
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        reports = [scan_outcomes_file(p)]
        gate_report = build_gate_report(reports, now)
        serialized = _serialize(gate_report)
        # Must be JSON-serializable
        as_str = json.dumps(serialized)
        loaded = json.loads(as_str)
        self.assertEqual(loaded["schema"], SCHEMA)
        self.assertIn("total_rejected", loaded)
        self.assertIn("overall_verdict", loaded)
        self.assertIn("operator_checklist", loaded)
        self.assertIn("workspace_reports", loaded)
        # Structural checks
        self.assertIsInstance(loaded["total_rejected"], int)
        self.assertIsInstance(loaded["fail_rate"], float)
        self.assertIsInstance(loaded["workspace_reports"], list)
        self.assertIsInstance(loaded["operator_checklist"], list)

    def test_8_legacy_bool_true_is_warn(self):
        """Test 8: new_rule_codified=True (bool) is a WARN, not fail."""
        rows = [_rejected_row("r1", new_rule_codified=True)]
        p = _write_outcomes(rows, self.tmp)
        report = scan_outcomes_file(p)
        self.assertEqual(report.warn_rows, 1)
        self.assertEqual(report.fail_rows, 0)
        self.assertEqual(report.verdict, "warn")  # warn not fail

    def test_9_pending_rows_skipped(self):
        """Test 9: pending/accepted rows are not flagged."""
        rows = [
            _pending_row("p1"),
            {"submission_id": "a1", "outcome": "accepted", "outcome_class": "real", "title": "Paid", "new_rule_codified": None},
        ]
        p = _write_outcomes(rows, self.tmp)
        report = scan_outcomes_file(p)
        self.assertEqual(report.rejected_rows, 0)
        self.assertEqual(report.fail_rows, 0)
        self.assertEqual(report.verdict, "pass")


# ---------------------------------------------------------------------------
# Gate report tests
# ---------------------------------------------------------------------------


class TestGateReport(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_overall_fail_when_any_fail(self):
        rows = [_rejected_row("r1", new_rule_codified=None)]
        p = _write_outcomes(rows, self.tmp)
        from datetime import datetime, timezone
        reports = [scan_outcomes_file(p)]
        gate_report = build_gate_report(reports, "2026-05-25T00:00:00Z")
        self.assertEqual(gate_report.overall_verdict, "fail")

    def test_overall_pass_all_classified(self):
        rows = [_rejected_row("r1", new_rule_codified="none")]
        p = _write_outcomes(rows, self.tmp)
        reports = [scan_outcomes_file(p)]
        gate_report = build_gate_report(reports, "2026-05-25T00:00:00Z")
        self.assertEqual(gate_report.overall_verdict, "pass")

    def test_overall_warn_legacy_bool(self):
        rows = [_rejected_row("r1", new_rule_codified=True)]
        p = _write_outcomes(rows, self.tmp)
        reports = [scan_outcomes_file(p)]
        gate_report = build_gate_report(reports, "2026-05-25T00:00:00Z")
        self.assertEqual(gate_report.overall_verdict, "warn")


# ---------------------------------------------------------------------------
# CLI integration test
# ---------------------------------------------------------------------------


class TestCLI(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)

    def tearDown(self):
        self._tmpdir.cleanup()

    def _run_main(self, argv: list[str]) -> int:
        old_argv = sys.argv
        sys.argv = ["outcome-ledger-gate"] + argv
        try:
            rc = _mod.main(argv)
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 0
        finally:
            sys.argv = old_argv
        return rc

    def test_strict_exits_1_on_fail(self):
        rows = [_rejected_row("r1", new_rule_codified=None)]
        p = _write_outcomes(rows, self.tmp)
        rc = self._run_main(["--outcomes", str(p), "--strict"])
        self.assertEqual(rc, 1)

    def test_non_strict_exits_0_on_fail(self):
        rows = [_rejected_row("r1", new_rule_codified=None)]
        p = _write_outcomes(rows, self.tmp)
        rc = self._run_main(["--outcomes", str(p)])
        self.assertEqual(rc, 0)

    def test_clean_exits_0(self):
        rows = [_rejected_row("r1", new_rule_codified="none")]
        p = _write_outcomes(rows, self.tmp)
        rc = self._run_main(["--outcomes", str(p), "--strict"])
        self.assertEqual(rc, 0)

    def test_json_out_creates_file(self):
        rows = [_rejected_row("r1", new_rule_codified="R56-RUBRIC"), _pending_row()]
        p = _write_outcomes(rows, self.tmp)
        out = self.tmp / "gate_report.json"
        self._run_main(["--outcomes", str(p), "--out-json", str(out)])
        self.assertTrue(out.is_file())
        data = json.loads(out.read_text())
        self.assertEqual(data["schema"], SCHEMA)

    def test_workspace_path_works(self):
        rows = [_rejected_row("r1", new_rule_codified="none")]
        _write_outcomes(rows, self.tmp)
        rc = self._run_main(["--workspace", str(self.tmp)])
        self.assertEqual(rc, 0)

    def test_missing_outcomes_file_exits_2(self):
        rc = self._run_main(["--outcomes", "/nonexistent/path/outcomes.jsonl"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
