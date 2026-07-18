"""Regression: the hunt-run-health verdict must be keyed on RECORD-LEVEL
reasoned-success (success_fraction), NOT on unit-engagement.

PROBLEM this guards (operator-observed 2026-07-13, axelar-dlt / nuva):
hunt-run-health emitted the STRONG verdict "healthy" keyed on the per-UNIT
best-record rollup (unit_engaged_fraction ~0.82) while the record-level
success_fraction was ~0.037 - it "looked audited" while almost every record was
an engaged-clean DECLINE, not a finding. Two root causes:
  1. classify_record labeled an explicit clean DECLINE (applies_to_target=no /
     NEGATIVE|refuted verdict) that happened to carry a real function_anchor.file
     as "success" - inflating units_success so u_find crossed the healthy floor.
  2. verdict_for keyed "healthy" on the per-unit u_find with NO record-level
     reasoned-success cross-check, so unit-engagement alone bought the badge.

FIX under test:
  - a clean decline is ALWAYS engaged-clean, NEVER success (regardless of anchor);
  - genuinely-reasoned NEGATIVE records whose anchor lives in file_line / a string
    function_anchor are engaged, not "empty";
  - "healthy" (the strong claim) requires the record-level success_fraction to
    clear REASONED_SUCCESS_FRACTION; unit-engagement alone yields at most
    "healthy-clean" (which still certifies a genuinely-engaged clean audit).
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "hunt-run-health-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("_hrh_reasoned", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


HRH = _load()


class TestDeclineNeverSuccess(unittest.TestCase):
    def test_decline_with_real_function_anchor_is_engaged_not_success(self):
        # The axelar-dlt shape: applies_to_target=no INSIDE result + a real
        # function_anchor.file. Must be engaged-clean, never success.
        rec = {
            "status": "ok",
            "function_anchor": {"file": "x/vote/keeper/poll.go", "line": 250},
            "result": json.dumps({"applies_to_target": "no",
                                  "file_line": "x/vote/keeper/poll.go:L250"}),
        }
        self.assertEqual(HRH.classify_record(rec)[0], "engaged")

    def test_native_negative_with_file_line_is_engaged_not_empty(self):
        # The entrypoint-corpus / per-fn terminal-negative shape: NO nested
        # result, anchor lives in file_line, verdict=refuted. Genuinely reasoned
        # -> engaged, NOT the false "empty" that deflated the record fraction.
        rec = {
            "schema": "auditooor.entrypoint_corpus_terminal_negative.v1",
            "verdict": "refuted",
            "applies_to_target": "no",
            "file_line": "src/axelar-core/x/evm/types/types.go:L63",
            "notes": "non-entry-point helper; no permissionless trigger",
        }
        self.assertEqual(HRH.classify_record(rec)[0], "engaged")

    def test_native_negative_with_string_function_anchor_is_engaged(self):
        rec = {
            "schema": "auditooor.hunt_finding_sidecar.v1",
            "function_anchor": "src/axelar-core/x/vote/abci.go:handlePollsAtExpiry:14",
            "verdict": "NEGATIVE",
            "candidate_finding": "EndBlocker panic unreachable",
            "file_line": "src/axelar-core/x/vote/abci.go:29",
        }
        self.assertEqual(HRH.classify_record(rec)[0], "engaged")

    def test_real_finding_still_success(self):
        # A genuine finding (applies_to_target=yes + real anchor) stays success.
        rec = {
            "status": "ok",
            "function_anchor": {"file": "src/Vault.sol", "fn": "withdraw"},
            "result": json.dumps({"applies_to_target": "yes",
                                  "file_line": "src/Vault.sol:L120"}),
        }
        self.assertEqual(HRH.classify_record(rec)[0], "success")


class TestVerdictKeyedOnReasonedSuccess(unittest.TestCase):
    def test_high_unit_engagement_low_reasoned_success_not_healthy(self):
        # THE operator case: per-unit metrics are strong (every unit engaged, and
        # even u_find=1.0) but the RECORD-level success_fraction is near-zero
        # because the surface is drowned in empty/decline records. The OLD code
        # returned "healthy" off u_find; the fix must NOT call this healthy.
        # 30 units, each credited success once, over 1530 total records.
        v = HRH.verdict_for(
            total=1530, success=30, engaged=0,
            distinct_units=30, units_engaged=30, units_success=30,
        )
        self.assertNotEqual(v, "healthy",
                            "unit-engagement alone must not buy the strong healthy badge")

    def test_genuine_high_reasoned_success_is_healthy(self):
        # Real findings across the surface: record-level success_fraction=0.8 and
        # per-unit find-rate high -> the strong healthy verdict.
        v = HRH.verdict_for(
            total=100, success=80, engaged=0,
            distinct_units=30, units_engaged=30, units_success=25,
        )
        self.assertEqual(v, "healthy")

    def test_engaged_clean_audit_still_certifies_as_healthy_clean(self):
        # A genuinely-engaged 0-finding clean audit (all engaged, ~0 success) must
        # NOT be punished to failed-run/degraded - it lands at healthy-clean,
        # which still passes the hunt-trust gate quiet.
        v = HRH.verdict_for(
            total=200, success=0, engaged=200,
            distinct_units=50, units_engaged=50, units_success=0,
        )
        self.assertEqual(v, "healthy-clean")

    def test_record_only_path_unchanged(self):
        # No resolvable units -> record-based path. Strong find-rate stays healthy;
        # near-zero stays failed-run.
        self.assertEqual(HRH.verdict_for(total=100, success=80), "healthy")
        self.assertEqual(HRH.verdict_for(total=300, success=2), "failed-run")


class TestBuildReportDeclineShapeIsHealthyClean(unittest.TestCase):
    """End-to-end: a directory of clean declines with real anchors (the axelar
    shape) must build to verdict=healthy-clean with success~0 - NOT the false
    strong 'healthy' the old rollup produced."""

    def _build(self, records):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            d = tmp / ".auditooor" / "hunt_findings_sidecars"
            d.mkdir(parents=True)
            for i, r in enumerate(records):
                (d / f"r_{i:04d}.json").write_text(json.dumps(r))
            return HRH.build_report(tmp, tmp.name, str(tmp))

    def test_decline_surface_healthy_clean_not_healthy(self):
        recs = []
        for i in range(60):
            recs.append({
                "status": "ok",
                "function_anchor": {"file": f"src/pkg/f{i}.go", "fn": f"fn{i}"},
                "result": json.dumps({"applies_to_target": "no",
                                      "file_line": f"src/pkg/f{i}.go:L{i}"}),
            })
        rep = self._build(recs)
        self.assertEqual(rep["verdict"], "healthy-clean")
        self.assertEqual(rep["success"], 0,
                         "clean declines must not be counted as success")
        self.assertGreaterEqual(rep["engaged_clean"], 60)
        self.assertFalse(rep["needs_re_hunt"])
        # reported-for-context but not load-bearing
        self.assertIn("unit_engaged_fraction", rep)
        self.assertIn("reasoned_success_fraction", rep["thresholds"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
