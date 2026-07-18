#!/usr/bin/env python3
"""Regression tests for the UNKNOWN-RATIO guard + closure reconciliation added to
tools/capability-wiring-integrity-check.py.

Root defect these pin: ~96% of inventory rows fell into the 'unknown' bucket
(no ``outputs`` metadata) and were NEVER counted as problems, so ``orphan=0``
read as a clean pass even under --enforce. Two fixes:

  1. UNKNOWN-RATIO guard - under --enforce, an unknown/total fraction above
     ``--max-unknown-ratio`` is a fail-closed (rc 1) condition, with the ratio
     reported in the JSON report + human output.
  2. Closure reconciliation shrinks the 'unknown' bucket by importing
     capability-orphan-closure-check.py WIRED reachability (exercised on the
     live repo by RealRepoReconciliationTest).

The synthetic tests below build a temp repo whose inventory is entirely
'unknown' rows (no tool_file, no outputs) - closure reconciliation is inert
there (no closure module in the temp tools/ dir), so the ratio guard is tested
in isolation: OVER threshold => rc 1 + ratio reported; UNDER threshold => rc 0.
"""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
TOOL = REPO / "tools" / "capability-wiring-integrity-check.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("cap_wiring_unknown_ratio", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


def _write_synthetic_repo(tmp: Path, n_unknown: int) -> Path:
    """Create a temp repo with n_unknown 'unknown' capability rows.

    A row is 'unknown' when it has neither an executable tool_file nor an emit
    artifact in ``outputs`` (INVOKED + FEEDS-TO both undeterminable) - exactly
    the shape ~96% of the live inventory has.
    """
    (tmp / "reference").mkdir(parents=True, exist_ok=True)
    (tmp / "tools").mkdir(parents=True, exist_ok=True)
    lines = []
    for i in range(n_unknown):
        lines.append(
            json.dumps(
                {
                    "id": f"unk-{i}",
                    "name": f"unknown cap {i}",
                    "category": "python-tool",
                    "status": "LANDED",
                    # no file_paths, no outputs -> verdict 'unknown'
                }
            )
        )
    (tmp / "reference" / "capability_inventory.jsonl").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    return tmp


class UnknownRatioGuardTest(unittest.TestCase):
    def test_over_threshold_enforce_fails(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _write_synthetic_repo(Path(d), n_unknown=10)
            report, rc = MOD.run(repo, enforce=True, max_unknown_ratio=0.20)
        # All rows are unknown -> ratio 1.0 > 0.20 -> fail-closed.
        self.assertEqual(report["counts"]["unknown"], 10)
        self.assertEqual(report["counts"]["total"], 10)
        self.assertAlmostEqual(report["unknown_ratio"], 1.0)
        self.assertTrue(report["unknown_ratio_exceeded"])
        self.assertEqual(report["verdict"], "fail-wiring-integrity")
        self.assertEqual(rc, 1, "enforce must return nonzero when unknown ratio is exceeded")

    def test_under_threshold_enforce_passes(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _write_synthetic_repo(Path(d), n_unknown=10)
            # A ceiling above the actual ratio (1.0) -> no breach.
            report, rc = MOD.run(repo, enforce=True, max_unknown_ratio=1.0)
        self.assertAlmostEqual(report["unknown_ratio"], 1.0)
        self.assertFalse(report["unknown_ratio_exceeded"])
        self.assertEqual(report["verdict"], "pass-wiring-integrity")
        self.assertEqual(rc, 0, "enforce must return zero when unknown ratio is within the ceiling")

    def test_ratio_reported_in_json(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _write_synthetic_repo(Path(d), n_unknown=4)
            report, _ = MOD.run(repo, enforce=True, max_unknown_ratio=0.20)
        # The ratio + ceiling are load-bearing fields, present in the report.
        self.assertIn("unknown_ratio", report)
        self.assertIn("max_unknown_ratio", report)
        self.assertIn("unknown_ratio_exceeded", report)
        self.assertEqual(report["max_unknown_ratio"], 0.20)

    def test_non_strict_never_fails_on_ratio(self):
        with tempfile.TemporaryDirectory() as d:
            repo = _write_synthetic_repo(Path(d), n_unknown=10)
            report, rc = MOD.run(repo, enforce=False, max_unknown_ratio=0.20)
        # Advisory-first: without --enforce the ratio is never load-bearing.
        self.assertFalse(report["unknown_ratio_exceeded"])
        self.assertEqual(rc, 0)


class RealRepoReconciliationTest(unittest.TestCase):
    """On the live repo, closure reconciliation materially shrinks 'unknown'."""

    def test_closure_reconciliation_shrinks_unknown(self):
        report, rc = MOD.run(REPO, enforce=False)
        c = report["counts"]
        # After importing closure WIRED reachability, the unknown bucket must be
        # far below the pre-fix ~1661 (the whole point of the fix).
        self.assertLess(
            c["unknown"], c["total"] * 0.20,
            f"unknown bucket still huge: {c}",
        )
        # Reconciliation actually rescued rows (the two tools now agree).
        self.assertGreater(report["wired_by_closure"], 0)
        # And the live repo passes under the default ceiling.
        report_e, rc_e = MOD.run(REPO, enforce=True)
        self.assertEqual(rc_e, 0, f"live repo must pass enforce; verdict={report_e['verdict']}")


if __name__ == "__main__":
    unittest.main()
