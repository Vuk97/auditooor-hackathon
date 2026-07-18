#!/usr/bin/env python3
"""Tests for tools/audit/fp_verdict_capture.py (Wave-5 lane W5-A2).

Stdlib only. All fixtures are synthetic, written into a tempdir.

Coverage matrix:
  1. Honest empty: no triage file, no --auto-negative -> 0 rows
     written, honest_empty true, exit 0.
  2. Operator triage join: a triage TP that matches a runner hit
     appends one TP row with the runner-reported function.
  3. Path-drift tolerance: triage records the file by basename
     only; it still joins to a hit recorded by absolute path.
  4. Unmatched triage: a triage verdict with no runner hit is
     reported as unmatched and NOT written.
  5. Idempotency: re-running on the same inputs writes 0 new rows
     (the identical-tuple dedupe).
  6. Re-triage flip: an FP -> TP flip is a new tuple and IS
     appended (verdict is part of the dedupe key).
  7. --auto-negative: a test/mock-classified hit not in the triage
     file gets a NEGATIVE row by recorded_by auto-path-class; a
     production-classified hit does not.
  8. --auto-negative does not double-write an operator-triaged hit.
  9. --dry-run computes rows but writes nothing.
 10. End-to-end: the feedback loop computes real precision from a
     ledger this tool produced.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "audit" / "fp_verdict_capture.py"
LOOP = ROOT / "tools" / "audit" / "fp_tp_feedback_loop.py"


def _run(tool, args, expect_rc=None):
    proc = subprocess.run(
        [sys.executable, str(tool), *args],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if expect_rc is not None:
        assert proc.returncode == expect_rc, (
            "rc=%d stdout=%s stderr=%s"
            % (proc.returncode, proc.stdout[-400:], proc.stderr[-400:])
        )
    return proc


def _envelope(hits):
    """Build a minimal universal-fp-runner.v1 envelope."""
    return {
        "schema": "auditooor.universal_fp_runner.v1",
        "workspace": "testws",
        "total_hits": len(hits),
        "hits": hits,
    }


def _hit(fp_id, file, line, function="", pclass="production"):
    return {
        "fp_id": fp_id,
        "file": file,
        "line": line,
        "function": function,
        "snippet": "",
        "confidence": "medium",
        "path_classification": pclass,
    }


def _triage_row(fp_id, file, line, verdict, note="", recorded_by="operator"):
    return json.dumps(
        {
            "schema": "auditooor.fp_triage_verdicts.v1",
            "fp_id": fp_id,
            "file": file,
            "line": line,
            "verdict": verdict,
            "note": note,
            "recorded_by": recorded_by,
        }
    )


class FpVerdictCaptureTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.ws = self.tmp / "ws"
        (self.ws / ".audit_logs").mkdir(parents=True)
        self.runner = self.ws / ".audit_logs" / "universal-fp-runner.output.json"
        self.triage = self.ws / ".audit_logs" / "fp_triage_verdicts.jsonl"
        self.ledger = self.tmp / "fp_verdict_ledger.jsonl"

    def tearDown(self):
        self._tmp.cleanup()

    def _write_envelope(self, hits):
        self.runner.write_text(json.dumps(_envelope(hits)), encoding="utf-8")

    def _write_triage(self, lines):
        self.triage.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _capture(self, extra=None, expect_rc=0):
        args = [
            "--workspace",
            str(self.ws),
            "--ledger",
            str(self.ledger),
        ]
        if extra:
            args.extend(extra)
        proc = _run(TOOL, args, expect_rc=expect_rc)
        return json.loads(proc.stdout)

    def _ledger_rows(self):
        if not self.ledger.is_file():
            return []
        return [
            json.loads(ln)
            for ln in self.ledger.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.startswith("#")
        ]

    # 1 -------------------------------------------------------------
    def test_honest_empty_no_triage(self):
        self._write_envelope([_hit("FP-01", "/abs/Staking.sol", 412)])
        summary = self._capture()
        self.assertTrue(summary["honest_empty"])
        self.assertEqual(summary["rows_written"], 0)
        self.assertEqual(self._ledger_rows(), [])

    # 2 -------------------------------------------------------------
    def test_operator_triage_join(self):
        self._write_envelope(
            [_hit("FP-01", "/abs/Staking.sol", 412, function="withdraw")]
        )
        self._write_triage(
            [_triage_row("FP-01", "contracts/Staking.sol", 412, "TP", "real")]
        )
        summary = self._capture()
        self.assertEqual(summary["rows_written"], 1)
        rows = self._ledger_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], "TP")
        self.assertEqual(rows[0]["fp_id"], "FP-01")
        self.assertEqual(rows[0]["function"], "withdraw")
        self.assertEqual(rows[0]["schema"], "auditooor.fp_verdict_ledger.v1")
        self.assertEqual(rows[0]["recorded_by"], "operator")

    # 3 -------------------------------------------------------------
    def test_path_drift_tolerance(self):
        self._write_envelope(
            [_hit("FP-02", "/some/other/root/x/Vault.sol", 88)]
        )
        # triage uses a bare basename - must still join.
        self._write_triage([_triage_row("FP-02", "Vault.sol", 88, "FP")])
        summary = self._capture()
        self.assertEqual(summary["rows_written"], 1)
        self.assertEqual(summary["unmatched_triage"], [])

    # 4 -------------------------------------------------------------
    def test_unmatched_triage_not_written(self):
        self._write_envelope([_hit("FP-01", "/abs/A.sol", 10)])
        self._write_triage([_triage_row("FP-01", "Nonexistent.sol", 99, "TP")])
        summary = self._capture()
        self.assertEqual(summary["rows_written"], 0)
        self.assertEqual(len(summary["unmatched_triage"]), 1)
        self.assertEqual(self._ledger_rows(), [])

    # 5 -------------------------------------------------------------
    def test_idempotent_rerun(self):
        self._write_envelope([_hit("FP-01", "/abs/A.sol", 10)])
        self._write_triage([_triage_row("FP-01", "A.sol", 10, "TP")])
        self._capture()
        self.assertEqual(len(self._ledger_rows()), 1)
        summary2 = self._capture()
        self.assertEqual(summary2["rows_written"], 0)
        self.assertEqual(len(self._ledger_rows()), 1)

    # 6 -------------------------------------------------------------
    def test_retriage_flip_appended(self):
        self._write_envelope([_hit("FP-01", "/abs/A.sol", 10)])
        self._write_triage([_triage_row("FP-01", "A.sol", 10, "FP")])
        self._capture()
        self.assertEqual(len(self._ledger_rows()), 1)
        # operator flips the verdict.
        self._write_triage([_triage_row("FP-01", "A.sol", 10, "TP")])
        summary2 = self._capture()
        self.assertEqual(summary2["rows_written"], 1)
        rows = self._ledger_rows()
        self.assertEqual(len(rows), 2)
        self.assertEqual({r["verdict"] for r in rows}, {"FP", "TP"})

    # 7 -------------------------------------------------------------
    def test_auto_negative(self):
        self._write_envelope(
            [
                _hit("FP-01", "/abs/test/ATest.sol", 5, pclass="test"),
                _hit("FP-01", "/abs/src/Real.sol", 7, pclass="production"),
            ]
        )
        summary = self._capture(extra=["--auto-negative"])
        rows = self._ledger_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], "NEGATIVE")
        self.assertEqual(rows[0]["recorded_by"], "auto-path-class")
        self.assertIn("test", rows[0]["note"])
        self.assertEqual(summary["auto_negative_rows"], 1)

    # 8 -------------------------------------------------------------
    def test_auto_negative_skips_operator_triaged(self):
        self._write_envelope(
            [_hit("FP-01", "/abs/test/ATest.sol", 5, pclass="test")]
        )
        # operator already triaged this test-file hit as FP.
        self._write_triage([_triage_row("FP-01", "ATest.sol", 5, "FP")])
        summary = self._capture(extra=["--auto-negative"])
        rows = self._ledger_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], "FP")
        self.assertEqual(summary["auto_negative_rows"], 0)

    # 9 -------------------------------------------------------------
    def test_dry_run_writes_nothing(self):
        self._write_envelope([_hit("FP-01", "/abs/A.sol", 10)])
        self._write_triage([_triage_row("FP-01", "A.sol", 10, "TP")])
        summary = self._capture(extra=["--dry-run"])
        self.assertEqual(summary["new_rows"], 1)
        self.assertEqual(summary["rows_written"], 0)
        self.assertEqual(self._ledger_rows(), [])

    # 10 ------------------------------------------------------------
    def test_feedback_loop_computes_real_precision(self):
        """End-to-end: a ledger this tool produces feeds the loop."""
        hits = [
            _hit("FP-01", "/abs/A.sol", 1),
            _hit("FP-01", "/abs/B.sol", 2),
            _hit("FP-01", "/abs/C.sol", 3),
            _hit("FP-01", "/abs/D.sol", 4),
        ]
        self._write_envelope(hits)
        self._write_triage(
            [
                _triage_row("FP-01", "A.sol", 1, "TP"),
                _triage_row("FP-01", "B.sol", 2, "TP"),
                _triage_row("FP-01", "C.sol", 3, "TP"),
                _triage_row("FP-01", "D.sol", 4, "FP"),
            ]
        )
        self._capture()
        self.assertEqual(len(self._ledger_rows()), 4)
        # Now run the feedback loop on the captured ledger.
        proc = _run(
            LOOP,
            [
                "--ledger",
                str(self.ledger),
                "--runner-output",
                str(self.runner),
            ],
            expect_rc=0,
        )
        loop_out = json.loads(proc.stdout)
        # Find FP-01 in the per-shape report.
        shapes = loop_out.get("shapes") or loop_out.get("fp_shapes") or []
        fp01 = None
        for s in shapes:
            if s.get("fp_id") == "FP-01":
                fp01 = s
                break
        self.assertIsNotNone(fp01, "FP-01 missing from loop output")
        # 3 TP / 1 FP => precision 0.75.
        self.assertAlmostEqual(fp01.get("precision"), 0.75, places=4)


if __name__ == "__main__":
    unittest.main()
