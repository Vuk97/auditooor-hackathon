#!/usr/bin/env python3
# <!-- r36-rebuttal: lane STEP-INTEGRITY-HUNT-FALSEGREEN registered in commit message -->
"""Strata 2026-06-30: readme-step-integrity check_hunt returned FULL on ANY >=1
per_fn_hacker_questions rows. brain-prime/orient emits those rows, so a workspace
whose step-3 scoped hunt NEVER dispatched (Strata: 10 rows, 0 hunt sidecars) was
certified FULL - a false-green that silently defeats audit-done-guard. Fix: FULL
now requires dispatch evidence (non-empty hunt_findings_sidecars/), else DEGRADED.
"""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "readme-step-integrity.py"


def _load():
    spec = importlib.util.spec_from_file_location("rsi", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["rsi"] = m
    spec.loader.exec_module(m)
    return m


rsi = _load()


def _mk(rows, with_sidecar):
    ws = Path(tempfile.mkdtemp(prefix="rsi_"))
    a = ws / ".auditooor"
    a.mkdir()
    (a / "per_fn_hacker_questions.jsonl").write_text(
        "".join('{"q":%d}\n' % i for i in range(rows)), encoding="utf-8")
    if with_sidecar:
        sc = a / "hunt_findings_sidecars" / "lane1"
        sc.mkdir(parents=True)
        (sc / "verdict.json").write_text("{}", encoding="utf-8")
    return ws


class HuntDispatchEvidenceTest(unittest.TestCase):
    def test_rows_without_sidecar_is_degraded_not_full(self):
        ws = _mk(10, with_sidecar=False)
        status, msg = rsi.check_hunt(str(ws))
        self.assertEqual(status, rsi.DEGRADED)
        self.assertIn("never dispatched", msg)

    def test_rows_with_sidecar_is_full(self):
        ws = _mk(10, with_sidecar=True)
        status, msg = rsi.check_hunt(str(ws))
        self.assertEqual(status, rsi.FULL)

    def test_no_questions_file_is_skipped(self):
        ws = Path(tempfile.mkdtemp(prefix="rsi_"))
        (ws / ".auditooor").mkdir()
        status, _ = rsi.check_hunt(str(ws))
        self.assertEqual(status, rsi.SKIPPED)


if __name__ == "__main__":
    unittest.main(verbosity=2)
