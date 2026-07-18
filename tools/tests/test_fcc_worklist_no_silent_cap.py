#!/usr/bin/env python3
"""Regression: function-coverage worklist text view must NOT silently cap.

Before 2026-06-27 _fmt_worklist sliced the worklist at [:80] with no trailer,
so a workspace with 284 uncovered functions printed only 80 lines and the
operator/loop driving the gate to green had NO signal that 204 functions were
hidden - the gate (which counts ALL 284) appeared unsatisfiable via its own
worklist. Anti-pattern class C (silent cap). Fix: print up to a generous cap
and, when truncated, emit a LOUD trailer naming the hidden count + --json.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "function-coverage-completeness.py"
_s = importlib.util.spec_from_file_location("function_coverage_completeness", _T)
fcc = importlib.util.module_from_spec(_s)
# python3.14 @dataclass needs the module registered before exec_module.
sys.modules["function_coverage_completeness"] = fcc
_s.loader.exec_module(fcc)


def _mk(n):
    return {
        "workspace_verdict": "fail-functions-untouched-or-hollow",
        "worklist_size": n,
        "worklist": [
            {"file_line": f"src/F.sol:{i}", "function": f"fn{i}",
             "classification": "hollow", "task": "drive a real per-function attack"}
            for i in range(n)
        ],
    }


class WorklistNoSilentCapTest(unittest.TestCase):
    def test_medium_worklist_prints_all_rows(self):
        # 284 (the morpho case) is below the cap -> every row must appear, no trailer.
        txt = fcc._fmt_worklist(_mk(284))
        row_lines = [l for l in txt.splitlines() if l.strip().startswith("- ")]
        self.assertEqual(len(row_lines), 284,
                         "all 284 uncovered fns must be emitted (was capped at 80)")
        self.assertNotIn("TRUNCATED", txt)

    def test_huge_worklist_truncates_LOUDLY(self):
        n = fcc._WORKLIST_TEXT_CAP + 47
        txt = fcc._fmt_worklist(_mk(n))
        row_lines = [l for l in txt.splitlines() if l.strip().startswith("- ")]
        self.assertEqual(len(row_lines), fcc._WORKLIST_TEXT_CAP)
        self.assertIn("TRUNCATED", txt, "truncation must be LOUD, not silent")
        self.assertIn("47 more", txt, "hidden count must be named")
        self.assertIn("--json", txt, "must point at the full machine-readable list")
        self.assertIn(str(n), txt, "must state the gate counts ALL n")

    def test_header_size_matches_true_count(self):
        txt = fcc._fmt_worklist(_mk(284))
        self.assertIn("size=284", txt)


if __name__ == "__main__":
    unittest.main()
