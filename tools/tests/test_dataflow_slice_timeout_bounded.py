#!/usr/bin/env python3
# <!-- r36-rebuttal: lane DATAFLOW-SLICE-TIMEOUT registered in commit message -->
"""Strata 2026-06-30: the advisory step-1c dataflow-slice ran UNBOUNDED inside make
audit (closure-unguarded over 122 .sol hit ~10min at 99% CPU), blocking the deep
engines + the whole pipeline. It has a designed function-mode fallback (never blocks),
so it must be wall-clock bounded. Pins: the dataflow-slice recipe wraps the python in
`timeout $AUDITOOOR_DATAFLOW_TIMEOUT` so a pathological closure falls back, not hangs."""
import re, unittest
from pathlib import Path

_MK = Path(__file__).resolve().parent.parent.parent / "Makefile"


class DataflowSliceTimeoutTest(unittest.TestCase):
    def test_recipe_is_timeout_bounded(self):
        txt = _MK.read_text(encoding="utf-8")
        # locate the dataflow-slice recipe block
        m = re.search(r"^dataflow-slice:\n(?:.*\n)*?^\tfi\n", txt, re.M)
        self.assertIsNotNone(m, "dataflow-slice recipe not found")
        block = m.group(0)
        self.assertIn("AUDITOOOR_DATAFLOW_TIMEOUT", block,
                      "dataflow-slice must honor AUDITOOOR_DATAFLOW_TIMEOUT")
        # both router + fallback python calls must be timeout-wrapped
        self.assertEqual(block.count("timeout "), 2,
                         "both dataflow.py and dataflow-slice.py invocations must be timeout-wrapped")
        self.assertIn("never blocks", block, "must keep the advisory fallback note")


if __name__ == "__main__":
    unittest.main(verbosity=2)
