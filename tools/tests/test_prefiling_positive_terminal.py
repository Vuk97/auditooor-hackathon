#!/usr/bin/env python3
"""Regression: a PoC-proven / filed / paste-ready exploit-queue row is TERMINAL
for the prefiling-stress producer (it reached its finding outcome and no longer
needs proving). 2026-07-07: a proof_status=proven/quality=filed row counted as a
non-terminal top lead, keeping top_n>0 and failing prove-top-leads on an
already-filed finding."""
import importlib.util, sys, unittest
from pathlib import Path
_H = Path(__file__).resolve().parent
_s = importlib.util.spec_from_file_location("pft", _H.parent / "prefiling-stress-test.py")
_m = importlib.util.module_from_spec(_s); sys.modules["pft"] = _m; _s.loader.exec_module(_m)


class T(unittest.TestCase):
    def test_proven_is_terminal(self):
        self.assertTrue(_m._is_terminal_queue_row({"proof_status": "proven"}))
    def test_filed_quality_is_terminal(self):
        self.assertTrue(_m._is_terminal_queue_row({"quality_gate_status": "filed"}))
    def test_paste_ready_is_terminal(self):
        self.assertTrue(_m._is_terminal_queue_row({"proof_status": "paste_ready"}))
    def test_killed_still_terminal(self):
        self.assertTrue(_m._is_terminal_queue_row({"proof_status": "closed_negative"}))
    def test_unproved_not_terminal(self):
        self.assertFalse(_m._is_terminal_queue_row({"proof_status": "unproved"}))
    def test_needs_harness_not_terminal(self):
        self.assertFalse(_m._is_terminal_queue_row({"proof_status": "needs_harness"}))


if __name__ == "__main__":
    unittest.main()
