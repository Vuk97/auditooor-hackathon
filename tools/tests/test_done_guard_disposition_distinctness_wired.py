#!/usr/bin/env python3
"""test_done_guard_disposition_distinctness_wired.py

Enforcement-gap audit (2026-07-03): disposition-distinctness-guard.py (the Track B
four-axis anti-false-negative sweep on NEGATIVE dispositions) was ORPHANED - only
reachable via `make disposition-sweep` - so shallow kills (dedup/OOS/known-issue
closed WITHOUT four-axis proof) never surfaced at DONE. It is now wired into
audit-done-guard.py as a FINAL-boundary sub-check, ADVISORY-FIRST: attaches a
read-only advisory on every DONE-reaching run; hard-fails ONLY under
AUDITOOOR_DONE_DISPOSITION_STRICT (default OFF -> no new hard failures).

Pins: the guard is invoked, the advisory key is attached, and the block is gated
behind the strict env (advisory-first, promotable) - not unconditionally enforced.
"""
import unittest
from pathlib import Path

_SRC = (Path(__file__).resolve().parents[1] / "audit-done-guard.py").read_text(
    encoding="utf-8", errors="replace")


class TestDispositionDistinctnessWired(unittest.TestCase):
    def test_guard_tool_invoked(self):
        self.assertIn("disposition-distinctness-guard.py", _SRC,
                      "audit-done-guard must invoke the disposition-distinctness sweep")
        self.assertIn("--sweep", _SRC, "must run the guard in --sweep mode over the ws")

    def test_advisory_attached(self):
        self.assertIn("disposition_distinctness_advisory", _SRC,
                      "a read-only advisory block must attach on every DONE-reaching run")
        self.assertIn("shallow_count", _SRC, "must parse the guard's shallow_count field")

    def test_advisory_first_env_gated(self):
        self.assertIn("AUDITOOOR_DONE_DISPOSITION_STRICT", _SRC,
                      "the hard-block must be gated behind the named strict env (advisory-first)")
        # the block must be a FINAL gate (placed before res['done'] = True), so it only
        # engages when the ws would otherwise be DONE (never bricks an already-failing ws).
        i_block = _SRC.find("disposition-distinctness FAIL (STRICT)")
        i_done = _SRC.rfind('res["done"] = True')
        self.assertGreater(i_block, 0, "strict-fail message must exist")
        self.assertLess(i_block, i_done, "the disposition gate must sit at the final DONE boundary")

    def test_fail_open_on_tool_error(self):
        # a subprocess/lib error must NOT brick done (advisory tool error != a shallow kill)
        seg = _SRC[_SRC.find("disposition_distinctness_advisory") - 400:
                   _SRC.find("disposition_distinctness_advisory") + 1200]
        self.assertIn("except Exception", seg, "the disposition sweep must fail-open on error")

    def test_syntax_ok(self):
        import ast
        ast.parse(_SRC)


if __name__ == "__main__":
    unittest.main()
