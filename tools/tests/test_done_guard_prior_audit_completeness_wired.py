#!/usr/bin/env python3
"""test_done_guard_prior_audit_completeness_wired.py

Enforcement-gap R8 (2026-07-03): prior-audit-completeness-check.py (the R47/R53
dedup-gap detector: a known-published audit for an in-scope product NOT on disk in
prior_audits/ is a dedup blind spot) was ORPHANED - nothing invoked it, so a candidate
finding that a missing audit already disclosed could pass. It is now wired into
audit-done-guard.py as a FINAL-boundary advisory sub-check, ADVISORY-FIRST: attaches a
read-only advisory on every DONE-reaching run; a FLAG (product expected but ZERO on
disk) hard-fails ONLY under AUDITOOOR_DONE_PRIOR_AUDIT_STRICT (default OFF).
"""
import unittest
from pathlib import Path

_SRC = (Path(__file__).resolve().parents[1] / "audit-done-guard.py").read_text(
    encoding="utf-8", errors="replace")


class TestPriorAuditCompletenessWired(unittest.TestCase):
    def test_tool_invoked(self):
        self.assertIn("prior-audit-completeness-check.py", _SRC,
                      "audit-done-guard must invoke the prior-audit-completeness check")

    def test_advisory_attached(self):
        self.assertIn("prior_audit_completeness_advisory", _SRC,
                      "a read-only advisory must attach on every DONE-reaching run")

    def test_advisory_first_env_gated(self):
        self.assertIn("AUDITOOOR_DONE_PRIOR_AUDIT_STRICT", _SRC,
                      "the hard-block must be gated behind the named strict env (advisory-first)")
        # the hard-fail must key on the FLAG verdict (product expected, zero on disk)
        self.assertIn("FLAG", _SRC, "must hard-fail on the tool's FLAG (dedup-gap) verdict")

    def test_final_boundary_placement(self):
        i_block = _SRC.find("prior-audit-completeness FLAG (STRICT)")
        i_done = _SRC.rfind('res["done"] = True')
        self.assertGreater(i_block, 0, "the FLAG-fail message must exist")
        self.assertLess(i_block, i_done, "the prior-audit gate must sit at the final DONE boundary")

    def test_fail_open_on_error(self):
        seg = _SRC[_SRC.find("prior_audit_completeness_advisory") - 400:
                   _SRC.find("prior_audit_completeness_advisory") + 1400]
        self.assertIn("except Exception", seg, "the prior-audit sweep must fail-open on error")

    def test_syntax_ok(self):
        import ast
        ast.parse(_SRC)


if __name__ == "__main__":
    unittest.main()
