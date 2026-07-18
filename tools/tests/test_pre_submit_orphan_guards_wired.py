#!/usr/bin/env python3
"""test_pre_submit_orphan_guards_wired.py

Enforcement-gap audit (2026-07-03): three recently-built paste-ready guards were
ORPHANED (ZERO callers on the submit path), so a drifted PoC / ambiguous-selector
PoC / anomaly-laundered down-tier reached paste-ready unchecked. They are now wired
into tools/pre-submit-check.sh as Checks #138-140, ADVISORY-FIRST (each hard-blocks
only under its own named strict env; default OFF -> byte-compatible submit path).

This pins: (a) each check header is present, (b) each invokes its tool, (c) each is
advisory-first (gated behind a strict env, default WARN not FAIL).
"""
import re
import unittest
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "pre-submit-check.sh"
_TEXT = _SCRIPT.read_text(encoding="utf-8", errors="replace")

_CHECKS = [
    ("138", "poc-freshness-recheck.py", "AUDITOOOR_POC_FRESHNESS_STRICT"),
    ("139", "poc-revert-selector-soundness-check.py", "AUDITOOOR_POC_REVERT_SELECTOR_STRICT"),
    ("140", "anomaly-escalation-guard.py", "AUDITOOOR_ANOMALY_ESCALATION_STRICT"),
]


class TestOrphanGuardsWired(unittest.TestCase):
    def test_each_check_header_present(self):
        for num, _tool, _env in _CHECKS:
            self.assertRegex(_TEXT, rf"{num}\.\s+[A-Z-]+",
                             f"Check #{num} header missing from pre-submit-check.sh")

    def test_each_check_invokes_its_tool(self):
        for num, tool, _env in _CHECKS:
            self.assertIn(tool, _TEXT, f"Check #{num} must invoke {tool}")

    def test_each_check_is_advisory_first(self):
        # the strict env gates the ❌-block; without it the check WARNs (warns++), so
        # the default submit path is byte-compatible (no new hard failures).
        for num, _tool, env in _CHECKS:
            self.assertIn(env, _TEXT, f"Check #{num} must be gated behind {env} (advisory-first)")
            # the env must gate a strict flag, not be unconditionally enforced
            self.assertRegex(_TEXT, rf"{env}:-",
                             f"{env} must default OFF (advisory-first, promotable)")

    def test_bash_syntax_ok(self):
        import subprocess
        r = subprocess.run(["bash", "-n", str(_SCRIPT)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, f"pre-submit-check.sh has a syntax error: {r.stderr}")


if __name__ == "__main__":
    unittest.main()
