#!/usr/bin/env python3
"""test_l30_callsite_enumeration_nonempty.py

Enforcement-gap L30 (2026-07-03): pre-submit Check #48 passed on a bare
`## Enumerated Call Sites` HEADER with NO actual sites - the superset-or-equal
(|AST| >= |grep|) completeness invariant was only a docstring, never asserted at
runtime. Check #48 now requires the section BODY to list >= 1 concrete call site
(file ref / :line / a `-`/`*` bullet naming a call). ADVISORY-FIRST: an empty header
WARN-passes by default; it hard-fails only under AUDITOOOR_L30_CALLSITE_STRICT.

This mirrors the exact site-counting logic embedded in tools/pre-submit-check.sh
Check #48 and pins its behavior + the advisory-first env gating + bash syntax.
"""
import re
import subprocess
import unittest
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "pre-submit-check.sh"
_TEXT = _SCRIPT.read_text(encoding="utf-8", errors="replace")


def _count_sites(body: str) -> int:
    site_re = re.compile(r"[A-Za-z0-9_./-]+\.(?:sol|go|rs|vy|cairo|move)\b|:\d+\b", re.I)
    bullet_re = re.compile(r"^\s*[-*]\s+.*\w+\s*\(")
    return len(site_re.findall(body)) + sum(1 for ln in body.splitlines() if bullet_re.match(ln))


class TestL30CallsiteNonEmpty(unittest.TestCase):
    def test_populated_section_counts_sites(self):
        self.assertGreaterEqual(_count_sites("- Vault.sol:42 withdraw()\n- route()\n"), 2)

    def test_empty_section_counts_zero(self):
        self.assertEqual(_count_sites("(none yet)\nTODO\n"), 0)

    def test_check48_requires_nonempty_and_is_advisory_first(self):
        self.assertIn("AUDITOOOR_L30_CALLSITE_STRICT", _TEXT,
                      "the empty-section hard-fail must be gated behind the named strict env")
        self.assertIn("enumerated_call_sites_section_empty", _TEXT,
                      "Check #48 must distinguish an empty section from a populated one")
        # the WARN (advisory) path must exist so default behavior stays byte-compatible
        self.assertIn("WARN:enumerated_call_sites_section_empty", _TEXT)

    def test_no_inline_regex_flags_bug(self):
        # the embedded python must not carry the `(?m)` mid-pattern flag that crashes py3.11+
        self.assertNotIn("(?m)^\\s*[-*]", _TEXT)

    def test_bash_syntax_ok(self):
        r = subprocess.run(["bash", "-n", str(_SCRIPT)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
