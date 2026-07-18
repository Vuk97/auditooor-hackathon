#!/usr/bin/env python3
# <!-- r36-rebuttal: lane GENUINE-COVERAGE-VERDICT-BUCKETING registered in commit message -->
"""Strata 2026-06-30: the genuine-coverage manifest `counts` were ALL-error while the
verdict detail rows were honest (29 vacuous + 11 no-mutants). Root cause: the Makefile
`_audit-deep-solidity-genuine-coverage` recipe extracted each per-fn verdict with a
`python3 -c` one-liner that put `try: ... except ...` on a SINGLE line -> SyntaxError ->
empty stdout -> the bucketing `case "$v"` fell to `*) errored` for EVERY function. So
counts.error=40, counts.vacuous=0 even though 29 were vacuous - a serving-join lie:
downstream gates reading counts.vacuous/counts.error get the wrong picture.

This test pins:
  1. a single-line `try:`/`except` in a `python3 -c` IS a SyntaxError (the trap), and
  2. the Makefile's CURRENT extraction idiom is NOT that broken form and DOES extract
     vacuous/no-mutants/non-vacuous correctly + degrades missing/garbage to "error", and
  3. the recipe carries a `no-mutants)` bucket arm + a `no_mutants` counts key.
"""
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_MAKEFILE = Path(__file__).resolve().parent.parent.parent / "Makefile"

# The exact extraction idiom now used in the recipe (kept in sync with the Makefile).
_EXTRACT = (
    'import json,sys; from pathlib import Path; p=Path(sys.argv[1]); '
    'raw=(p.read_text(encoding="utf-8") if p.exists() else ""); '
    'd=(json.loads(raw) if raw.strip().startswith("{") else {}); '
    'print((d.get("verdict") or "error") if isinstance(d,dict) else "error")'
)


def _extract(verdict_json: str | None) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        if verdict_json is not None:
            f.write(verdict_json)
        path = f.name
    out = subprocess.run([sys.executable, "-c", _EXTRACT, path],
                         capture_output=True, text=True)
    return out.stdout.strip()


class VerdictBucketingTest(unittest.TestCase):
    def test_single_line_try_except_is_syntax_error(self):
        # Documents the original trap: a compound `try:` mixed onto a `;`-joined
        # single logical line (exactly how the Makefile `\`-continuation collapsed it)
        # is a SyntaxError -> NO stdout -> every verdict mis-bucketed to error.
        broken = ('import json,sys; try: print("x") '
                  'except Exception: print("error")')
        r = subprocess.run([sys.executable, "-c", broken], capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout.strip(), "")
        self.assertIn("SyntaxError", r.stderr)

    def test_extract_preserves_real_verdicts(self):
        self.assertEqual(_extract('{"verdict":"vacuous"}'), "vacuous")
        self.assertEqual(_extract('{"verdict":"no-mutants"}'), "no-mutants")
        self.assertEqual(_extract('{"verdict":"non-vacuous"}'), "non-vacuous")
        self.assertEqual(_extract('{"verdict":"no-baseline"}'), "no-baseline")

    def test_extract_degrades_missing_and_garbage_to_error(self):
        self.assertEqual(_extract(""), "error")
        self.assertEqual(_extract("not json"), "error")
        self.assertEqual(_extract('{"no_verdict_key":1}'), "error")

    def test_makefile_has_no_single_line_try_except_extractor(self):
        txt = _MAKEFILE.read_text(encoding="utf-8")
        # the broken pattern: a `try:` with an inline statement on the SAME line
        self.assertNotRegex(
            txt, r"try:\s*print\(json\.loads",
            "Makefile reintroduced the single-line try/except verdict extractor")

    def test_makefile_buckets_no_mutants_explicitly(self):
        txt = _MAKEFILE.read_text(encoding="utf-8")
        self.assertIn("no-mutants) nomutants=", txt)
        self.assertIn('"no_mutants":nomutants', txt)


if __name__ == "__main__":
    unittest.main(verbosity=2)
