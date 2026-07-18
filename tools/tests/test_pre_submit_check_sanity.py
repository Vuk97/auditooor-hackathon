#!/usr/bin/env python3
"""Sanity-audit regression for tools/pre-submit-check.sh.

Authored by Lane ZZZZZ of V3 closeout iter17 (2026-05-23) after the script
crossed 100 checks. The shell wrapper has historically accumulated quiet
regressions when a new R-rule check is added:

  - severity-arg case mismatch (Lane ZZZZZ iter17: R44 silently errored on
    `--severity High` because its argparse only accepted UPPERCASE)
  - silent-skip: a tool exists, severity-trigger passes, but the verdict
    line never reaches stdout (iter9 WS_DIR dead-zone, iter12 grep miss)
  - ordering regressions: R45 must run BEFORE R42, R52 BEFORE R47, etc.

These tests are LINTS over the script, not behavior-driven tests. They
catch drift at PR time before another draft eats a silent failure.
"""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "pre-submit-check.sh"
TOOLS_DIR = ROOT / "tools"


def _read_script() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def _list_check_numbers_from_echoes(text: str) -> list[int]:
    """Return every numeric check identifier that appears as a verdict source.

    Captures TWO emission shapes:
      1. `echo "  ✅ 42. SOMETHING ..."`           - direct echo
      2. `_check "42. SOMETHING ..." ...`          - via the _check helper
      3. `_warn "42. SOMETHING ..." ...`           - via the _warn helper
    """
    out: set[int] = set()
    direct = re.compile(r'\s*echo\s+"\s*(?:[✅❌⚠️🔧]\s*)?(\d+)[a-z]?\.\s')
    via_helper = re.compile(r'\s*_(?:check|warn)\s+"(\d+)[a-z]?\.\s')
    for line in text.splitlines():
        for pat in (direct, via_helper):
            m = pat.match(line)
            if m:
                out.add(int(m.group(1)))
                break
    return sorted(out)


def _list_section_headers(text: str) -> list[tuple[int, int, str]]:
    """Return [(line_no, check_num, name)] for `# --- Check N:` markers."""
    out: list[tuple[int, int, str]] = []
    for ln, line in enumerate(text.splitlines(), start=1):
        m = re.match(r'#\s*---\s*Check\s+#?(\d+)([a-z]?)\s*:?\s*(.*?)\s*-*$', line)
        if m:
            out.append((ln, int(m.group(1)), m.group(3).strip()))
    return out


class PreSubmitCheckSanityTests(unittest.TestCase):
    """Lints over tools/pre-submit-check.sh.

    Each test is independent and self-contained. None of them require a
    workspace fixture or external network. They run against the script's
    source text only.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.text = _read_script()

    def test_script_passes_bash_syntax(self) -> None:
        """`bash -n` on the script must succeed."""
        r = subprocess.run(
            ["bash", "-n", str(SCRIPT)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(r.returncode, 0, msg=f"bash -n failed: {r.stderr}")

    def test_check_numbers_are_within_known_range(self) -> None:
        """Check numbers should be in 1..106 inclusive. New checks must extend the test."""
        nums = _list_check_numbers_from_echoes(self.text)
        self.assertTrue(nums, "no check echoes detected; pattern out of date")
        self.assertGreaterEqual(min(nums), 1)
        self.assertLessEqual(
            max(nums),
            106,
            f"check number {max(nums)} > 106; if a new check #{max(nums)} was added, "
            "update this test bound after confirming numbering is intentional",
        )

    def test_known_check_number_gaps_are_documented(self) -> None:
        """Gaps in check numbering must be limited to the known retired/grouped set.

        Known intentional gaps as of 2026-05-23:
          - #9: retired
          - #37, #38: never landed
          - #44-#47: grouped under `# --- Checks 44-47:` block
          - #50-#57: grouped under `# --- Checks 50-57:` block
          - #100: present in script but may not always emit verdict
        """
        nums = set(_list_check_numbers_from_echoes(self.text))
        # 100 is present in the source but R28 is severity-gated; not always visible
        known_intentional_gaps = {9, 37, 38, 44, 45, 46, 47, 50, 51, 52, 53, 54, 55, 56, 57}
        expected_present = set(range(1, 102)) - known_intentional_gaps
        # 4b / 4c are alphanumeric sub-checks; numeric 4 is present
        missing = expected_present - nums
        # Allow at most #100 to be missing (R28 is the most-recent addition)
        unexpected = missing - {100}
        self.assertFalse(
            unexpected,
            f"check numbers missing from script echoes (unexpected gaps): {sorted(unexpected)}\n"
            "If a check was intentionally removed, add it to known_intentional_gaps.",
        )

    def test_r45_fires_before_r42_in_script(self) -> None:
        """Doctrine: R45 must run BEFORE R42 (R45 short-circuits R42 narrowing)."""
        headers = _list_section_headers(self.text)
        r45 = next((h for h in headers if "R45" in h[2]), None)
        r42 = next((h for h in headers if "R42" in h[2]), None)
        self.assertIsNotNone(r45, "no R45 section header found")
        self.assertIsNotNone(r42, "no R42 section header found")
        self.assertLess(
            r45[0],
            r42[0],
            f"R45 (line {r45[0]}) must precede R42 (line {r42[0]})",
        )

    def test_r52_fires_before_r47_in_script(self) -> None:
        """Doctrine: R52 (rubric-row coverage) is structurally upstream of R47."""
        headers = _list_section_headers(self.text)
        r52 = next((h for h in headers if "R52" in h[2]), None)
        r47 = next((h for h in headers if "R47" in h[2]), None)
        self.assertIsNotNone(r52, "no R52 section header found")
        self.assertIsNotNone(r47, "no R47 section header found")
        self.assertLess(
            r52[0],
            r47[0],
            f"R52 (line {r52[0]}) must precede R47 (line {r47[0]})",
        )

    def test_ws_dir_defaulted_before_walkup(self) -> None:
        """WS_DIR must be defaulted (set -u safety) BEFORE the walk-up runs.

        iter9 found that Checks #94-#99 could reference WS_DIR before the
        walk-up at line ~980, causing `unbound variable` aborts under set -u.
        Fix: WS_DIR="" early in the script, then re-assigned after walk-up.
        """
        lines = self.text.splitlines()
        first_decl = None
        walkup_loc = None
        for i, line in enumerate(lines, start=1):
            if first_decl is None and re.match(r'\s*WS_DIR=""\s*(?:#|$)', line):
                first_decl = i
            if walkup_loc is None and 'WS_DIR="${_WS:-}"' in line:
                walkup_loc = i
            if first_decl and walkup_loc:
                break
        self.assertIsNotNone(first_decl, "WS_DIR default declaration not found")
        self.assertIsNotNone(walkup_loc, "WS_DIR walk-up assignment not found")
        self.assertLess(
            first_decl,
            walkup_loc,
            f"WS_DIR default (line {first_decl}) must precede walk-up (line {walkup_loc})",
        )

    def test_severity_arg_lower_passed_to_lowercase_only_tools(self) -> None:
        """Tools whose argparse `choices=` are lowercase-only must receive SEVERITY_ARG_LOWER."""
        # These tools, when their --help is parsed, only accept lowercase
        # choice values (the verified-incompatible set as of 2026-05-23).
        # The script MUST pass `$SEVERITY_ARG_LOWER` not `$SEVERITY_ARG` to them.
        require_lower = [
            ("commitment-vs-validation-check.py", "_R29_ARGS"),
            ("external-url-liveness-check.py", "_R54_ARGS"),
        ]
        for tool_name, arr in require_lower:
            with self.subTest(tool=tool_name):
                # Find the line that appends --severity to arr
                pat = re.compile(
                    rf'{re.escape(arr)}\+=\("--severity"\s+"\$([A-Z_]+)"\)'
                )
                m = pat.search(self.text)
                self.assertIsNotNone(m, f"no --severity append found for {arr}")
                var = m.group(1)
                self.assertEqual(
                    var,
                    "SEVERITY_ARG_LOWER",
                    f"{arr} must pass $SEVERITY_ARG_LOWER (tool accepts lowercase only); "
                    f"currently passes ${var}",
                )

    def test_severity_upper_passed_to_uppercase_only_tools(self) -> None:
        """Tools whose argparse `choices=` are uppercase-only must receive SEVERITY_UPPER.

        Empirical anchor: Lane ZZZZZ iter17 found R44
        (opposed-trace-actor-separation-check.py) silently errored with
        `invalid choice: 'High'` because the script passed SEVERITY_ARG
        but the tool only accepts {auto,LOW,MEDIUM,HIGH,CRITICAL}.
        """
        require_upper = [
            ("opposed-trace-actor-separation-check.py", "_R44_ARGS"),
        ]
        for tool_name, arr in require_upper:
            with self.subTest(tool=tool_name):
                pat = re.compile(
                    rf'{re.escape(arr)}\+=\("--severity"\s+"\$([A-Z_]+)"\)'
                )
                m = pat.search(self.text)
                self.assertIsNotNone(m, f"no --severity append found for {arr}")
                var = m.group(1)
                self.assertEqual(
                    var,
                    "SEVERITY_UPPER",
                    f"{arr} must pass $SEVERITY_UPPER (tool accepts uppercase only); "
                    f"currently passes ${var}",
                )

    def test_severity_args_resolved_at_compute_site(self) -> None:
        """SEVERITY_UPPER and SEVERITY_ARG_LOWER must both be declared at startup.

        These are the two canonical normalized forms. Every later check that
        needs a particular case picks the right one. Without both being
        computed up-front, a downstream check would have to re-derive.
        """
        self.assertRegex(
            self.text,
            r'\bSEVERITY_UPPER\s*=\s*\$\(printf',
            "SEVERITY_UPPER must be defined early via printf+tr",
        )
        self.assertRegex(
            self.text,
            r'\bSEVERITY_ARG_LOWER\s*=\s*\$\(printf',
            "SEVERITY_ARG_LOWER must be defined early via printf+tr",
        )

    def test_no_check_exits_early_on_individual_check_failure(self) -> None:
        """No individual check should call `exit` mid-script; failures only
        increment `fails`. Early exits would skip every downstream check.
        """
        # The only legitimate exits are: arg validation (line ~267), missing
        # SUB (line ~302), and final summary block (lines ~8200+). Count.
        exit_locs: list[int] = []
        for i, line in enumerate(self.text.splitlines(), start=1):
            if re.match(r'\s*exit\s+\d+\s*$', line):
                exit_locs.append(i)
        # Expect <=5 (arg-help, missing-sub, summary's 3 branches)
        self.assertLessEqual(
            len(exit_locs),
            5,
            f"too many `exit N` statements: {exit_locs}; an individual check "
            "must NOT exit the script (use fails=$((fails+1)) instead)",
        )


if __name__ == "__main__":
    unittest.main()
