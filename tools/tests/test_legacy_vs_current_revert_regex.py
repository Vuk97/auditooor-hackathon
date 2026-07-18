"""Hermetic regression: PR #132 Codex blocker on PR #121 A9
(legacy-vs-current-shadow-code-path).

Codex's verbatim blocker:
    `function.body_not_contains_regex` uses `^\\s*revert\\s*\\(` to suppress an
    unconditionally reverting legacy function, but the predicate engine
    searches the function source content, which normally includes the
    function signature before the body. A clean fixture shaped like
    `function legacySettle(...) external pure { revert(...); }` will not
    have `revert` at the start of the searched string, so the anchored
    regex may fail to suppress it.

Root cause: `detectors/_predicate_engine.py` evaluates
`function.body_not_contains_regex` against `function.source_mapping.content`,
which is the FULL function source (signature + body). The Slither
documentation and our predicate-engine code path both confirm this.

This test pins the regex semantics WITHOUT requiring Slither / forge /
the full detector pipeline. It mirrors what `_predicate_engine.py` does:
load the source string and evaluate `re.search(regex, src, re.IGNORECASE)`.

Why hermetic: `detectors/test_fixtures/run_tests.sh` already wires the same
fixtures through the real pipeline (vuln + clean), but that requires
Slither + forge to be installed. This unit test runs in CI/dev with just
`python3 -m unittest` and pins the regex itself, so the bug can never
silently regress even if someone edits the YAML and forgets to rerun
forge.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]

PATTERN_YAML = REPO / "reference" / "patterns.dsl" / "legacy-vs-current-shadow-code-path.yaml"
COMPILED_PY = REPO / "detectors" / "wave18" / "legacy_vs_current_shadow_code_path.py"
FIXTURE_CLEAN = REPO / "detectors" / "test_fixtures" / "legacy_vs_current_shadow_code_path_clean.sol"
FIXTURE_VULN = REPO / "detectors" / "test_fixtures" / "legacy_vs_current_shadow_code_path_vulnerable.sol"


# --- helpers ---------------------------------------------------------------

# The shape Slither hands the predicate engine: the function source as it
# appears in the file, signature + body, NOT just the body.
LEGACY_CLEAN = (
    'function legacySettle(uint256, address, uint256) external pure {\n'
    '    revert("deprecated: use settle()");\n'
    '}'
)
LEGACY_VULN = (
    'function legacySettle(uint256 epoch, address user, uint256 amount) external {\n'
    '    payouts[user] = amount;\n'
    '}'
)


def _eval_body_not_contains_regex(regex: str, function_source: str) -> bool:
    """Mirror of _predicate_engine.py logic for `function.body_not_contains_regex`.

    Returns True when the regex does NOT match — i.e. when the predicate
    *passes* (the detector is allowed to fire / not be suppressed). For
    the clean fixture we want this to return False (regex matched →
    predicate fails → detector suppressed).
    """
    return not bool(re.search(regex, function_source, re.IGNORECASE))


# --- tests -----------------------------------------------------------------


class LegacyVsCurrentRevertRegexTest(unittest.TestCase):
    """Pin the revert-regex semantics described in PR #132 Codex comment."""

    # --- (1) The buggy regex DOES NOT suppress the clean shape -------------

    def test_buggy_anchored_regex_fails_to_suppress_clean(self) -> None:
        """Document the bug Codex flagged: `^\\s*revert\\s*\\(` does NOT match
        `function legacySettle(...) external pure { revert(...); }` because
        `revert` is not at start-of-string.

        If this test ever flips to True, someone has either (a) re-anchored
        the regex incorrectly or (b) discovered the predicate engine now
        scans body-only — in which case the fix below should be revisited.
        """
        buggy = r"^\s*revert\s*\("
        # `body_not_contains_regex` returns True (predicate passes →
        # detector fires) on the clean shape with the buggy regex.
        # That's the bug — clean fixture is NOT suppressed.
        self.assertTrue(
            _eval_body_not_contains_regex(buggy, LEGACY_CLEAN),
            "Buggy regex unexpectedly suppressed the clean shape — has the "
            "predicate engine been changed to scan body-only? Re-check "
            "_predicate_engine.py.",
        )

    # --- (2) The fixed regex DOES suppress the clean shape -----------------

    def test_fixed_word_boundary_regex_suppresses_clean(self) -> None:
        """`\\brevert\\s*\\(` correctly matches the clean shape, so the
        clean fixture is suppressed (no detector hit)."""
        fixed = r"\brevert\s*\("
        # body_not_contains_regex returns False on clean shape → predicate
        # fails → detector suppressed.
        self.assertFalse(
            _eval_body_not_contains_regex(fixed, LEGACY_CLEAN),
            "Fixed regex \\brevert\\s*\\( did NOT match the clean shape — "
            "the suppression filter is broken and the detector will fire on "
            "documented safe migration shims.",
        )

    # --- (3) The fixed regex still fires on the vulnerable shape -----------

    def test_fixed_regex_still_allows_vulnerable_to_fire(self) -> None:
        """The vulnerable fixture has NO revert in its body; the fixed
        regex must NOT match, so the predicate passes and the detector
        fires."""
        fixed = r"\brevert\s*\("
        self.assertTrue(
            _eval_body_not_contains_regex(fixed, LEGACY_VULN),
            "Fixed regex unexpectedly matched the vulnerable shape — "
            "true positive will be wrongly suppressed.",
        )

    # --- (4) The committed YAML / .py use the fixed regex ------------------

    def test_committed_yaml_uses_fixed_regex(self) -> None:
        """Pin the YAML so a future edit can't silently re-introduce the
        anchored form."""
        text = PATTERN_YAML.read_text()
        self.assertIn(
            r"function.body_not_contains_regex: '\brevert\s*\('",
            text,
            "YAML no longer uses the fixed `\\brevert\\s*\\(` regex — "
            "Codex PR #132 blocker has regressed.",
        )
        # Defensive: explicitly assert the buggy form is NOT present.
        self.assertNotIn(
            r"function.body_not_contains_regex: '^\s*revert\s*\('",
            text,
            "YAML re-introduced the buggy `^\\s*revert\\s*\\(` regex.",
        )

    def test_committed_compiled_py_uses_fixed_regex(self) -> None:
        """The compiled detector .py must mirror the YAML — otherwise
        run_custom.py will keep using the broken regex."""
        text = COMPILED_PY.read_text()
        self.assertIn(
            r"'function.body_not_contains_regex': '\\brevert\\s*\\('",
            text,
            "Compiled wave18/legacy_vs_current_shadow_code_path.py no "
            "longer uses the fixed `\\brevert\\s*\\(` regex.",
        )
        self.assertNotIn(
            r"'function.body_not_contains_regex': '^\\s*revert\\s*\\('",
            text,
            "Compiled .py re-introduced the buggy regex — re-run "
            "tools/pattern-compile.py.",
        )

    # --- (5) The committed fixtures match the shapes we test --------------

    def test_clean_fixture_has_revert_in_body(self) -> None:
        """Sanity: the clean fixture file actually contains the
        `function legacySettle(...) { revert(...); }` shape that motivated
        the blocker."""
        text = FIXTURE_CLEAN.read_text()
        self.assertRegex(text, r"function\s+legacySettle\b")
        self.assertRegex(text, r"\brevert\s*\(")

    def test_vulnerable_fixture_has_no_revert_in_body(self) -> None:
        """Sanity: the vulnerable fixture must NOT contain a revert in the
        legacySettle body, otherwise the test_fixed_regex_still_allows_…
        assertion would be testing the wrong thing."""
        text = FIXTURE_VULN.read_text()
        # Allow `revert` strings only OUTSIDE the legacySettle body — the
        # fixture currently has none anywhere, but the strict invariant is
        # "no revert inside legacySettle body". Use a coarse check: assert
        # the file contains no `revert(` call at all.
        self.assertNotRegex(
            text,
            r"\brevert\s*\(",
            "Vulnerable fixture unexpectedly contains a revert(…) call — "
            "the suppression filter would suppress it and the detector "
            "would not fire.",
        )


if __name__ == "__main__":
    unittest.main()
