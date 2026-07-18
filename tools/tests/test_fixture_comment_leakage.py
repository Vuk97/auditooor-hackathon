#!/usr/bin/env python3
"""Regression test: detector test fixtures must not contain trigger-word
comments that can leak into ``body_contains_regex`` predicate matches.

Background (foot-gun #2 from recurring-mistakes memory):
    The predicate engine evaluates ``function.body_contains_regex`` against
    ``function.source_mapping.content``, which includes BOTH the function
    signature AND the body. Any developer-facing tag inside fixture comments
    — specifically ``// BUG:``, ``// VULN:``, ``// CLEAN:`` — is therefore
    visible to detector regexes and can cause spurious matches (vulnerable
    fixtures hitting on the comment instead of the buggy code path; clean
    fixtures hitting on the comment instead of the genuinely-clean body).

This test enforces that no fixture under ``detectors/test_fixtures/`` carries
the literal trigger tags. Use neutral prose like ``// Pattern:``,
``// Negative case:``, or descriptive sentences instead — the fixture's
file-name suffix (``_vulnerable`` / ``_clean``) and the runner script
(``detectors/test_fixtures/run_tests.sh``) are the source of truth for
expected hit counts, not the comments.

The ``// missing`` and ``// __gap`` shapes from the recurring-mistakes
queue item were considered but intentionally excluded: prose like
``// Missing paired write`` is legitimate descriptive English in
auto-generated fixtures, and ``__gap`` is a real Solidity storage-gap
identifier whose mention in comments is benign. Only the three explicit
``BUG:`` / ``VULN:`` / ``CLEAN:`` colon-tags are consistently leakage
risks worth a tripwire.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = REPO_ROOT / "detectors" / "test_fixtures"

# Triggers — keep in sync with the queue item that motivated this guard
# ("Foot-gun #2 — fixture comment-leakage"). The patterns cover both
# ``// X:`` and ``/// X:`` (NatSpec triple-slash) variants, with optional
# whitespace, plus the in-line variant where the tag appears mid-comment
# (e.g. ``// transferOwnership inherited — BUG: new owner ...``).
_TRIGGER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # Start-of-comment variants
    ("// BUG:", re.compile(r"//+\s*BUG:")),
    ("// VULN:", re.compile(r"//+\s*VULN:")),
    ("// CLEAN:", re.compile(r"//+\s*CLEAN:")),
    # Mid-line variants (still inside a ``//`` comment).
    ("inline BUG:", re.compile(r"//[^\n]*\bBUG:")),
    ("inline VULN:", re.compile(r"//[^\n]*\bVULN:")),
    ("inline CLEAN:", re.compile(r"//[^\n]*\bCLEAN:")),
)


class FixtureCommentLeakageTest(unittest.TestCase):
    """Smoke guard for foot-gun #2 — fixture comment-leakage."""

    def test_fixtures_dir_exists(self) -> None:
        self.assertTrue(
            FIXTURES_DIR.is_dir(),
            f"Expected fixtures dir at {FIXTURES_DIR}",
        )

    def test_no_trigger_word_comments_in_fixtures(self) -> None:
        offenders: list[str] = []
        for sol in sorted(FIXTURES_DIR.glob("*.sol")):
            try:
                text = sol.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for line_no, line in enumerate(text.splitlines(), start=1):
                for label, pat in _TRIGGER_PATTERNS:
                    if pat.search(line):
                        offenders.append(
                            f"{sol.relative_to(REPO_ROOT)}:{line_no} matches "
                            f"{label!r}: {line.strip()}"
                        )
                        break
        if offenders:
            preview = "\n  - " + "\n  - ".join(offenders[:20])
            self.fail(
                "Trigger-word comments found in detector test fixtures "
                f"({len(offenders)} hit(s)). Replace with neutral prose "
                "(e.g. '// Pattern:', '// Negative case:'). Foot-gun #2: "
                "comments leak into body_contains_regex predicate matches."
                + preview
            )


if __name__ == "__main__":
    unittest.main()
