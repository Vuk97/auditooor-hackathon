"""Regression test locking the iter4 T2 bundle-local audit doc against silent drift.

If someone adds a new ``$_WS/<path>`` path-resolution site to
``tools/pre-submit-check.sh`` without updating
``docs/PRE_SUBMIT_BUNDLE_LOCAL_CHECKS.md``, this test fails. The test
does NOT enforce row-for-row alignment — only that the doc enumerates
at least as many rows as there are grep-matchable path-resolution
sites in pre-submit. The doc counts auxiliary sites (cosmetic echoes,
guards, error-text references) too, so it is allowed to exceed the
grep count.

See ``docs/LOOP_ITER_004_PLAN.md`` §T2 for task scope. The regression
test is the "truth-audit catch" called out in that section.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PRE_SUBMIT_SH = REPO_ROOT / "tools" / "pre-submit-check.sh"
AUDIT_DOC = REPO_ROOT / "docs" / "PRE_SUBMIT_BUNDLE_LOCAL_CHECKS.md"


def _count_ws_path_sites(pre_submit_text: str) -> int:
    """Count grep-matchable ``$_WS/...`` and ``$_FR_WS/...`` references.

    This is the *minimum* site count — the audit doc must enumerate at
    least this many rows. The doc is allowed to enumerate more (Class D
    ``dirname $SUB`` walks, Class E cosmetic sites, Check #10's
    ``$WS_ROOT`` chain), but it must never enumerate *fewer*.
    """
    count = 0
    for line in pre_submit_text.splitlines():
        # Strip shell comments from the line (but keep the `$_WS` tokens
        # if they appear before a `#`). A naive lstrip-#-match is
        # sufficient for pre-submit-check.sh, which never puts `#` inside
        # a string on a line that also contains `$_WS/`.
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        # Match both $_WS/ and $_FR_WS/ as distinct path-site markers.
        count += len(re.findall(r"\$_WS/", line))
        count += len(re.findall(r"\$_FR_WS/", line))
    return count


def _count_enumeration_rows(doc_text: str) -> int:
    """Count data rows in the '## Enumeration' markdown table.

    The table header is recognised by a leading ``| # | Line |`` column
    spec; the rows are separated by a ``|---|---|`` divider. Each
    subsequent ``|``-prefixed line that is not the divider counts as one
    enumerated row.
    """
    in_table = False
    header_seen = False
    divider_seen = False
    rows = 0
    for line in doc_text.splitlines():
        stripped = line.strip()
        if not in_table:
            if stripped.startswith("| # |") and "Line" in stripped:
                in_table = True
                header_seen = True
                continue
            continue
        # We're inside the table. Divider comes next.
        if not divider_seen:
            if stripped.startswith("|---") or re.match(r"^\|\s*-+\s*\|", stripped):
                divider_seen = True
                continue
            # Some renderers put the divider on the same line block;
            # tolerate an empty line before it.
            if not stripped:
                continue
            # If we hit a non-divider non-empty line before the divider
            # something is malformed — stop counting.
            break
        # Past the divider: count `|`-prefixed rows until a blank line or
        # a non-table line.
        if not stripped:
            break
        if not stripped.startswith("|"):
            break
        rows += 1
    assert header_seen, "Enumeration table header not found in audit doc"
    assert divider_seen, "Enumeration table divider not found in audit doc"
    return rows


class BundleLocalAuditDocTest(unittest.TestCase):
    """Lock the audit doc against silent pre-submit drift."""

    def test_doc_enumeration_matches_pre_submit_grep_count(self) -> None:
        self.assertTrue(
            PRE_SUBMIT_SH.exists(),
            f"pre-submit-check.sh not found at {PRE_SUBMIT_SH}",
        )
        self.assertTrue(
            AUDIT_DOC.exists(),
            f"audit doc not found at {AUDIT_DOC} — iter4 T2 deliverable missing",
        )

        pre_submit_text = PRE_SUBMIT_SH.read_text()
        doc_text = AUDIT_DOC.read_text()

        ws_sites = _count_ws_path_sites(pre_submit_text)
        doc_rows = _count_enumeration_rows(doc_text)

        # Lock: the doc must enumerate at least as many rows as there
        # are grep-matchable ``$_WS/``+``$_FR_WS/`` sites in pre-submit.
        # If someone adds a new ``$_WS/<path>`` reference without
        # updating the doc, ws_sites climbs and this assertion fails.
        self.assertGreaterEqual(
            doc_rows,
            ws_sites,
            msg=(
                f"Audit doc ({AUDIT_DOC.name}) enumerates {doc_rows} rows "
                f"but pre-submit-check.sh now has {ws_sites} grep-matchable "
                f"$_WS/... + $_FR_WS/... path-resolution sites. "
                "Update docs/PRE_SUBMIT_BUNDLE_LOCAL_CHECKS.md so the "
                "enumeration table covers every new site."
            ),
        )

        # Sanity: the doc must enumerate at least one row (it enumerates
        # 27 today, but hard-coding that couples the test to the exact
        # table shape; a floor of 1 is enough to catch "doc got wiped").
        self.assertGreaterEqual(
            doc_rows,
            1,
            "Audit doc enumeration table is empty",
        )
        self.assertGreaterEqual(
            ws_sites,
            1,
            "Pre-submit grep count is zero — regex or path is wrong",
        )


if __name__ == "__main__":
    unittest.main()
