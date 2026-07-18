#!/usr/bin/env python3
"""FIX-7 regression tests (capv3 iter-007 T1).

Locks the two iter-v3-6 T3 deep truth-audit queued follow-ups:

  Part 1 — Playbook §5 `cannot-run.reason` vocabulary row.
    Note-1 of `docs/CAPV3_ITER6_T3_deep_truth_audit.md §Queued-follow-ups`
    flagged that `cannot-run` was emitted by 3 producers
    (`adversarial-copilot.py`, `llm-dispatch.py`, `adversarial-live-run.sh`)
    with a documented sub-code set, but §5 had no row for it. FIX-7 adds
    that row. Tests 1 + 2 lock both the row's presence and the exact
    sub-code set (no over- or under-enumeration).

  Part 2 — Factory honest-zero disambiguation header.
    Note-2 flagged that `submission-factory.py` emits zero rebuttal
    markers on honest-zero bundles (e.g. `negrisk`-shape), which is
    correct behavior but easily misread as a FIX-1/FIX-6 regression by
    a reviewer scrolling past the rebuttal block. FIX-7 adds a single
    disambiguation comment at the very top of `cantina_ready.md` that
    is always one of 2 literal strings:
      `<!-- triager-risk: markers present -->`
      `<!-- triager-risk: no-known-class -->`
    Tests 3 + 4 lock both branches.

Offline, stdlib-only, hermetic. Tests 3 + 4 shell out to
`tools/submission-factory.py` via subprocess (mirrors
`tools/tests/test_submission_factory.py`'s CLI-contract discipline).
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PLAYBOOK = ROOT / "docs" / "10_OF_10_PLAYBOOK.md"
FACTORY = ROOT / "tools" / "submission-factory.py"

# The 7 canonical sub-codes the §5 row must enumerate. Derived from
# iter-v3-3 adversarial-copilot + iter-v3-5 llm-dispatch + iter-v3-6
# adversarial-live-run wrapper. Exact set; no more, no fewer.
EXPECTED_CANNOT_RUN_SUB_CODES = {
    "no-api-key",
    "timeout",
    "429-retry-exhausted",
    "malformed-response",
    "swarm-dispatcher-is-not-an-llm-caller",
    "operator-not-consented",
    "driver-error",
}


def _extract_section5_table_rows(text: str) -> list[str]:
    """Return the raw pipe-delimited rows of the §5 vocabulary table.

    The §5 heading is `## 5. The status vocabulary — locked`. The table
    lives between that heading and the next `##` heading. We return
    every line that starts with `|` and is not a header-separator row
    (i.e. not the `|---|---|...` alignment row).
    """
    section_match = re.search(
        r"^## 5\.\s[^\n]*\n(.+?)(?=^## \d)",
        text, re.DOTALL | re.MULTILINE,
    )
    if not section_match:
        raise AssertionError("Could not find §5 in playbook")
    body = section_match.group(1)
    rows: list[str] = []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        # Skip the header-separator row (all dashes between pipes).
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if cells and all(set(c) <= set("-: ") for c in cells):
            continue
        rows.append(stripped)
    return rows


def _build_minimal_bundle(tmp: Path, *, draft_body: str) -> Path:
    """Create a packaged-shape bundle with the given draft body."""
    bundle = tmp / "bundle"
    bundle.mkdir(parents=True)
    (bundle / "source-draft.md").write_text(draft_body)
    # Provide a `.t.sol` so PoC derivation stays on the happy path
    # (not strictly needed for this test, but avoids noise).
    (bundle / "poc.t.sol").write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity 0.8.20;\n"
        "import {Test} from \"forge-std/Test.sol\";\n"
        "contract Sample is Test {\n"
        "    function testExploit() public {}\n"
        "}\n"
    )
    return bundle


def _run_factory(bundle: Path) -> tuple[int, str, str]:
    argv = [sys.executable, str(FACTORY), "--bundle", str(bundle)]
    r = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout, r.stderr


class TestPlaybookSection5CannotRunRow(unittest.TestCase):
    """Part 1 — §5 row presence + exact sub-code enumeration."""

    def test_playbook_section5_has_cannot_run_row(self) -> None:
        """Row is present in §5, names all 3 producers, and lists all 7 sub-codes."""
        text = PLAYBOOK.read_text(encoding="utf-8")
        rows = _extract_section5_table_rows(text)
        matches = [r for r in rows if "cannot-run.reason" in r]
        self.assertEqual(
            len(matches), 1,
            f"Expected exactly 1 row with `cannot-run.reason` in §5; got {len(matches)}: {matches!r}",
        )
        row = matches[0]
        # All 3 producers named verbatim.
        self.assertIn("adversarial-copilot.py", row)
        self.assertIn("llm-dispatch.py", row)
        self.assertIn("adversarial-live-run.sh", row)
        # Every expected sub-code appears at least once.
        for sub in EXPECTED_CANNOT_RUN_SUB_CODES:
            self.assertIn(sub, row, f"Missing sub-code `{sub}` in §5 row: {row!r}")
        # Consumer-notes anchor: tool-local + wrapper exits 0 + no
        # escalation to submission gate / evidence matrix.
        self.assertIn("Tool-local", row)
        self.assertIn("exits 0", row)
        self.assertIn("submission gate", row)

    def test_playbook_section5_cannot_run_row_lists_all_sub_codes(self) -> None:
        """Exact set match — no over- or under-enumeration vs the locked 7."""
        text = PLAYBOOK.read_text(encoding="utf-8")
        rows = _extract_section5_table_rows(text)
        matches = [r for r in rows if "cannot-run.reason" in r]
        self.assertEqual(len(matches), 1)
        row = matches[0]
        # Cells are pipe-delimited. The "Allowed values" cell is index 2
        # (0=producer, 1=field, 2=values, 3=consumer-notes) when we
        # strip the leading/trailing pipes.
        cells = [c.strip() for c in row.strip("|").split("|")]
        self.assertGreaterEqual(len(cells), 3, f"Too few cells in row: {row!r}")
        values_cell = cells[2]
        # Extract every backticked token.
        found = set(re.findall(r"`([^`]+)`", values_cell))
        self.assertEqual(
            found, EXPECTED_CANNOT_RUN_SUB_CODES,
            f"Sub-code set mismatch.\n  expected={sorted(EXPECTED_CANNOT_RUN_SUB_CODES)}\n  found   ={sorted(found)}",
        )


class TestFactoryHonestZeroHeader(unittest.TestCase):
    """Part 2 — factory emits exactly one of the 2 disambiguation headers."""

    def test_factory_emits_markers_present_header_when_classes_matched(self) -> None:
        """Draft triggers ≥1 rebuttal class → header says `markers present`."""
        # POLY-45 trigger (uint256.max) — mirrors `test_submission_factory.py::test_triager_risk_section_flags_poly45_class_correctly`.
        draft = (
            "## Submission — #FIX-PRESENT — High — VERIFIED\n\n"
            "### Finding Title\n```\nmakerAmount uint256.max overflow\n```\n\n"
            "## Impact\nSetting makerAmount to uint256.max drains vault.\n"
        )
        with tempfile.TemporaryDirectory() as td:
            bundle = _build_minimal_bundle(Path(td), draft_body=draft)
            rc, _, err = _run_factory(bundle)
            self.assertEqual(rc, 0, msg=f"stderr={err}")
            produced = (bundle / "cantina_ready.md").read_text()
            first_line = produced.splitlines()[0]
            self.assertEqual(
                first_line, "<!-- triager-risk: markers present -->",
                f"First line of cantina_ready.md must be the markers-present header; got {first_line!r}",
            )
            # And the no-known-class alternative must not leak through.
            self.assertNotIn("<!-- triager-risk: no-known-class -->", produced)
            # Sanity: rebuttal block is present (belt + suspenders).
            self.assertIn("<!-- rebuttal:start -->", produced)
            self.assertIn("[POLY-45]", produced)

    def test_factory_emits_no_known_class_header_when_no_match(self) -> None:
        """Draft triggers 0 rebuttal classes → header says `no-known-class`."""
        # Deliberately negrisk-shape: talks about a fee refund path, no
        # uint-bounds keywords, no event-emit language, no attribution
        # language, no bridge/cross-chain language.
        draft = (
            "# NegRiskFeeModule fee refund path reverts on CTF refunds\n\n"
            "## Impact\n"
            "Given USDC total supply of ~32e24, any refund in the $1k-$100k range "
            "is achievable as accumulated neg-risk CTF fees. The module cannot "
            "refund the accumulated amount because the internal bookkeeping path "
            "rejects the id.\n\n"
            "## Severity\nLow.\n"
        )
        with tempfile.TemporaryDirectory() as td:
            bundle = _build_minimal_bundle(Path(td), draft_body=draft)
            rc, _, err = _run_factory(bundle)
            self.assertEqual(rc, 0, msg=f"stderr={err}")
            produced = (bundle / "cantina_ready.md").read_text()
            first_line = produced.splitlines()[0]
            self.assertEqual(
                first_line, "<!-- triager-risk: no-known-class -->",
                f"First line must be the no-known-class header on honest-zero bundle; got {first_line!r}",
            )
            # And the markers-present alternative must not leak through.
            self.assertNotIn("<!-- triager-risk: markers present -->", produced)
            # Sanity: the honest-zero rebuttal wording is preserved.
            self.assertIn("No known rejection-class matches.", produced)
            # Hard-negative: rebuttal markers must be absent on honest-zero.
            self.assertNotIn("<!-- rebuttal:start -->", produced)


if __name__ == "__main__":
    unittest.main()
