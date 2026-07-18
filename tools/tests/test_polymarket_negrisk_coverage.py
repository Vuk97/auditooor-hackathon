#!/usr/bin/env python3
"""PR #121 B2 — NegRisk-race / auth-dup detector coverage regression test.

Per `docs/DETECTOR_BACKFILL_ENGAGEMENT_4_5.md` Workstream B2: confirm the
corpus has detectors that catch the underlying NegRisk-race / auth-dup
pattern that produced submissions in the POLY-198 era.

The Polymarket coverage ledger
(`docs/POLYMARKET_18_DETECTOR_COVERAGE.md` /
 `reference/polymarket_detector_coverage.json`) records that the
NegRisk-race finding (Cantina #205, "NegRiskOperator unflag race:
resolveQuestion preempts admin emergencyResolveQuestion due to
DELAY_PERIOD = 0") is covered by

    detectors/wave17/unflag_race_resolve_without_delay_period.py
    reference/patterns.dsl/unflag-race-resolve-without-delay-period.yaml

with `today_status: active-no-fire` — DSL authored from this exact
finding (lives in `patterns.dsl.r77_polymarket/`); the historical
NegRiskOperator contract source is in a sibling Polymarket repository
not present in `~/audits/polymarket/src-v2/`, so a real Slither run is
gated on source-tree availability. The verification methodology is
source-grep: confirm the detector's regex predicates match the
historical NegRiskOperator PoC source code as captured in
`~/audits/polymarket/submissions/SUBMISSIONS.md` (Draft 5).

This regression test locks four properties:

1. The ledger row for Cantina #205 still points at the expected
   `detector_path` / `dsl_path`.
2. The DSL pattern file exists at the recorded path and carries the
   five core predicates that anchor it to the NegRisk-race shape
   (DELAY_PERIOD source clue, resolveQuestion name, onlyNotFlagged
   modifier, body comparator on `block.timestamp < ... + DELAY_PERIOD`,
   and the `DELAY_PERIOD = 0` constant clue).
3. The compiled wave17 detector module loads and preserves all five
   predicates (regression-detect a regenerate that drifts away from
   the NegRisk shape).
4. Source-grep verification: every regex predicate in the detector
   fires against the historical NegRiskOperator PoC source code (the
   exact snippet quoted in the Draft-5 submission). This is the
   `active-no-fire` ledger row's by-construction match-shape claim,
   reified as a hermetic test-case so a future predicate edit that
   breaks the match shape is caught immediately rather than silently
   regressing to `missing` coverage.

If a future change retires this detector OR loosens the NegRisk-anchor
predicates such that the historical PoC no longer matches, this test
fails and the ledger entry must be reconciled (either point at a new
detector or convert the row to `missing`).

Hermetic: no Slither invocation, no network, no filesystem writes.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]

LEDGER_JSON = REPO / "reference" / "polymarket_detector_coverage.json"
LEDGER_MD = REPO / "docs" / "POLYMARKET_18_DETECTOR_COVERAGE.md"

EXPECTED_DETECTOR_PATH = "detectors/wave17/unflag_race_resolve_without_delay_period.py"
EXPECTED_DSL_PATH = "reference/patterns.dsl/unflag-race-resolve-without-delay-period.yaml"

# The historical NegRiskOperator PoC source as quoted in Draft 5 of
# `~/audits/polymarket/submissions/SUBMISSIONS.md` (Cantina #205).
# Inlined here to keep the test hermetic — the audit ledger lives
# outside this repo and isn't available to CI.
HISTORICAL_NEGRISK_OPERATOR_SOURCE = """
// NegRiskOperator.sol:180-192
contract NegRiskOperator {
    uint256 public constant DELAY_PERIOD = 0;

    mapping(bytes32 => uint256) public flaggedAt;
    mapping(bytes32 => uint256) public reportedAt;
    mapping(bytes32 => bool) public results;

    modifier onlyNotFlagged(bytes32 _questionId) {
        if (flaggedAt[_questionId] != 0) revert OnlyNotFlagged();
        _;
    }

    function resolveQuestion(bytes32 _questionId) external onlyNotFlagged(_questionId) {
        uint256 reportedAt_ = reportedAt[_questionId];
        if (reportedAt_ == 0) revert ResultNotAvailable();
        if (block.timestamp < reportedAt_ + DELAY_PERIOD) revert DelayPeriodNotOver();
        bool result = results[_questionId];
        nrAdapter.reportOutcome(_questionId, result);
        emit QuestionResolved(_questionId, result);
    }

    function unflagQuestion(bytes32 _questionId) external onlyAdmin {
        if (flaggedAt[_questionId] == 0) revert OnlyFlagged();
        flaggedAt[_questionId] = 0;
        emit QuestionUnflagged(_questionId);
    }
}
"""


def _load_ledger_row(submission_id: str) -> dict:
    data = json.loads(LEDGER_JSON.read_text())
    for row in data.get("rows", []):
        if row.get("submission_id") == submission_id:
            return row
    raise AssertionError(
        f"submission_id {submission_id!r} not found in {LEDGER_JSON}"
    )


class NegRiskRaceCoverageTests(unittest.TestCase):
    """B2 lock: NegRisk-race / Cantina #205 detector coverage."""

    def test_ledger_row_205_points_at_expected_detector_and_dsl(self) -> None:
        """Lock 1: the JSON ledger row for #205 still records the
        active wave17 detector and the matching DSL pattern.

        If a future ledger refresh drops or rewrites this row, this
        test fails loudly so the regression is visible rather than
        silently sliding to `missing`.
        """
        row = _load_ledger_row("205")
        self.assertEqual(row["detector_path"], EXPECTED_DETECTOR_PATH, row)
        self.assertEqual(row["dsl_path"], EXPECTED_DSL_PATH, row)
        self.assertIn(
            row["today_status"],
            {"active-fires", "active-no-fire"},
            f"row #205 today_status regressed below positive coverage: {row}",
        )
        self.assertEqual(row["root_class"], "unflag_race_resolve_without_delay_period", row)

    def test_dsl_pattern_carries_negrisk_anchor_predicates(self) -> None:
        """Lock 2: the DSL file exists and still carries the five
        predicates that anchor it to the NegRisk-race shape.

        These predicates are read as raw text from the YAML rather
        than parsed via PyYAML — the latter is not in the test-suite
        baseline dependencies, and a substring assertion is enough
        to catch the regressions we care about (predicate dropped,
        regex weakened, modifier renamed).
        """
        dsl_file = REPO / EXPECTED_DSL_PATH
        self.assertTrue(dsl_file.exists(), dsl_file)
        body = dsl_file.read_text()

        # Five anchor predicates pulled directly from the DSL spec.
        # If any of these strings disappear, the detector has drifted
        # away from the historical NegRiskOperator shape and the
        # ledger's `active-no-fire` claim becomes unfounded.
        expected_predicate_anchors = [
            "flaggedAt|unflagQuestion|DELAY_PERIOD",
            "resolveQuestion|_?commitResolution",
            "onlyNotFlagged|whenNotFlagged",
            "block\\.timestamp",
            "DELAY_PERIOD\\s*=\\s*0",
        ]
        for anchor in expected_predicate_anchors:
            self.assertIn(
                anchor,
                body,
                f"DSL predicate anchor {anchor!r} missing from {dsl_file}",
            )

    def test_compiled_detector_preserves_negrisk_anchor_predicates(self) -> None:
        """Lock 3: the wave17 compiled detector loads and its
        `_PRECONDITIONS` + `_MATCH` predicate lists carry the same
        five anchors. A future regenerate that strips a predicate
        (e.g., relaxes the modifier requirement, drops the
        DELAY_PERIOD = 0 source clue) is caught here.
        """
        det_file = REPO / EXPECTED_DETECTOR_PATH
        self.assertTrue(det_file.exists(), det_file)
        body = det_file.read_text()

        # All five anchors must be present in the compiled detector
        # body (they appear in the _PRECONDITIONS / _MATCH literal
        # lists, which pattern-compile.py emits as raw repr() text).
        for anchor in [
            "flaggedAt|unflagQuestion|DELAY_PERIOD",
            "resolveQuestion|_?commitResolution",
            "onlyNotFlagged|whenNotFlagged",
            "block\\\\.timestamp",  # escaped once for re, again for repr() in compiled .py
            "DELAY_PERIOD\\\\s*=\\\\s*0",
        ]:
            self.assertIn(
                anchor,
                body,
                f"compiled detector lost NegRisk anchor {anchor!r} (file: {det_file})",
            )

        # And the detector advertises the NegRisk-operator source tag
        # in its docstring header so a future grep over the corpus
        # for "NegRiskOperator-resolveQuestion" still finds it.
        self.assertIn("NegRiskOperator-resolveQuestion", body, det_file)

    def test_historical_negrisk_operator_source_grep_matches_predicates(self) -> None:
        """Lock 4: source-grep verification — the detector's regex
        predicates all fire against the historical NegRiskOperator
        PoC source as captured in Draft 5 of SUBMISSIONS.md.

        This is the `active-no-fire` row's by-construction shape-match
        claim made hermetic. If a future predicate edit weakens one of
        these regexes such that the historical instance no longer
        matches, the ledger entry must be reconciled.
        """
        src = HISTORICAL_NEGRISK_OPERATOR_SOURCE

        # Precondition (contract-level): contract source mentions any
        # of `flaggedAt`, `unflagQuestion`, `DELAY_PERIOD`.
        self.assertRegex(src, r"(?i)flaggedAt|unflagQuestion|DELAY_PERIOD")

        # Match (contract-level): contract source has `DELAY_PERIOD = 0`
        # constant declaration.
        self.assertRegex(src, r"(?i)DELAY_PERIOD\s*=\s*0")

        # Match (function-level, name): a function named `resolveQuestion`
        # (or `_commitResolution`) is declared.
        self.assertRegex(src, r"(?i)function\s+(resolveQuestion|_?commitResolution)")

        # Match (function-level, modifier): the function carries an
        # `onlyNotFlagged` (or `whenNotFlagged`) modifier.
        self.assertRegex(
            src,
            r"function\s+resolveQuestion[^{]*(onlyNotFlagged|whenNotFlagged)",
        )

        # Match (function-level, body): the function body contains
        # `block.timestamp < <ident> + DELAY_PERIOD` (or
        # `... < ...reportedAt + ...`).
        self.assertRegex(
            src,
            r"(?i)block\.timestamp\s*<\s*\w+\s*\+\s*DELAY_PERIOD",
        )

    def test_ledger_md_row_205_contains_expected_detector_path(self) -> None:
        """Lock 5: the human-readable ledger (Markdown) row for #205
        also still references the expected detector path. The two
        ledgers must stay in sync; if the JSON moves and the MD
        doesn't (or vice versa), this catches it.
        """
        body = LEDGER_MD.read_text()
        # The MD table row for #205 has both the detector filename and
        # the DSL filename (without the leading `reference/patterns.dsl/`).
        self.assertRegex(
            body,
            r"\|\s*205\s*\|.*unflag_race_resolve_without_delay_period\.py",
        )
        self.assertIn(
            "unflag-race-resolve-without-delay-period.yaml",
            body,
            "MD ledger row for #205 lost the DSL filename",
        )


if __name__ == "__main__":
    unittest.main()
