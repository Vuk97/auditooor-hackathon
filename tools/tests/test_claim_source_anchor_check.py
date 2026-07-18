"""Unit tests for Rule 61 Claim-Source-Anchor-Required gate (Check #108).

Covers all pass-* and fail-* verdicts, the rebuttal short-circuit, severity
discipline, plus the live empirical anchors:

  Test 1 (negative anchor): the Spark LEAD 1 v9 unanchored draft at
    /Users/wolf/audits/spark/submissions/staging/lead1_triager_reply_v9.md
    must verdict fail-unanchored-claim (forced High severity).
  Test 2 (positive anchor): the Spark LEAD 1 v10 anchored draft at
    /Users/wolf/audits/spark/submissions/staging/
      spark-coop-exit-lead1-v10-triager-response/
      spark-coop-exit-lead1-v10-triager-response.md
    must verdict pass-all-anchored (forced High to exercise the gate;
    in production it auto-resolves to Medium -> pass-out-of-scope, also
    a passing verdict).
  Test 3 (severity discipline): the Hyperbridge DRILL-9 Low draft at
    /Users/wolf/audits/hyperbridge/submissions/paste_ready/
      smt-eth-branch-isempty-value-conflation/
      smt-eth-branch-isempty-value-conflation.md
    must verdict pass-out-of-scope (severity below HIGH).
  Test 4 (synthetic mixed-anchor): a HIGH draft with 3 structural
    negations where 2 are anchored and 1 is not must verdict
    fail-unanchored-claim.
  Test 5 (synthetic fully-anchored): a HIGH draft with all structural
    negations anchored to file:line citations must verdict
    pass-all-anchored.
  Test 6 (rebuttal short-circuit): a HIGH draft with a visible
    r61-rebuttal marker must verdict ok-rebuttal regardless of unanchored
    negations.
"""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

_spec = importlib.util.spec_from_file_location(
    "claim_source_anchor_check",
    ROOT / "tools" / "claim-source-anchor-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


# Live empirical anchors (real files on disk).
LEAD1_V9_UNANCHORED_PATH = Path(
    "/Users/wolf/audits/spark/submissions/staging/"
    "lead1_triager_reply_v9.md"
)
LEAD1_V10_ANCHORED_PATH = Path(
    "/Users/wolf/audits/spark/submissions/staging/"
    "spark-coop-exit-lead1-v10-triager-response/"
    "spark-coop-exit-lead1-v10-triager-response.md"
)
DRILL9_LOW_PATH = Path(
    "/Users/wolf/audits/hyperbridge/submissions/paste_ready/"
    "smt-eth-branch-isempty-value-conflation/"
    "smt-eth-branch-isempty-value-conflation.md"
)


def _draft(body: str, filename: str = "draft-HIGH.md") -> Path:
    root = Path(tempfile.mkdtemp(prefix="r61_test_"))
    p = root / filename
    p.write_text(body, encoding="utf-8")
    return p


def _run(
    draft: Path,
    *,
    severity: str | None = None,
    strict: bool = False,
) -> tuple[int, dict]:
    return mod.run(draft, severity_override=severity, strict=strict)


# ---------------------------------------------------------------------------
# Test 1 — Live anchor: v9 unanchored (must fail-unanchored-claim)
# ---------------------------------------------------------------------------
class TestSparkLead1V9Unanchored(unittest.TestCase):
    """Empirical anchor: the v9 draft contains the load-bearing row-2 claim
    'QueryBroadcastableTransferLeaves unreachable because NodeConfirmationHeight
    stays NULL' without an inline file:line anchor in the same paragraph (the
    paragraph cites `(lines 154-189)` which lacks a file extension and is
    therefore not a recognized source anchor). R61 must catch this.
    """

    @unittest.skipUnless(
        LEAD1_V9_UNANCHORED_PATH.exists(),
        f"v9 anchor file missing: {LEAD1_V9_UNANCHORED_PATH}",
    )
    def test_v9_unanchored_fails(self) -> None:
        rc, payload = _run(LEAD1_V9_UNANCHORED_PATH, severity="High")
        self.assertEqual(
            rc, 1,
            msg=f"v9 anchor unexpectedly passed: {payload.get('reason')}",
        )
        self.assertEqual(payload["verdict"], "fail-unanchored-claim")
        ev = payload.get("evidence", {})
        self.assertGreater(
            ev.get("unanchored_count", 0), 0,
            msg="v9 must surface at least one unanchored structural negation",
        )


# ---------------------------------------------------------------------------
# Test 2 — Live anchor: v10 fully anchored (must pass-all-anchored at High)
# ---------------------------------------------------------------------------
class TestSparkLead1V10Anchored(unittest.TestCase):
    """Empirical anchor: v10 is the honest-concession walk-back. Every
    structural negation in v10 is paired with an inline file:line anchor.
    R61 must verdict pass-all-anchored (forced High to exercise the gate;
    in production v10 has Severity: Medium -> pass-out-of-scope, also a
    passing verdict).
    """

    @unittest.skipUnless(
        LEAD1_V10_ANCHORED_PATH.exists(),
        f"v10 anchor file missing: {LEAD1_V10_ANCHORED_PATH}",
    )
    def test_v10_anchored_passes_forced_high(self) -> None:
        rc, payload = _run(LEAD1_V10_ANCHORED_PATH, severity="High")
        self.assertEqual(
            rc, 0,
            msg=f"v10 anchor unexpectedly failed: {payload.get('reason')}\n"
                f"unanchored: {payload.get('evidence', {}).get('unanchored', [])[:3]}",
        )
        self.assertEqual(payload["verdict"], "pass-all-anchored")
        ev = payload.get("evidence", {})
        self.assertEqual(ev.get("unanchored_count", -1), 0)

    @unittest.skipUnless(
        LEAD1_V10_ANCHORED_PATH.exists(),
        f"v10 anchor file missing: {LEAD1_V10_ANCHORED_PATH}",
    )
    def test_v10_auto_severity_passes_oos(self) -> None:
        # v10 has <!-- Severity: Medium --> so auto-detect returns Medium ->
        # pass-out-of-scope (R61 only fires HIGH+).
        rc, payload = _run(LEAD1_V10_ANCHORED_PATH)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")


# ---------------------------------------------------------------------------
# Test 3 — Live anchor: DRILL-9 Low draft (must pass-out-of-scope)
# ---------------------------------------------------------------------------
class TestDrill9LowOutOfScope(unittest.TestCase):
    """Severity discipline: R61 only fires HIGH+. The Hyperbridge DRILL-9
    Low draft must auto-resolve to Low -> pass-out-of-scope.
    """

    @unittest.skipUnless(
        DRILL9_LOW_PATH.exists(),
        f"DRILL-9 anchor file missing: {DRILL9_LOW_PATH}",
    )
    def test_drill9_low_passes_oos(self) -> None:
        rc, payload = _run(DRILL9_LOW_PATH)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")


# ---------------------------------------------------------------------------
# Test 4 — Synthetic HIGH draft with 3 negations, 2 anchored, 1 unanchored
# ---------------------------------------------------------------------------
class TestSyntheticMixed(unittest.TestCase):

    def test_three_negations_two_anchored_one_not_fails(self) -> None:
        body = (
            "- Severity: High\n\n"
            "## Summary\n\n"
            "The vulnerable path is at `modules/foo/src/handler.rs:142` and "
            "the validation never executes for attacker-controlled input.\n\n"
            "## Analysis\n\n"
            "The defensive guard at `modules/foo/src/guard.rs:78` fails to "
            "fire when the input shape includes a nested call.\n\n"
            "## Edge case\n\n"
            "The protocol's recovery flow is unreachable in the attack "
            "model because the receiver wallet has no way to know.\n"
        )
        draft = _draft(body, filename="mixed-HIGH.md")
        rc, payload = _run(draft)
        self.assertEqual(rc, 1, msg=payload.get("reason"))
        self.assertEqual(payload["verdict"], "fail-unanchored-claim")
        ev = payload.get("evidence", {})
        self.assertEqual(ev.get("total_negation_scopes"), 3)
        self.assertEqual(ev.get("anchored_count"), 2)
        self.assertEqual(ev.get("unanchored_count"), 1)


# ---------------------------------------------------------------------------
# Test 5 — Synthetic HIGH draft with all negations anchored
# ---------------------------------------------------------------------------
class TestSyntheticFullyAnchored(unittest.TestCase):

    def test_all_anchored_passes(self) -> None:
        body = (
            "- Severity: High\n\n"
            "## Summary\n\n"
            "The vulnerable path is at `modules/foo/src/handler.rs:142` "
            "and the validation never executes for attacker-controlled "
            "input.\n\n"
            "## Analysis\n\n"
            "The defensive guard at `modules/foo/src/guard.rs:78` fails to "
            "fire when the input shape includes a nested call.\n\n"
            "## Edge case\n\n"
            "[src: modules/foo/src/recovery.rs:201-214] - the protocol's "
            "recovery flow is unreachable in the attack model because the "
            "receiver wallet has no way to know.\n"
        )
        draft = _draft(body, filename="fully-anchored-HIGH.md")
        rc, payload = _run(draft)
        self.assertEqual(rc, 0, msg=payload.get("reason"))
        self.assertEqual(payload["verdict"], "pass-all-anchored")
        ev = payload.get("evidence", {})
        self.assertEqual(ev.get("total_negation_scopes"), 3)
        self.assertEqual(ev.get("anchored_count"), 3)
        self.assertEqual(ev.get("unanchored_count"), 0)


# ---------------------------------------------------------------------------
# Test 6 — Rebuttal short-circuit
# ---------------------------------------------------------------------------
class TestRebuttal(unittest.TestCase):

    def test_html_comment_rebuttal_passes(self) -> None:
        body = (
            "- Severity: High\n\n"
            "## Summary\n\n"
            "The validation never executes; structurally blocked at the "
            "handler entrypoint.\n\n"
            "<!-- r61-rebuttal: this dispute draft quotes a prior round's "
            "unanchored claim verbatim and corrects it inline below -->\n"
        )
        draft = _draft(body, filename="rebuttal-HIGH.md")
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_visible_line_rebuttal_passes(self) -> None:
        body = (
            "- Severity: Critical\n\n"
            "## Summary\n\n"
            "The defensive path is unreachable in the attack model.\n\n"
            "r61-rebuttal: legitimately unanchored structural assertion; "
            "the source anchor is in the accompanying gist.\n"
        )
        draft = _draft(body, filename="rebuttal-CRIT.md")
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_oversized_rebuttal_ignored_then_fails(self) -> None:
        too_long = "x" * 250
        body = (
            "- Severity: High\n\n"
            "The validation never executes for the attacker case; "
            "structurally blocked at the handler entrypoint.\n\n"
            f"<!-- r61-rebuttal: {too_long} -->\n"
        )
        draft = _draft(body, filename="oversized-HIGH.md")
        rc, payload = _run(draft)
        # Oversized rebuttal is ignored -> fail-unanchored-claim path.
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-unanchored-claim")


# ---------------------------------------------------------------------------
# Supplementary: severity discipline, no-negations pass, rubric-context FP
# ---------------------------------------------------------------------------
class TestSeverityDiscipline(unittest.TestCase):

    def test_low_severity_skipped(self) -> None:
        body = (
            "- Severity: Low\n\n"
            "The validation never executes in the attack model.\n"
        )
        draft = _draft(body, filename="low-skipped.md")
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_medium_severity_skipped(self) -> None:
        body = (
            "- Severity: Medium\n\n"
            "The validation is unreachable; structurally blocked.\n"
        )
        draft = _draft(body, filename="med-skipped.md")
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_missing_severity_skipped(self) -> None:
        body = (
            "# Some finding\n\n"
            "The validation never executes.\n"
        )
        draft = _draft(body, filename="nosev.md")
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")


class TestNoStructuralAssertions(unittest.TestCase):

    def test_high_with_no_negations_passes(self) -> None:
        body = (
            "- Severity: High\n\n"
            "## Summary\n\n"
            "The handler at `modules/foo/src/handler.rs:142` accepts the "
            "attacker-controlled input and transitions state to FINALIZED.\n"
        )
        draft = _draft(body, filename="positive-only-HIGH.md")
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-no-structural-assertions")


class TestRubricContextFalsePositive(unittest.TestCase):
    """The 'does NOT apply' phrasing inside rubric-row-mapping tables refers
    to whether a RUBRIC ROW covers the finding, not codebase behavior. R61
    must not penalize these.
    """

    def test_rubric_row_does_not_apply_skipped(self) -> None:
        body = (
            "- Severity: High\n\n"
            "## Rubric Row Mapping (R52)\n\n"
            "- CRIT-1 'Direct loss of funds' - does NOT apply under the "
            "corrected analysis; receiver fund loss is not deterministic.\n"
            "- CRIT-2 'Permanent freezing' - does NOT apply; no permanent "
            "freeze.\n"
        )
        draft = _draft(body, filename="rubric-HIGH.md")
        rc, payload = _run(draft)
        # Rubric-row mapping negations are filtered; no structural claims
        # remain.
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-no-structural-assertions")


class TestHarnessCoverageFalsePositive(unittest.TestCase):

    def test_harness_did_not_exercise_skipped(self) -> None:
        body = (
            "- Severity: High\n\n"
            "## Coverage analysis\n\n"
            "The PoC harness exercised the Bitcoin layer but did not "
            "exercise the receiver wallet's auto-claim flow.\n"
        )
        draft = _draft(body, filename="harness-HIGH.md")
        rc, payload = _run(draft)
        # Harness-coverage negation is filtered.
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-no-structural-assertions")


class TestSrcBracketForm(unittest.TestCase):

    def test_src_bracket_form_anchors_claim(self) -> None:
        body = (
            "- Severity: High\n\n"
            "The validation never executes for the attacker case "
            "[src: modules/foo/src/guard.rs:42-58].\n"
        )
        draft = _draft(body, filename="srcbracket-HIGH.md")
        rc, payload = _run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-all-anchored")


class TestAdjacentBulletAnchorPropagates(unittest.TestCase):
    """R29/R42/R43/R57 sections often emit one bullet per blank-line-delimited
    paragraph. R61 must look at adjacent bullet siblings for anchors when the
    current paragraph is a single bullet."""

    def test_adjacent_bullet_anchor_propagates(self) -> None:
        body = (
            "- Severity: High\n\n"
            "## Load-Bearing Bytes Attribution\n\n"
            "- **Load-bearing artifact**: `node.RawRefundTx` post-claim bytes "
            "(the intermediate refund cannot broadcast in the attack model).\n\n"
            "- **Production site**: `spark/so/handler/transfer_handler.go:4457` "
            "installs the bytes.\n\n"
            "- **Required signers**: 2-of-2 FROST.\n"
        )
        draft = _draft(body, filename="adjacent-bullet-HIGH.md")
        rc, payload = _run(draft)
        self.assertEqual(
            rc, 0,
            msg=f"adjacent-bullet test failed: {payload.get('reason')}\n"
                f"unanchored: {payload.get('evidence', {}).get('unanchored', [])}",
        )
        self.assertEqual(payload["verdict"], "pass-all-anchored")


if __name__ == "__main__":
    unittest.main()
