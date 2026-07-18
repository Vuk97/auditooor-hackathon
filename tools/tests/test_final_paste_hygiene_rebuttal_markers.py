#!/usr/bin/env python3
"""Tests for Gap 18: FINAL-PASTE-HYGIENE rebuttal-marker whitelist.

The ``html_comment`` violation detector in
``tools/audit-closeout-check.py::_final_paste_hygiene_violations`` is too
strict: it rejects ALL HTML comments, but multiple codified R-rules (R20,
R22, R29, R43, ..., R58) and L-rules (L29, L30, L31, L32, L33, L34) accept
ONLY the HTML-comment form for in-draft rebuttal markers (e.g.
``<!-- r22-rebuttal: ... -->``). The closeout hygiene rule must whitelist
sanctioned rebuttal markers and auditooor-coordination markers, otherwise
every legitimate paste-ready that uses a rule-rebuttal trips a structural
false-fail on Check #43 in ``pre-submit-check.sh``.

Stdlib-only, hermetic via ``tempfile.TemporaryDirectory``. The module is
loaded via ``importlib`` because the script name contains a hyphen.
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "audit-closeout-check.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "audit_closeout_check_gap18", TOOL_PATH
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["audit_closeout_check_gap18"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


def _violations(text: str) -> list[dict]:
    """Run the hygiene detector against in-memory text via a temp file."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".md", delete=False, encoding="utf-8"
    ) as tf:
        tf.write(text)
        path = Path(tf.name)
    try:
        return MOD._final_paste_hygiene_violations(path)
    finally:
        path.unlink(missing_ok=True)


def _html_comment_kinds(text: str) -> list[str]:
    """Return the excerpts of just the html_comment violations."""
    return [
        row["excerpt"] for row in _violations(text)
        if row["kind"] == "html_comment"
    ]


class TestRebuttalMarkerWhitelist(unittest.TestCase):
    """Whitelisted rule-rebuttal markers MUST NOT be flagged as html_comment."""

    def test_r22_rebuttal_with_rust_generics_in_payload(self) -> None:
        # The DRILL-6 anchor: r22-rebuttal with Rust generics (`Fees::<T>`)
        # in the payload. Pre-fix, the `[^>]` constraint in the whitelist
        # regex would reject the `<T>` and treat it as a violation.
        text = (
            "# draft\n\n"
            "<!-- r22-rebuttal: structural on-chain state corruption "
            "(Fees::<T> entry zeroed via withdrawal.rs:178 + truncated u128 "
            "dispatched at withdrawal.rs:139), not a process-restart-fixable "
            "race; persistence is inherent to substrate storage commitment - "
            "no restart heals the zeroed Fees entry. -->\n"
        )
        self.assertEqual([], _html_comment_kinds(text))

    def test_r24_rebuttal(self) -> None:
        text = "<!-- r24-rebuttal: non-self impact via validator-cluster halt. -->\n"
        self.assertEqual([], _html_comment_kinds(text))

    def test_r25_rebuttal(self) -> None:
        text = (
            "<!-- r25-rebuttal: Honest walk-back disclosure: race "
            "structurally rejected on production-profile. -->\n"
        )
        self.assertEqual([], _html_comment_kinds(text))

    def test_r29_rebuttal(self) -> None:
        text = (
            "<!-- r29-rebuttal: protection cardinality of 1; commit point at "
            "watch_chain.go:1309 is irreversible; gap is POST-commit. -->\n"
        )
        self.assertEqual([], _html_comment_kinds(text))

    def test_r40_rebuttal(self) -> None:
        text = (
            "<!-- r40-rebuttal: V3-grade unblocked; mocks only stand in for "
            "external dependencies. -->\n"
        )
        self.assertEqual([], _html_comment_kinds(text))

    def test_r43_rebuttal(self) -> None:
        text = (
            "<!-- r43-rebuttal: load-bearing bytes attributed to FROST share; "
            "attacker IS in 2-of-2 signer set. -->\n"
        )
        self.assertEqual([], _html_comment_kinds(text))

    def test_r57_rebuttal(self) -> None:
        text = (
            "<!-- r57-rebuttal: single-defense protocol; only one defense "
            "call site exists in the defender codebase. -->\n"
        )
        self.assertEqual([], _html_comment_kinds(text))

    def test_l29_rebuttal(self) -> None:
        text = (
            "<!-- l29-rebuttal: title-impact-vs-evidence mismatch was a "
            "synonym normalization; PoC transcript covers both rows. -->\n"
        )
        self.assertEqual([], _html_comment_kinds(text))

    def test_l32_rebuttal(self) -> None:
        text = (
            "<!-- l32-rebuttal: v3 PoC runs on real goleveldb backend with "
            "rootmulti production restore path; production-grade per "
            "in-process-vs-node-level discipline. -->\n"
        )
        self.assertEqual([], _html_comment_kinds(text))

    def test_l34_rebuttal(self) -> None:
        text = (
            "<!-- l34-rebuttal: operator authorised batch-edit naming "
            "this specific draft 2026-05-25. -->\n"
        )
        self.assertEqual([], _html_comment_kinds(text))


class TestNamedRebuttalMarkers(unittest.TestCase):
    """Named-rebuttal markers (non-numeric) MUST NOT be flagged."""

    def test_reachability_rebuttal(self) -> None:
        text = (
            "<!-- reachability-rebuttal: production-config trace at "
            "config.go:142 confirms registration. -->\n"
        )
        self.assertEqual([], _html_comment_kinds(text))

    def test_config_downstream_rebuttal(self) -> None:
        text = (
            "<!-- config-downstream-rebuttal: downstream consumer is the "
            "default registered router at register.go:88. -->\n"
        )
        self.assertEqual([], _html_comment_kinds(text))

    def test_opposed_trace_rebuttal(self) -> None:
        text = (
            "<!-- opposed-trace-rebuttal: single-actor harness because the "
            "attacker model is the validator itself. -->\n"
        )
        self.assertEqual([], _html_comment_kinds(text))

    def test_operator_action_rebuttal(self) -> None:
        text = (
            "<!-- operator-action-rebuttal: operator confirmed paste-time "
            "in PR-thread review on 2026-05-25. -->\n"
        )
        self.assertEqual([], _html_comment_kinds(text))

    def test_auditooor_tracker_rebuttal(self) -> None:
        text = (
            "<!-- auditooor-tracker-rebuttal: tracker append authorised "
            "via Wave-N batch-sweep. -->\n"
        )
        self.assertEqual([], _html_comment_kinds(text))

    def test_severity_calibration_rebuttal(self) -> None:
        # REQUIRED by severity-calibration-check.py:102 to green a bounded,
        # source-backed calibration exception. Pre-fix this marker and the
        # hygiene gate were mutually exclusive - any finding earning the
        # calibration rebuttal could never pass both #43 and #71.
        text = (
            "<!-- severity-calibration-rebuttal: single-node consensus-halt "
            "PoC; net-level exceedance extrapolated, tier held at "
            "SEVERITY.md:92 Temporary-freeze. -->\n"
        )
        self.assertEqual([], _html_comment_kinds(text))

    def test_oos_natural_activity_rebuttal(self) -> None:
        # REQUIRED by per-finding-oos-check.py:314 to prove a bug despite
        # natural-activity keyword false-positives. Same mutual-exclusion
        # class as severity-calibration (gate #77 demands it, #43 forbade it).
        text = (
            "<!-- oos-natural-activity-rebuttal: the begin-blocker queue walk "
            "is protocol-internal consensus work, not permissionless user "
            "activity; the OOS clause is refuted in-section. -->\n"
        )
        self.assertEqual([], _html_comment_kinds(text))


class TestAuditooorCoordinationMarkers(unittest.TestCase):
    """AUDITOOOR_* coordination markers MUST NOT be flagged."""

    def test_tracker_managed_start(self) -> None:
        text = "<!-- AUDITOOOR_TRACKER_MANAGED_START -->\n... -->\n"
        # Only the START marker should pass; the closing literal "... -->\n"
        # is not a real marker but the START one MUST be whitelisted.
        kinds = _html_comment_kinds(text)
        self.assertFalse(
            any("AUDITOOOR_TRACKER_MANAGED_START" in e for e in kinds),
            f"AUDITOOOR_TRACKER_MANAGED_START got flagged: {kinds}",
        )

    def test_tracker_managed_end(self) -> None:
        text = "<!-- AUDITOOOR_TRACKER_MANAGED_END -->\n"
        self.assertEqual([], _html_comment_kinds(text))

    def test_pr_managed_start(self) -> None:
        text = "<!-- AUDITOOOR_PR_MANAGED_START -->\n"
        self.assertEqual([], _html_comment_kinds(text))


class TestStrayCommentsStillRejected(unittest.TestCase):
    """Genuine paste-hygiene violations must STILL be flagged after the
    whitelist change. Without these control cases, a regression could
    silently whitelist every HTML comment."""

    def test_inline_todo_comment(self) -> None:
        text = "Some prose.\n\n<!-- TODO: fix this before paste -->\n"
        kinds = _html_comment_kinds(text)
        self.assertEqual(1, len(kinds), f"expected 1 violation, got {kinds}")
        self.assertIn("TODO", kinds[0])

    def test_internal_workflow_note(self) -> None:
        text = "<!-- claude-internal-note: skip rubric check this round -->\n"
        kinds = _html_comment_kinds(text)
        self.assertEqual(1, len(kinds))

    def test_html_section_break(self) -> None:
        # Used by some operators to break content; should still be flagged
        # as a hygiene leak from local templating.
        text = "<!-- === SECTION BREAK === -->\n"
        kinds = _html_comment_kinds(text)
        self.assertEqual(1, len(kinds))

    def test_orchestrator_pointer(self) -> None:
        text = (
            "<!-- agent_outputs/swarm/RE-12 -->\n"
            "<!-- worker-NN sub-agent reply preserved here -->\n"
        )
        kinds = _html_comment_kinds(text)
        self.assertEqual(2, len(kinds))

    def test_empty_html_comment(self) -> None:
        text = "<!-- -->\n"
        kinds = _html_comment_kinds(text)
        self.assertEqual(1, len(kinds))

    def test_rule_rebuttal_with_empty_payload_still_rejected(self) -> None:
        # Empty-payload rebuttals are not honored by rule-side gates per the
        # codified contract (CLAUDE.md: "Empty or oversized reason is
        # ignored; original fail verdict stands."). The hygiene detector
        # should reject them too so the operator gets visible feedback.
        text = "<!-- r22-rebuttal: -->\n"
        kinds = _html_comment_kinds(text)
        self.assertEqual(
            1, len(kinds),
            "empty-payload rebuttal MUST still be flagged; rule-side gate "
            "ignores it, so hygiene gate should not silently whitelist it",
        )

    def test_unknown_rebuttal_kind_still_rejected(self) -> None:
        # Whitelist is keyed to known rule numbers + named markers only;
        # invented kinds (e.g. `foo-rebuttal`) must still be flagged so we
        # don't grandfather typos into the whitelist.
        text = "<!-- foo-rebuttal: invented marker, should fail -->\n"
        kinds = _html_comment_kinds(text)
        self.assertEqual(1, len(kinds))


class TestCoexistenceWithOtherCheckers(unittest.TestCase):
    """The hygiene check still flags other violation kinds independently
    of the html_comment whitelist."""

    def test_rebuttal_with_local_path_still_flags_path(self) -> None:
        # If a draft has BOTH a whitelisted rebuttal AND a separate local
        # path leak, the rebuttal passes but the path is flagged.
        text = (
            "<!-- r22-rebuttal: legitimate rebuttal text. -->\n\n"
            "## Evidence\n\n"
            "See /Users/wolf/audits/x/poc.go for the assertion.\n"
        )
        violations = _violations(text)
        kinds = {row["kind"] for row in violations}
        self.assertIn("local_absolute_path", kinds)
        self.assertNotIn("html_comment", kinds)

    def test_multiple_rebuttals_all_pass(self) -> None:
        text = (
            "<!-- r22-rebuttal: structural state corruption. -->\n"
            "<!-- r24-rebuttal: non-self impact. -->\n"
            "<!-- r25-rebuttal: defense traversal walk-back. -->\n"
            "<!-- r43-rebuttal: load-bearing-bytes attributed. -->\n"
        )
        self.assertEqual([], _html_comment_kinds(text))

    def test_whitelist_constant_is_exported(self) -> None:
        # Discoverability requirement from the lane brief: the whitelist
        # must be a module-level constant so future engineers can find it.
        self.assertTrue(
            hasattr(MOD, "_PASTE_HYGIENE_ALLOWED_COMMENT_RE"),
            "whitelist regex must be exported as a module-level constant",
        )


if __name__ == "__main__":
    unittest.main()
