#!/usr/bin/env python3
"""Tests for the `pre-submit-llm-review` engage stage.

Hermetic: no live API, no `gh` invocation, no real LLM dispatch. The
``tools/llm-scope-triage.py`` subprocess hook is monkey-patched on the loaded
module so each test exercises a specific branch of the consensus mapper and
the stage-status classifier.

Coverage:
  1. ``_classify_pre_submit_llm_outcomes`` — pure classifier branches:
       SUCCESS / SUCCESS_WARN (DISAGREED) /
       SUCCESS_WARN (AGREED-OFF-SCOPE, advisory default) /
       FAIL (AGREED-OFF-SCOPE, future opt-in hard-block) /
       SUCCESS_WARN (no drafts) / SKIPPED (all dispatch failed).
  2. ``_scope_triage_consensus_to_label`` — maps the standalone tool's
     consensus dict to the engage-stage vocabulary
     (AGREED-IN-SCOPE / AGREED-OFF-SCOPE / DISAGREED / LLM-FAILURE).
  3. Stage walks ``submissions/staging/*.md`` and writes per-draft
     artefacts under ``submissions/llm_review/draft_<slug>.json``.
  4. Stage SUCCESS_WARN when no drafts.
  5. Stage SKIPPED when ``llm-scope-triage.py`` is missing.
  6. Stage classifies a mocked AGREED-OFF-SCOPE consensus as SUCCESS_WARN
     (advisory default — Codex HOLD on PR #227); a separate test verifies
     the future opt-in hard-block path via the
     ``PRE_SUBMIT_LLM_HARD_BLOCK_AGREED_OFF_SCOPE`` constant.
  7. Stage delegates calibration to the standalone tool and does NOT log
     calibration rows itself with the (wrong) ``pr-review`` task-type or
     a TRUE/FALSE verdict mapping (Codex P0 #2 regression guard).

Test inputs are NEUTRAL synthetic drafts (no comment-leakage from real PRs).
"""
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "engage.py"


def _load_engage():
    """Import tools/engage.py as a module (cached on sys.modules).

    `engage.py` imports `submission_paths` from its sibling tools/ directory,
    so we must put tools/ on sys.path before exec_module — otherwise the
    submodule import would silently no-op the rest of the file.
    """
    cache_key = "_engage_module_for_pre_submit_llm_test"
    if cache_key in sys.modules:
        return sys.modules[cache_key]
    tools_dir = str(TOOL.parent)
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    spec = importlib.util.spec_from_file_location(cache_key, TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[cache_key] = mod
    spec.loader.exec_module(mod)
    return mod


def _make_args(quiet: bool = True) -> SimpleNamespace:
    return SimpleNamespace(quiet=quiet)


def _write_draft(staging: Path, name: str, body: str = "Test draft body") -> Path:
    staging.mkdir(parents=True, exist_ok=True)
    p = staging / name
    p.write_text(body, encoding="utf-8")
    return p


class ClassifierTest(unittest.TestCase):
    """_classify_pre_submit_llm_outcomes covers all four mapped statuses."""

    def setUp(self) -> None:
        self.mod = _load_engage()

    def test_no_drafts_yields_success_warn(self) -> None:
        status = self.mod._classify_pre_submit_llm_outcomes([])
        self.assertTrue(status.startswith("SUCCESS_WARN"))
        self.assertIn("no drafts", status)

    def test_all_in_scope_yields_success(self) -> None:
        status = self.mod._classify_pre_submit_llm_outcomes(
            ["AGREED-IN-SCOPE", "AGREED-IN-SCOPE"]
        )
        self.assertTrue(status.startswith("SUCCESS"))
        self.assertNotIn("WARN", status)
        self.assertIn("AGREED-IN-SCOPE", status)

    def test_any_disagreed_yields_success_warn(self) -> None:
        status = self.mod._classify_pre_submit_llm_outcomes(
            ["AGREED-IN-SCOPE", "DISAGREED", "AGREED-IN-SCOPE"]
        )
        self.assertTrue(status.startswith("SUCCESS_WARN"))
        self.assertIn("DISAGREED", status)

    def test_any_off_scope_yields_advisory_success_warn(self) -> None:
        # Default (advisory) behaviour per Codex HOLD on PR #227: a single
        # AGREED-OFF-SCOPE row is NOT enough calibration evidence to hard-
        # block `track-submissions`. Surface it as SUCCESS_WARN so the
        # operator sees the warning while the per-draft artefact + scope-
        # triage ledger row still land for human review.
        status = self.mod._classify_pre_submit_llm_outcomes(
            ["AGREED-IN-SCOPE", "AGREED-OFF-SCOPE", "DISAGREED"]
        )
        self.assertTrue(status.startswith("SUCCESS_WARN"))
        self.assertIn("AGREED-OFF-SCOPE", status)
        self.assertIn("advisory", status)
        # Sanity: default constant is False so the hard-block path stays off.
        self.assertFalse(self.mod.PRE_SUBMIT_LLM_HARD_BLOCK_AGREED_OFF_SCOPE)

    def test_any_off_scope_yields_fail_when_hard_block_enabled(self) -> None:
        # Future opt-in hard-block: when calibration matures, flipping the
        # ``PRE_SUBMIT_LLM_HARD_BLOCK_AGREED_OFF_SCOPE`` constant restores
        # the original FAIL semantics. This test guards that opt-in path so
        # we can roll it forward without re-deriving the classifier.
        with patch.object(
            self.mod, "PRE_SUBMIT_LLM_HARD_BLOCK_AGREED_OFF_SCOPE", True
        ):
            status = self.mod._classify_pre_submit_llm_outcomes(
                ["AGREED-IN-SCOPE", "AGREED-OFF-SCOPE", "DISAGREED"]
            )
        self.assertTrue(status.startswith("FAIL"))
        self.assertIn("AGREED-OFF-SCOPE", status)

    def test_all_dispatch_failure_yields_skipped(self) -> None:
        status = self.mod._classify_pre_submit_llm_outcomes(
            ["LLM-FAILURE", "LLM-FAILURE"]
        )
        self.assertTrue(status.startswith("SKIPPED"))
        self.assertIn("dispatch unavailable", status)

    def test_partial_dispatch_failure_yields_success_warn(self) -> None:
        status = self.mod._classify_pre_submit_llm_outcomes(
            ["AGREED-IN-SCOPE", "LLM-FAILURE"]
        )
        # One dispatch failed but a healthy AGREED-IN-SCOPE remains, so
        # don't pretend the chain saw nothing — surface a warning.
        self.assertTrue(status.startswith("SUCCESS_WARN"))


class ConsensusMapperTest(unittest.TestCase):
    """``_scope_triage_consensus_to_label`` maps standalone consensus dicts."""

    def setUp(self) -> None:
        self.mod = _load_engage()

    def test_high_confidence_in_scope(self) -> None:
        c = {"scope": "IN_SCOPE", "severity": "Medium", "confidence": "HIGH"}
        self.assertEqual(
            self.mod._scope_triage_consensus_to_label(c), "AGREED-IN-SCOPE"
        )

    def test_medium_confidence_in_scope(self) -> None:
        c = {"scope": "IN_SCOPE", "severity": "Low", "confidence": "MEDIUM"}
        self.assertEqual(
            self.mod._scope_triage_consensus_to_label(c), "AGREED-IN-SCOPE"
        )

    def test_high_confidence_oos_tag(self) -> None:
        c = {"scope": "OOS_MO_3", "severity": None, "confidence": "HIGH"}
        self.assertEqual(
            self.mod._scope_triage_consensus_to_label(c), "AGREED-OFF-SCOPE"
        )

    def test_disagreed_consensus(self) -> None:
        c = {"scope": "IN_SCOPE", "severity": None, "confidence": "DISAGREED"}
        self.assertEqual(
            self.mod._scope_triage_consensus_to_label(c), "DISAGREED"
        )

    def test_low_confidence_promotes_to_disagreed(self) -> None:
        # LOW confidence is not actionable as a hard block — surface as
        # DISAGREED so a human reviews before track-submissions.
        c = {"scope": "OOS_X_1", "severity": None, "confidence": "LOW"}
        self.assertEqual(
            self.mod._scope_triage_consensus_to_label(c), "DISAGREED"
        )

    def test_missing_consensus_yields_llm_failure(self) -> None:
        self.assertEqual(
            self.mod._scope_triage_consensus_to_label(None), "LLM-FAILURE"
        )
        self.assertEqual(
            self.mod._scope_triage_consensus_to_label({}), "LLM-FAILURE"
        )

    def test_both_providers_failed_yields_llm_failure(self) -> None:
        # Standalone tool reports DISAGREED when scope tag is missing on
        # one or both sides. If BOTH errored we promote to LLM-FAILURE so
        # SKIPPED is reachable in offline test envs.
        c = {"scope": None, "severity": None, "confidence": "DISAGREED"}
        errors = [
            "kimi-failed: dispatch rc=127",
            "minimax-failed: dispatch rc=127",
        ]
        self.assertEqual(
            self.mod._scope_triage_consensus_to_label(c, errors=errors),
            "LLM-FAILURE",
        )


class StageWalksDraftsTest(unittest.TestCase):
    """The stage walks staging drafts and produces per-draft artefacts."""

    def setUp(self) -> None:
        self.mod = _load_engage()

    def test_no_drafts_returns_success_warn(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "fake-engagement"
            (ws / "submissions").mkdir(parents=True)
            status = self.mod.stage_pre_submit_llm_review(ws, _make_args())
            self.assertTrue(status.startswith("SUCCESS_WARN"))
            self.assertIn("no drafts", status)

    def test_scope_triage_missing_yields_skipped(self) -> None:
        """When ``llm-scope-triage.py`` does not exist on disk, the stage
        degrades to SKIPPED rather than blocking the chain."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "fake-engagement"
            staging = ws / "submissions" / "staging"
            _write_draft(staging, "F-001-test.md", body="Synthetic finding A.")
            _write_draft(staging, "F-002-test.md", body="Synthetic finding B.")
            with patch.object(
                self.mod,
                "LLM_SCOPE_TRIAGE",
                Path("/nonexistent/llm-scope-triage.py"),
            ):
                status = self.mod.stage_pre_submit_llm_review(ws, _make_args())
            self.assertTrue(status.startswith("SKIPPED"))

    def test_dispatch_failure_yields_skipped(self) -> None:
        """When ``llm-scope-triage.py`` exists but every invocation returns
        rc!=0 with no artefact (offline test env), the stage degrades to
        SKIPPED rather than blocking."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "fake-engagement"
            staging = ws / "submissions" / "staging"
            _write_draft(staging, "F-001-test.md", body="Synthetic finding A.")
            _write_draft(staging, "F-002-test.md", body="Synthetic finding B.")

            def fake_invoke(*a, **kw):
                # rc=127 (missing tool / dispatch fail) and no artefact
                # written — every draft surfaces as LLM-FAILURE, the
                # classifier promotes that to SKIPPED.
                return 127, "", "scope-triage missing api keys"

            with patch.object(self.mod, "LLM_SCOPE_TRIAGE", TOOL), \
                 patch.object(self.mod, "_invoke_scope_triage",
                              side_effect=fake_invoke):
                status = self.mod.stage_pre_submit_llm_review(ws, _make_args())
            self.assertTrue(status.startswith("SKIPPED"))

    def test_agreed_off_scope_consensus_yields_advisory_success_warn(self) -> None:
        """Mock the scope-triage subprocess to write a per-finding artefact
        whose consensus is HIGH-confidence OOS — verify the stage surfaces
        that as advisory SUCCESS_WARN (Codex HOLD on PR #227 — scope-triage
        calibration ledger has only 1 row, hard-blocking is unsafe) and
        still writes the per-draft artefact under
        submissions/llm_review/."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "fake-engagement"
            staging = ws / "submissions" / "staging"
            _write_draft(staging, "F-003-bad.md", body="Out-of-scope draft.")

            def fake_invoke(draft, *, engagement, engage_root, output_dir, timeout):
                # Mimic what tools/llm-scope-triage.py would write: one
                # artefact per finding, deterministic name.
                output_dir.mkdir(parents=True, exist_ok=True)
                rec = {
                    "finding_path": str(draft),
                    "engagement": engagement,
                    "providers": ["kimi", "minimax"],
                    "verdicts": {
                        "kimi": {"scope": "OOS_FE_1", "severity": "Low",
                                 "confidence": "HIGH"},
                        "minimax": {"scope": "OOS_FE_1", "severity": "Low",
                                    "confidence": "HIGH"},
                    },
                    "consensus": {
                        "scope": "OOS_FE_1",
                        "severity": "Low",
                        "confidence": "HIGH",
                        "reason": "scope-and-severity-agreed-with-HIGH",
                    },
                    "errors": [],
                    "prompt_hash": "abc123" * 6,
                }
                art_name = (
                    f"triage-{engagement}-{draft.stem}-"
                    f"{rec['prompt_hash'][:12]}.json"
                )
                (output_dir / art_name).write_text(
                    json.dumps(rec, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                return 0, "", ""

            with patch.object(self.mod, "LLM_SCOPE_TRIAGE", TOOL), \
                 patch.object(self.mod, "_invoke_scope_triage",
                              side_effect=fake_invoke):
                status = self.mod.stage_pre_submit_llm_review(ws, _make_args())
            # Default (advisory) behaviour: SUCCESS_WARN with the OFF-SCOPE
            # count surfaced. The future opt-in FAIL path is exercised
            # in ClassifierTest.test_any_off_scope_yields_fail_when_hard_block_enabled.
            self.assertTrue(status.startswith("SUCCESS_WARN"))
            self.assertIn("AGREED-OFF-SCOPE", status)
            self.assertIn("advisory", status)
            artefact = ws / "submissions" / "llm_review" / "draft_F-003-bad.json"
            self.assertTrue(
                artefact.is_file(),
                f"per-draft artefact not written: {artefact}",
            )
            payload = json.loads(artefact.read_text(encoding="utf-8"))
            self.assertEqual(payload["consensus"], "AGREED-OFF-SCOPE")
            self.assertEqual(payload["engagement"], "fake-engagement")
            self.assertIsNotNone(payload.get("scope_triage_artefact"))


class CalibrationDelegationTest(unittest.TestCase):
    """Codex P0 #2 regression guard.

    Before this PR, the engage stage logged calibration rows itself with
    ``task_type=pr-review`` and a mechanical
    ``IN-SCOPE -> TRUE / OFF-SCOPE -> FALSE`` mapping BEFORE any human
    verification. That polluted the calibration ledger (same trap PR #198
    backfilled, but for SCOPE not PR-review).

    The fix: the stage delegates calibration to ``tools/llm-scope-triage.py``,
    which writes ``task_type=scope-triage`` + verdict ``INDETERMINATE``.
    These tests assert:
      * the engage stage does NOT log calibration rows itself
        (no direct invocation of ``llm-calibration-log.py log`` from the
        stage's subprocess.run calls);
      * the standalone tool, when invoked, IS expected to emit
        ``scope-triage``/``INDETERMINATE`` rows (verified separately by
        ``test_llm_scope_triage.py``).
    """

    def setUp(self) -> None:
        self.mod = _load_engage()

    def test_stage_does_not_invoke_calibration_log_directly(self) -> None:
        """The stage itself must not call ``llm-calibration-log.py`` — that
        responsibility lives in ``tools/llm-scope-triage.py``. We assert by
        wiring the scope-triage subprocess hook AND a sentinel
        ``subprocess.run`` patch that fails any call to the calibration
        CLI."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "fake-engagement"
            staging = ws / "submissions" / "staging"
            _write_draft(staging, "F-100-cal.md", body="Calibration probe.")

            calibration_calls: list[list] = []

            real_run = self.mod.subprocess.run

            def sentinel_run(cmd, *a, **kw):  # pragma: no cover - sentinel
                # If the engage stage ever calls llm-calibration-log.py
                # directly, capture the cmdline so the test can assert
                # against it.
                cmd_str = " ".join(str(x) for x in (cmd or []))
                if "llm-calibration-log.py" in cmd_str:
                    calibration_calls.append(list(cmd))
                return real_run(cmd, *a, **kw)

            def fake_invoke(draft, *, engagement, engage_root, output_dir, timeout):
                output_dir.mkdir(parents=True, exist_ok=True)
                rec = {
                    "finding_path": str(draft),
                    "engagement": engagement,
                    "consensus": {
                        "scope": "IN_SCOPE",
                        "severity": "Medium",
                        "confidence": "HIGH",
                        "reason": "ok",
                    },
                    "errors": [],
                    "prompt_hash": "deadbeef" * 8,
                }
                (output_dir / f"triage-{engagement}-{draft.stem}-"
                              f"{rec['prompt_hash'][:12]}.json").write_text(
                    json.dumps(rec, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                return 0, "", ""

            with patch.object(self.mod, "LLM_SCOPE_TRIAGE", TOOL), \
                 patch.object(self.mod, "_invoke_scope_triage",
                              side_effect=fake_invoke), \
                 patch.object(self.mod.subprocess, "run",
                              side_effect=sentinel_run):
                self.mod.stage_pre_submit_llm_review(ws, _make_args())

            self.assertEqual(
                calibration_calls,
                [],
                "engage stage must not invoke llm-calibration-log.py "
                "directly — that responsibility lives in "
                "tools/llm-scope-triage.py (Codex P0 #2 regression).",
            )

    def test_no_pr_review_task_type_helper_exists(self) -> None:
        """The buggy ``_log_pre_submit_calibration`` helper that logged
        ``task_type=pr-review`` and mapped IN-SCOPE/OFF-SCOPE to TRUE/FALSE
        before human verification has been removed. This is a regression
        guard against re-introducing it."""
        self.assertFalse(
            hasattr(self.mod, "_log_pre_submit_calibration"),
            "stage should NOT define _log_pre_submit_calibration anymore — "
            "calibration logging is delegated to tools/llm-scope-triage.py "
            "with the correct task_type=scope-triage + INDETERMINATE verdict "
            "(Codex P0 #2).",
        )

    def test_scope_triage_subprocess_invoked_with_engagement_context(self) -> None:
        """The stage must pass the engagement name + engage-root to
        ``llm-scope-triage.py`` so the standalone tool can locate
        ``OOS_CHECKLIST.md`` and ``SEVERITY_CAPS.md`` (Codex P0 #1).
        """
        import tempfile
        captured: list[dict] = []
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "morpho-fake"
            staging = ws / "submissions" / "staging"
            _write_draft(staging, "F-200-scope.md", body="Probe.")

            def fake_invoke(draft, *, engagement, engage_root, output_dir, timeout):
                captured.append({
                    "draft": str(draft),
                    "engagement": engagement,
                    "engage_root": str(engage_root),
                })
                output_dir.mkdir(parents=True, exist_ok=True)
                rec = {
                    "consensus": {
                        "scope": "IN_SCOPE", "severity": "High",
                        "confidence": "HIGH", "reason": "ok",
                    },
                    "errors": [],
                    "prompt_hash": "ff" * 16,
                }
                (output_dir / f"triage-{engagement}-{draft.stem}-"
                              f"{rec['prompt_hash'][:12]}.json").write_text(
                    json.dumps(rec, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                return 0, "", ""

            with patch.object(self.mod, "LLM_SCOPE_TRIAGE", TOOL), \
                 patch.object(self.mod, "_invoke_scope_triage",
                              side_effect=fake_invoke):
                self.mod.stage_pre_submit_llm_review(ws, _make_args())

        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0]["engagement"], "morpho-fake")
        # engage-root is the ws's parent (the enclosing audits/ tree).
        self.assertEqual(
            captured[0]["engage_root"], str(ws.parent),
        )


class StageRegistrationTest(unittest.TestCase):
    """The stage is wired into STAGES, STAGE_TABLE, and SUMMARY_ARTIFACT_PATTERNS."""

    def setUp(self) -> None:
        self.mod = _load_engage()

    def test_stage_registered_in_stages_tuple(self) -> None:
        self.assertIn("pre-submit-llm-review", self.mod.STAGES)

    def test_stage_position_after_pre_submit_before_track(self) -> None:
        names = [n for n, _, _ in self.mod.STAGE_TABLE]
        self.assertIn("pre-submit-llm-review", names)
        # pre-submit must come before pre-submit-llm-review (cheap
        # 22-check fail-fast first); pre-submit-llm-review must come
        # before track-submissions (so OFF-SCOPE never reaches the
        # submission ledger close-out).
        idx_pre  = names.index("pre-submit")
        idx_llm  = names.index("pre-submit-llm-review")
        idx_track = names.index("track-submissions")
        self.assertLess(idx_pre, idx_llm)
        self.assertLess(idx_llm, idx_track)


if __name__ == "__main__":
    unittest.main()
