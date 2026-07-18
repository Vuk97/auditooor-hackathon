#!/usr/bin/env python3
"""Tests for tools/llm-pr-review.py — dual-LLM PR review pipeline.

Hermetic: no live API, no `gh` invocation. The provider abstraction is
exercised through `subprocess.run` mocks. Test inputs are NEUTRAL diffs and
NEUTRAL responses — no real PR comment text is reused as a fixture, to avoid
comment-leakage in artefact replay.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import unittest
from unittest.mock import patch, MagicMock

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "llm-pr-review.py"


def _load_module():
    """Import the hyphenated tool as a module."""
    spec = importlib.util.spec_from_file_location("llm_pr_review", TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class VerdictParserTest(unittest.TestCase):
    """parse_verdict handles all 4 categories + malformed input."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_parse_merge_ok(self) -> None:
        out = "VERDICT: MERGE-OK\nRATIONALE: Looks fine, single-line tweak."
        v, r = self.mod.parse_verdict(out)
        self.assertEqual(v, "MERGE-OK")
        self.assertIn("Looks fine", r)

    def test_parse_needs_fix(self) -> None:
        out = "VERDICT: NEEDS-FIX\nRATIONALE: Off-by-one in the bounds check."
        v, r = self.mod.parse_verdict(out)
        self.assertEqual(v, "NEEDS-FIX")
        self.assertIn("Off-by-one", r)

    def test_parse_needs_rework(self) -> None:
        out = "VERDICT: NEEDS-REWORK\nRATIONALE: Algorithmic approach is wrong."
        v, r = self.mod.parse_verdict(out)
        self.assertEqual(v, "NEEDS-REWORK")

    def test_parse_off_scope(self) -> None:
        out = "VERDICT: OFF-SCOPE\nRATIONALE: Touches unrelated config files."
        v, r = self.mod.parse_verdict(out)
        self.assertEqual(v, "OFF-SCOPE")

    def test_parse_lowercase_verdict_normalised(self) -> None:
        # Regex is case-insensitive but verdict is normalised upper.
        out = "verdict: merge-ok\nrationale: tiny diff."
        v, r = self.mod.parse_verdict(out)
        self.assertEqual(v, "MERGE-OK")

    def test_parse_malformed_returns_none(self) -> None:
        out = "I think this looks reasonable but I can't be sure."
        v, r = self.mod.parse_verdict(out)
        self.assertIsNone(v)
        self.assertIn("looks reasonable", r)

    def test_parse_empty_returns_none(self) -> None:
        v, r = self.mod.parse_verdict("")
        self.assertIsNone(v)

    def test_parse_verdict_with_extra_prose(self) -> None:
        out = (
            "Sure, here is my review.\n"
            "VERDICT: NEEDS-FIX\n"
            "RATIONALE: Two callsites missed the rename.\n"
        )
        v, r = self.mod.parse_verdict(out)
        self.assertEqual(v, "NEEDS-FIX")
        self.assertIn("missed the rename", r)


class ConsensusTest(unittest.TestCase):
    """compute_consensus reduces per-provider verdicts correctly."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_both_agree_merge(self) -> None:
        c = self.mod.compute_consensus({"kimi": "MERGE-OK", "minimax": "MERGE-OK"})
        self.assertEqual(c, "AGREED-MERGE-OK")

    def test_both_agree_fix(self) -> None:
        c = self.mod.compute_consensus({"kimi": "NEEDS-FIX", "minimax": "NEEDS-FIX"})
        self.assertEqual(c, "AGREED-NEEDS-FIX")

    def test_disagreement(self) -> None:
        c = self.mod.compute_consensus({"kimi": "MERGE-OK", "minimax": "NEEDS-FIX"})
        self.assertEqual(c, "DISAGREED")

    def test_one_unparsed_is_failure(self) -> None:
        c = self.mod.compute_consensus({"kimi": None, "minimax": "MERGE-OK"})
        self.assertEqual(c, "LLM-FAILURE")

    def test_empty_is_failure(self) -> None:
        self.assertEqual(self.mod.compute_consensus({}), "LLM-FAILURE")

    def test_single_provider_agrees_with_self(self) -> None:
        # Solo run is structurally "AGREED" — the matrix's dual-agreement
        # signal degrades gracefully when only one provider was requested.
        c = self.mod.compute_consensus({"kimi": "MERGE-OK"})
        self.assertEqual(c, "AGREED-MERGE-OK")


class ProviderAbstractionTest(unittest.TestCase):
    """kimi_review / minimax_review wire through subprocess.run correctly."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def _ok_proc(self, stdout: str) -> MagicMock:
        rv = MagicMock()
        rv.returncode = 0
        rv.stdout = stdout
        rv.stderr = ""
        return rv

    def _fail_proc(self, stderr: str) -> MagicMock:
        rv = MagicMock()
        rv.returncode = 3
        rv.stdout = ""
        rv.stderr = stderr
        return rv

    def test_kimi_review_returns_stdout(self) -> None:
        with patch.object(self.mod.subprocess, "run") as run:
            run.return_value = self._ok_proc(
                "VERDICT: MERGE-OK\nRATIONALE: small.\n"
            )
            text = self.mod.kimi_review(
                diff_text="diff --git a/x b/x\n+1\n",
                prompt="prompt-body",
                max_tokens=100, timeout=5.0,
            )
            self.assertIn("VERDICT: MERGE-OK", text)
            # Verify the dispatch was called with --provider kimi.
            args, kwargs = run.call_args
            cmd = args[0]
            self.assertIn("--provider", cmd)
            self.assertEqual(cmd[cmd.index("--provider") + 1], "kimi")

    def test_minimax_review_returns_stdout(self) -> None:
        with patch.object(self.mod.subprocess, "run") as run:
            run.return_value = self._ok_proc(
                "VERDICT: NEEDS-FIX\nRATIONALE: bounds.\n"
            )
            text = self.mod.minimax_review(
                diff_text="diff --git a/y b/y\n+1\n",
                prompt="prompt-body",
                max_tokens=100, timeout=5.0,
            )
            self.assertIn("NEEDS-FIX", text)
            args, kwargs = run.call_args
            cmd = args[0]
            self.assertEqual(cmd[cmd.index("--provider") + 1], "minimax")

    def test_provider_failure_raises(self) -> None:
        with patch.object(self.mod.subprocess, "run") as run:
            run.return_value = self._fail_proc("dispatch-failed: no-api-key")
            with self.assertRaises(RuntimeError):
                self.mod.kimi_review("diff", "prompt",
                                     max_tokens=10, timeout=2.0)

    def test_provider_env_includes_consent(self) -> None:
        env = self.mod._build_provider_env("kimi")
        self.assertEqual(env.get("AUDITOOOR_LLM_NETWORK_CONSENT"), "1")


class CommentFormattingTest(unittest.TestCase):
    """format_review_comment includes attribution, calibration disclaimer."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_comment_contains_consensus_and_disclaimer(self) -> None:
        body = self.mod.format_review_comment(
            pr_number=999,
            verdicts={"kimi": "MERGE-OK", "minimax": "MERGE-OK"},
            rationales={"kimi": "looks ok", "minimax": "small diff"},
            consensus="AGREED-MERGE-OK",
        )
        self.assertIn("AGREED-MERGE-OK", body)
        self.assertIn("Kimi", body)
        self.assertIn("Minimax", body)
        self.assertIn("LLM_DELEGATION_MATRIX", body)
        self.assertIn("Verify before adopting", body)
        self.assertIn("PR #999", body)

    def test_comment_handles_unparsed_verdict(self) -> None:
        body = self.mod.format_review_comment(
            pr_number=42,
            verdicts={"kimi": None, "minimax": "NEEDS-FIX"},
            rationales={"kimi": "", "minimax": "callsite"},
            consensus="LLM-FAILURE",
        )
        self.assertIn("UNPARSED", body)
        self.assertIn("LLM-FAILURE", body)


class SummariseTest(unittest.TestCase):
    """Telemetry tally counts each consensus bucket and auto-merges."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_summarise_buckets(self) -> None:
        recs = [
            {"consensus": "AGREED-MERGE-OK", "merge_sha": "abc1234"},
            {"consensus": "AGREED-MERGE-OK", "merge_sha": None},
            {"consensus": "AGREED-NEEDS-FIX"},
            {"consensus": "DISAGREED"},
            {"consensus": "LLM-FAILURE"},
            {"consensus": "AGREED-NEEDS-REWORK"},
            {"consensus": "AGREED-OFF-SCOPE"},
        ]
        t = self.mod.summarise(recs)
        self.assertEqual(t["reviewed"], 7)
        self.assertEqual(t["agreed_merge"], 2)
        self.assertEqual(t["auto_merged"], 1)
        self.assertEqual(t["agreed_fix"], 1)
        self.assertEqual(t["agreed_rework"], 1)
        self.assertEqual(t["agreed_offscope"], 1)
        self.assertEqual(t["disagreed"], 1)
        self.assertEqual(t["llm_failure"], 1)


class CliParsingTest(unittest.TestCase):
    """Argparse glue rejects unknown providers and requires a target."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_providers_parse(self) -> None:
        p = self.mod.build_arg_parser()
        ns = p.parse_args(["--pr", "1", "--providers", "kimi"])
        self.assertEqual(ns.providers, ["kimi"])

    def test_unknown_provider_rejected(self) -> None:
        p = self.mod.build_arg_parser()
        with self.assertRaises(SystemExit):
            p.parse_args(["--pr", "1", "--providers", "openai"])

    def test_target_required(self) -> None:
        p = self.mod.build_arg_parser()
        with self.assertRaises(SystemExit):
            p.parse_args([])


class PostCommentsDefaultTest(unittest.TestCase):
    """Regression guard: posting comments is OPT-IN, not the default.

    Codex 2026-04-26 review (PR #224 P0 #3) flagged the prior default-on
    posture as a cron-driven comment-spam risk. Default must stay artefact-
    only. Both ``--post-comments`` and ``--no-post-comments`` must remain
    accepted for backwards-compat with existing callers.
    """

    def setUp(self) -> None:
        self.mod = _load_module()

    def _resolve(self, flags: list[str]) -> bool:
        """Replay main()'s post_comments resolution from parsed args."""
        ns = self.mod.build_arg_parser().parse_args(["--pr", "1", *flags])
        return bool(ns.post_comments and not ns.no_post_comments)

    def test_default_is_artefact_only(self) -> None:
        # No flag passed: posting must NOT happen. This is the regression
        # guard — flipping the default back to True would break this test.
        self.assertFalse(self._resolve([]))

    def test_post_comments_opt_in(self) -> None:
        # Explicit opt-in actually posts.
        self.assertTrue(self._resolve(["--post-comments"]))

    def test_no_post_comments_still_accepted(self) -> None:
        # Backwards-compat: callers passing the legacy explicit opt-out
        # must still parse and resolve to no-post.
        self.assertFalse(self._resolve(["--no-post-comments"]))

    def test_both_flags_resolve_to_no_post(self) -> None:
        # If a script accidentally passes both, the no-post side wins —
        # the conservative outcome.
        self.assertFalse(
            self._resolve(["--post-comments", "--no-post-comments"])
        )

    def test_argparse_defaults_are_false(self) -> None:
        # Direct attribute check on the parsed Namespace, independent of
        # the resolution helper above.
        ns = self.mod.build_arg_parser().parse_args(["--pr", "1"])
        self.assertFalse(ns.post_comments)
        self.assertFalse(ns.no_post_comments)


class TruncationFlagPropagationTest(unittest.TestCase):
    """Regression guard: when llm-pr-review head-cuts a diff, the
    ``--input-is-truncated`` flag MUST be forwarded to llm-dispatch.py.

    Codex 2026-04-26 review (PR #224 P0 #4) flagged that PR #210 added
    the dispatch-side flag but llm-pr-review never propagated it. Without
    the flag, MiniMax-M2.7 reverts to the foot-gun #13d failure mode
    (hallucinating "missing file" findings on truncated diffs, validated
    on PR #172). Both the positive case (truncated source -> flag
    present) and the negative case (fits -> flag absent) are guarded so
    a future refactor cannot silently re-introduce the bug.
    """

    def setUp(self) -> None:
        self.mod = _load_module()

    def _ok_proc(self, stdout: str = "") -> MagicMock:
        rv = MagicMock()
        rv.returncode = 0
        rv.stdout = stdout
        rv.stderr = ""
        return rv

    def _captured_cmd(self, run_mock: MagicMock) -> list[str]:
        args, _ = run_mock.call_args
        return list(args[0])

    def test_truncated_flag_forwarded_when_runner_called_truncated(self) -> None:
        # Direct: invoke kimi_review with truncated=True and confirm the
        # subprocess argv contains --input-is-truncated.
        with patch.object(self.mod.subprocess, "run") as run:
            run.return_value = self._ok_proc("VERDICT: MERGE-OK\nRATIONALE: x.\n")
            self.mod.kimi_review(
                diff_text="diff", prompt="p",
                max_tokens=50, timeout=5.0, truncated=True,
            )
            cmd = self._captured_cmd(run)
            self.assertIn("--input-is-truncated", cmd)

    def test_truncated_flag_absent_when_runner_called_not_truncated(self) -> None:
        # Negative: kimi_review without truncated kwarg -> flag must NOT
        # be in argv (default False).
        with patch.object(self.mod.subprocess, "run") as run:
            run.return_value = self._ok_proc("VERDICT: MERGE-OK\nRATIONALE: x.\n")
            self.mod.kimi_review(
                diff_text="diff", prompt="p",
                max_tokens=50, timeout=5.0,
            )
            cmd = self._captured_cmd(run)
            self.assertNotIn("--input-is-truncated", cmd)

    def test_minimax_runner_forwards_truncated_flag(self) -> None:
        # Same guard for the minimax runner — both providers receive the
        # flag from the source (review_one_pr decides once, both runners
        # forward verbatim).
        with patch.object(self.mod.subprocess, "run") as run:
            run.return_value = self._ok_proc("VERDICT: NEEDS-FIX\nRATIONALE: y.\n")
            self.mod.minimax_review(
                diff_text="diff", prompt="p",
                max_tokens=50, timeout=5.0, truncated=True,
            )
            cmd = self._captured_cmd(run)
            self.assertIn("--input-is-truncated", cmd)

    def test_review_one_pr_propagates_when_diff_exceeds_limit(self) -> None:
        # End-to-end: simulate an oversize diff and confirm dispatch was
        # invoked with --input-is-truncated. This is the assertion that
        # would have caught the original bug.
        oversize = "a" * (self.mod.MAX_DIFF_CHARS + 1024)
        with tempfile_dir() as out_dir:
            with patch.object(
                self.mod, "fetch_pr_meta",
                return_value={
                    "title": "neutral", "baseRefName": "main",
                    "headRefName": "feat/x", "mergeStateStatus": "CLEAN",
                    "state": "OPEN", "url": "https://example.invalid/pr/1",
                },
            ), patch.object(
                self.mod, "fetch_pr_diff", return_value=oversize,
            ), patch.object(self.mod.subprocess, "run") as run:
                run.return_value = self._ok_proc(
                    "VERDICT: MERGE-OK\nRATIONALE: ok.\n"
                )
                rec = self.mod.review_one_pr(
                    1,
                    providers=["kimi"],
                    max_tokens=50,
                    timeout=5.0,
                    post_comments=False,
                    auto_merge=False,
                    output_dir=pathlib.Path(out_dir),
                )
                self.assertTrue(rec.get("truncated"))
                # subprocess.run was called at least once (the kimi
                # dispatch); every invocation must carry the flag.
                self.assertGreaterEqual(run.call_count, 1)
                for call in run.call_args_list:
                    cmd = list(call.args[0])
                    self.assertIn("--input-is-truncated", cmd)

    def test_review_one_pr_omits_flag_when_diff_fits(self) -> None:
        # Negative end-to-end: small diff -> flag MUST NOT appear, and
        # the artefact records truncated=False.
        small = "diff --git a/x b/x\n+1\n"
        with tempfile_dir() as out_dir:
            with patch.object(
                self.mod, "fetch_pr_meta",
                return_value={
                    "title": "neutral", "baseRefName": "main",
                    "headRefName": "feat/x", "mergeStateStatus": "CLEAN",
                    "state": "OPEN", "url": "https://example.invalid/pr/1",
                },
            ), patch.object(
                self.mod, "fetch_pr_diff", return_value=small,
            ), patch.object(self.mod.subprocess, "run") as run:
                run.return_value = self._ok_proc(
                    "VERDICT: MERGE-OK\nRATIONALE: ok.\n"
                )
                rec = self.mod.review_one_pr(
                    1,
                    providers=["kimi"],
                    max_tokens=50,
                    timeout=5.0,
                    post_comments=False,
                    auto_merge=False,
                    output_dir=pathlib.Path(out_dir),
                )
                self.assertFalse(rec.get("truncated"))
                for call in run.call_args_list:
                    cmd = list(call.args[0])
                    self.assertNotIn("--input-is-truncated", cmd)


# Local helper — kept inside the test module so the global import surface
# stays minimal (the mainline tool already takes care to import only
# stdlib).
import contextlib
import tempfile


@contextlib.contextmanager
def tempfile_dir():
    d = tempfile.mkdtemp(prefix="llm-pr-review-test-")
    try:
        yield d
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


class RequiresCodexRoutingTest(unittest.TestCase):
    """V4 P5 §3.2: which task-types must reach Codex?

    The routing truth-table is the spec contract every downstream caller
    relies on. Each row gets its own test so a future drift (someone
    flipping a default) shows up as a single named regression.
    """

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_requires_codex_detector_tier_b(self) -> None:
        # detector-tier-b is mechanical smoke + cross-fire only —
        # auto-mergeable on AGREED-MERGE-OK without Codex.
        self.assertFalse(self.mod.compute_requires_codex("detector-tier-b"))

    def test_requires_codex_gate_hardening(self) -> None:
        # gate-hardening is a hard-gate change — Codex must arbitrate.
        self.assertTrue(self.mod.compute_requires_codex("gate-hardening"))

    def test_requires_codex_docs_plan(self) -> None:
        # docs-plan: pure plan, no executable surface.
        self.assertFalse(self.mod.compute_requires_codex("docs-plan"))

    def test_requires_codex_submission_critical(self) -> None:
        # submission-critical touches live render pipeline -> Codex required.
        self.assertTrue(
            self.mod.compute_requires_codex("submission-critical")
        )

    def test_requires_codex_crypto_review_submission_bound(self) -> None:
        # crypto-review + submission-bound -> True
        self.assertTrue(self.mod.compute_requires_codex(
            "crypto-review", submission_bound=True
        ))

    def test_requires_codex_crypto_review_not_submission_bound(self) -> None:
        # crypto-review without --submission-bound -> False (default).
        self.assertFalse(self.mod.compute_requires_codex(
            "crypto-review", submission_bound=False
        ))
        # Default kwarg also -> False.
        self.assertFalse(self.mod.compute_requires_codex("crypto-review"))

    def test_requires_codex_econ_review_submission_bound(self) -> None:
        self.assertTrue(self.mod.compute_requires_codex(
            "econ-review", submission_bound=True
        ))

    def test_requires_codex_econ_review_not_submission_bound(self) -> None:
        self.assertFalse(self.mod.compute_requires_codex(
            "econ-review", submission_bound=False
        ))
        self.assertFalse(self.mod.compute_requires_codex("econ-review"))

    def test_requires_codex_legacy_path_is_false(self) -> None:
        # task_type=None is the legacy 4-verdict path; the routing field
        # MUST default to False so the existing auto-merge semantics are
        # preserved bit-for-bit.
        self.assertFalse(self.mod.compute_requires_codex(None))

    def test_requires_codex_unknown_task_type_is_false(self) -> None:
        # Defensive: anything outside the spec routing table maps to
        # False so a typo does not silently force-codex-route.
        self.assertFalse(self.mod.compute_requires_codex("not-a-real-type"))


class TaskPromptsAndSchemasTest(unittest.TestCase):
    """Each preset has a prompt template + verdict schema with the
    required keys. Catches drift between TASK_TYPES, TASK_PROMPTS, and
    TASK_VERDICT_SCHEMAS.
    """

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_all_six_task_types_have_prompts(self) -> None:
        for tt in self.mod.TASK_TYPES:
            self.assertIn(tt, self.mod.TASK_PROMPTS, msg=tt)
            tmpl = self.mod.TASK_PROMPTS[tt]
            self.assertTrue(tmpl.strip(), msg=f"empty prompt for {tt}")
            # Required placeholders are present so build_task_prompt won't
            # KeyError at format time.
            self.assertIn("{title}", tmpl, msg=tt)
            self.assertIn("{number}", tmpl, msg=tt)
            self.assertIn("{base}", tmpl, msg=tt)
            self.assertIn("{diff}", tmpl, msg=tt)
            self.assertIn("{max_diff_chars}", tmpl, msg=tt)

    def test_all_six_task_types_have_verdict_schemas(self) -> None:
        for tt in self.mod.TASK_TYPES:
            self.assertIn(tt, self.mod.TASK_VERDICT_SCHEMAS, msg=tt)
            schema = self.mod.TASK_VERDICT_SCHEMAS[tt]
            # Every schema must declare verdict + requires_codex; that's
            # the cross-preset contract downstream consumers rely on.
            self.assertIn("verdict", schema, msg=tt)
            self.assertIn("requires_codex", schema, msg=tt)
            # rationale is also part of every preset's output.
            self.assertIn("rationale", schema, msg=tt)

    def test_build_task_prompt_substitutes_metadata(self) -> None:
        out = self.mod.build_task_prompt(
            "detector-tier-b",
            title="Neutral title",
            number=42,
            base="main",
            diff="diff --git a/x b/x\n+1\n",
            max_diff_chars=60_000,
        )
        self.assertIn("Neutral title", out)
        self.assertIn("#42", out)
        self.assertIn("main", out)
        self.assertIn("diff --git", out)
        self.assertIn("60000", out)

    def test_parse_task_verdict_pass(self) -> None:
        out = (
            "VERDICT: PASS\n"
            "SMOKE_SCORE: 0.9\n"
            "RATIONALE: All hunks land cleanly."
        )
        v, r = self.mod.parse_task_verdict(out)
        self.assertEqual(v, "PASS")
        # The 2-state grammar's rationale capture skips structured
        # mid-fields and keeps the descriptive tail.
        self.assertIn("PASS", out)

    def test_parse_task_verdict_fail(self) -> None:
        out = "VERDICT: FAIL\nRATIONALE: regression in fixture"
        v, r = self.mod.parse_task_verdict(out)
        self.assertEqual(v, "FAIL")
        self.assertIn("regression", r)

    def test_parse_task_verdict_malformed(self) -> None:
        v, r = self.mod.parse_task_verdict("nothing structured here")
        self.assertIsNone(v)


class TaskTypeArgparseTest(unittest.TestCase):
    """CLI surface for V4 P5 — backwards-compat default + new flags."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_argparse_task_type_default_none(self) -> None:
        # No flag -> task_type=None (legacy 4-verdict path).
        ns = self.mod.build_arg_parser().parse_args(["--pr", "1"])
        self.assertIsNone(ns.task_type)
        # submission_bound default also stays False.
        self.assertFalse(ns.submission_bound)

    def test_argparse_task_type_valid_choice(self) -> None:
        for tt in self.mod.TASK_TYPES:
            ns = self.mod.build_arg_parser().parse_args(
                ["--pr", "1", "--task-type", tt]
            )
            self.assertEqual(ns.task_type, tt, msg=tt)

    def test_argparse_task_type_invalid_choice_rejected(self) -> None:
        with self.assertRaises(SystemExit):
            self.mod.build_arg_parser().parse_args(
                ["--pr", "1", "--task-type", "not-real"]
            )

    def test_argparse_submission_bound_flag(self) -> None:
        ns = self.mod.build_arg_parser().parse_args(
            ["--pr", "1", "--task-type", "crypto-review",
             "--submission-bound"]
        )
        self.assertTrue(ns.submission_bound)
        # Without the flag -> False.
        ns2 = self.mod.build_arg_parser().parse_args(
            ["--pr", "1", "--task-type", "crypto-review"]
        )
        self.assertFalse(ns2.submission_bound)


class TaskTypeReviewIntegrationTest(unittest.TestCase):
    """End-to-end: review_one_pr with a task-type preset embeds
    requires_codex, task_type, submission_bound, and the task_schema in
    the per-PR artefact, and forbids auto-merge for codex-required
    presets.
    """

    def setUp(self) -> None:
        self.mod = _load_module()

    def _ok_proc(self, stdout: str = "") -> MagicMock:
        rv = MagicMock()
        rv.returncode = 0
        rv.stdout = stdout
        rv.stderr = ""
        return rv

    def _meta(self) -> dict:
        return {
            "title": "neutral", "baseRefName": "main",
            "headRefName": "feat/x", "mergeStateStatus": "CLEAN",
            "state": "OPEN", "url": "https://example.invalid/pr/1",
        }

    def test_artefact_carries_requires_codex_for_gate_hardening(self) -> None:
        small = "diff --git a/x b/x\n+1\n"
        with tempfile_dir() as out_dir:
            with patch.object(self.mod, "fetch_pr_meta",
                              return_value=self._meta()), \
                 patch.object(self.mod, "fetch_pr_diff", return_value=small), \
                 patch.object(self.mod.subprocess, "run") as run:
                run.return_value = self._ok_proc(
                    "VERDICT: PASS\nRATIONALE: hardens the gate.\n"
                )
                rec = self.mod.review_one_pr(
                    1,
                    providers=["kimi"],
                    max_tokens=50,
                    timeout=5.0,
                    post_comments=False,
                    auto_merge=False,
                    output_dir=pathlib.Path(out_dir),
                    task_type="gate-hardening",
                    submission_bound=False,
                )
                self.assertEqual(rec["task_type"], "gate-hardening")
                self.assertTrue(rec["requires_codex"])
                self.assertIn("task_schema", rec)
                self.assertTrue(rec["task_schema"]["requires_codex"])

    def test_artefact_carries_requires_codex_false_for_docs_plan(self) -> None:
        small = "diff --git a/x b/x\n+1\n"
        with tempfile_dir() as out_dir:
            with patch.object(self.mod, "fetch_pr_meta",
                              return_value=self._meta()), \
                 patch.object(self.mod, "fetch_pr_diff", return_value=small), \
                 patch.object(self.mod.subprocess, "run") as run:
                run.return_value = self._ok_proc(
                    "VERDICT: PASS\nRATIONALE: plan looks ok.\n"
                )
                rec = self.mod.review_one_pr(
                    1,
                    providers=["kimi"],
                    max_tokens=50,
                    timeout=5.0,
                    post_comments=False,
                    auto_merge=False,
                    output_dir=pathlib.Path(out_dir),
                    task_type="docs-plan",
                )
                self.assertEqual(rec["task_type"], "docs-plan")
                self.assertFalse(rec["requires_codex"])

    def test_artefact_submission_bound_flips_crypto_to_codex(self) -> None:
        small = "diff --git a/x b/x\n+1\n"
        with tempfile_dir() as out_dir:
            with patch.object(self.mod, "fetch_pr_meta",
                              return_value=self._meta()), \
                 patch.object(self.mod, "fetch_pr_diff", return_value=small), \
                 patch.object(self.mod.subprocess, "run") as run:
                run.return_value = self._ok_proc(
                    "VERDICT: PASS\nRATIONALE: crypto looks ok.\n"
                )
                rec_unbound = self.mod.review_one_pr(
                    1,
                    providers=["kimi"],
                    max_tokens=50,
                    timeout=5.0,
                    post_comments=False,
                    auto_merge=False,
                    output_dir=pathlib.Path(out_dir),
                    task_type="crypto-review",
                    submission_bound=False,
                )
                self.assertFalse(rec_unbound["requires_codex"])

                rec_bound = self.mod.review_one_pr(
                    2,
                    providers=["kimi"],
                    max_tokens=50,
                    timeout=5.0,
                    post_comments=False,
                    auto_merge=False,
                    output_dir=pathlib.Path(out_dir),
                    task_type="crypto-review",
                    submission_bound=True,
                )
                self.assertTrue(rec_bound["requires_codex"])
                self.assertTrue(
                    rec_bound["task_schema"]["submission_bound"]
                )

    def test_legacy_path_artefact_omits_codex_routing_effect(self) -> None:
        # task_type=None -> requires_codex=False, task_type field None,
        # task_schema absent.
        small = "diff --git a/x b/x\n+1\n"
        with tempfile_dir() as out_dir:
            with patch.object(self.mod, "fetch_pr_meta",
                              return_value=self._meta()), \
                 patch.object(self.mod, "fetch_pr_diff", return_value=small), \
                 patch.object(self.mod.subprocess, "run") as run:
                run.return_value = self._ok_proc(
                    "VERDICT: MERGE-OK\nRATIONALE: ok.\n"
                )
                rec = self.mod.review_one_pr(
                    3,
                    providers=["kimi"],
                    max_tokens=50,
                    timeout=5.0,
                    post_comments=False,
                    auto_merge=False,
                    output_dir=pathlib.Path(out_dir),
                )
                self.assertIsNone(rec["task_type"])
                self.assertFalse(rec["requires_codex"])
                self.assertNotIn("task_schema", rec)

    def test_auto_merge_blocked_when_requires_codex_true(self) -> None:
        # Even with --auto-merge, a codex-required preset MUST NOT call
        # merge_pr(). Two reasons reinforce each other:
        #   1) Preset consensus is AGREED-PASS, not AGREED-MERGE-OK, so
        #      the legacy auto-merge gate does not match.
        #   2) The defensive ``requires_codex`` guard short-circuits even
        #      if a future caller widens the consensus check.
        # We assert the user-facing invariant: no merge happens, and the
        # routing decision is observable in the artefact.
        small = "diff --git a/x b/x\n+1\n"
        with tempfile_dir() as out_dir:
            with patch.object(self.mod, "fetch_pr_meta",
                              return_value=self._meta()), \
                 patch.object(self.mod, "fetch_pr_diff", return_value=small), \
                 patch.object(self.mod, "merge_pr") as merge_mock, \
                 patch.object(self.mod.subprocess, "run") as run:
                run.return_value = self._ok_proc(
                    "VERDICT: PASS\nRATIONALE: hardens.\n"
                )
                rec = self.mod.review_one_pr(
                    4,
                    providers=["kimi"],
                    max_tokens=50,
                    timeout=5.0,
                    post_comments=False,
                    auto_merge=True,
                    output_dir=pathlib.Path(out_dir),
                    task_type="submission-critical",
                )
                # merge_pr MUST NOT have been invoked.
                merge_mock.assert_not_called()
                self.assertTrue(rec["requires_codex"])
                self.assertIsNone(rec.get("merge_sha"))


class TaskTypeAutoMergeGateTest(unittest.TestCase):
    """Codex HOLD on PR #236 — auto-merge gate must recognise the
    task-type preset's ``AGREED-PASS`` consensus while leaving the legacy
    ``AGREED-MERGE-OK`` semantics bit-for-bit unchanged.

    Four scenarios pin the contract:

      a) task-type + AGREED-PASS + requires_codex=False + clean
         -> ``merge_pr`` IS invoked. This is the bug fix: before the
         patch, the gate only matched ``AGREED-MERGE-OK`` so PASS-eligible
         task-type PRs were silently held.

      b) task-type + AGREED-PASS + requires_codex=True + clean
         -> ``merge_pr`` is NOT invoked. The high-risk preset guard
         (gate-hardening / submission-critical / submission-bound
         crypto/econ) MUST still fire regardless of consensus. An
         ``auto-merge-skipped`` entry surfaces the routing decision in
         ``errors[]`` so dashboards see why.

      c) task-type + AGREED-PASS-WITH-NITS + requires_codex=False + clean
         -> ``merge_pr`` is NOT invoked. Only an exact ``AGREED-PASS``
         consensus auto-merges; any "with nits" verdict still routes
         through human review. Forward-compat lock.

      d) Legacy path (no task-type) + AGREED-MERGE-OK + clean
         -> ``merge_pr`` IS invoked. Regression check that the
         per-path gate selection did not break the legacy 4-verdict
         contract.
    """

    def setUp(self) -> None:
        self.mod = _load_module()

    def _ok_proc(self, stdout: str = "") -> MagicMock:
        rv = MagicMock()
        rv.returncode = 0
        rv.stdout = stdout
        rv.stderr = ""
        return rv

    def _meta(self) -> dict:
        return {
            "title": "neutral", "baseRefName": "main",
            "headRefName": "feat/x", "mergeStateStatus": "CLEAN",
            "state": "OPEN", "url": "https://example.invalid/pr/1",
        }

    def test_a_task_type_pass_clean_not_codex_merges(self) -> None:
        # detector-tier-b is requires_codex=False; PASS verdict produces
        # AGREED-PASS consensus; status is CLEAN; auto_merge=True.
        # Expected: merge_pr IS invoked exactly once with the PR number.
        small = "diff --git a/x b/x\n+1\n"
        with tempfile_dir() as out_dir:
            with patch.object(self.mod, "fetch_pr_meta",
                              return_value=self._meta()), \
                 patch.object(self.mod, "fetch_pr_diff", return_value=small), \
                 patch.object(self.mod, "merge_pr",
                              return_value="deadbeef") as merge_mock, \
                 patch.object(self.mod.subprocess, "run") as run:
                run.return_value = self._ok_proc(
                    "VERDICT: PASS\nRATIONALE: smoke + crossfire clean.\n"
                )
                rec = self.mod.review_one_pr(
                    101,
                    providers=["kimi"],
                    max_tokens=50,
                    timeout=5.0,
                    post_comments=False,
                    auto_merge=True,
                    output_dir=pathlib.Path(out_dir),
                    task_type="detector-tier-b",
                    submission_bound=False,
                )
                self.assertEqual(rec["consensus"], "AGREED-PASS")
                self.assertFalse(rec["requires_codex"])
                merge_mock.assert_called_once_with(101)
                self.assertEqual(rec.get("merge_sha"), "deadbeef")

    def test_b_task_type_pass_clean_codex_required_blocks(self) -> None:
        # gate-hardening is requires_codex=True; even on AGREED-PASS the
        # high-risk preset guard MUST fire — merge_pr stays uninvoked
        # and an auto-merge-skipped entry lands in errors[].
        small = "diff --git a/x b/x\n+1\n"
        with tempfile_dir() as out_dir:
            with patch.object(self.mod, "fetch_pr_meta",
                              return_value=self._meta()), \
                 patch.object(self.mod, "fetch_pr_diff", return_value=small), \
                 patch.object(self.mod, "merge_pr") as merge_mock, \
                 patch.object(self.mod.subprocess, "run") as run:
                run.return_value = self._ok_proc(
                    "VERDICT: PASS\nRATIONALE: hardens the gate.\n"
                )
                rec = self.mod.review_one_pr(
                    102,
                    providers=["kimi"],
                    max_tokens=50,
                    timeout=5.0,
                    post_comments=False,
                    auto_merge=True,
                    output_dir=pathlib.Path(out_dir),
                    task_type="gate-hardening",
                    submission_bound=False,
                )
                self.assertEqual(rec["consensus"], "AGREED-PASS")
                self.assertTrue(rec["requires_codex"])
                merge_mock.assert_not_called()
                self.assertIsNone(rec.get("merge_sha"))
                # The skip is observable in the artefact so dashboards
                # can flag the held PR.
                joined = "\n".join(rec.get("errors", []))
                self.assertIn("auto-merge-skipped", joined)
                self.assertIn("requires_codex=True", joined)

    def test_c_task_type_pass_with_nits_does_not_merge(self) -> None:
        # AGREED-PASS-WITH-NITS is forward-compat: only exact AGREED-PASS
        # auto-merges. We construct the consensus directly because the
        # current parser is 2-state PASS/FAIL — but the gate is the
        # invariant under test, and a future grammar widening must not
        # accidentally promote nits to auto-merge.
        small = "diff --git a/x b/x\n+1\n"
        with tempfile_dir() as out_dir:
            with patch.object(self.mod, "fetch_pr_meta",
                              return_value=self._meta()), \
                 patch.object(self.mod, "fetch_pr_diff", return_value=small), \
                 patch.object(self.mod, "merge_pr") as merge_mock, \
                 patch.object(self.mod, "compute_consensus",
                              return_value="AGREED-PASS-WITH-NITS"), \
                 patch.object(self.mod.subprocess, "run") as run:
                run.return_value = self._ok_proc(
                    "VERDICT: PASS\nRATIONALE: tiny nit on naming.\n"
                )
                rec = self.mod.review_one_pr(
                    103,
                    providers=["kimi"],
                    max_tokens=50,
                    timeout=5.0,
                    post_comments=False,
                    auto_merge=True,
                    output_dir=pathlib.Path(out_dir),
                    task_type="detector-tier-b",
                    submission_bound=False,
                )
                self.assertEqual(rec["consensus"], "AGREED-PASS-WITH-NITS")
                self.assertFalse(rec["requires_codex"])
                merge_mock.assert_not_called()
                self.assertIsNone(rec.get("merge_sha"))

    def test_d_legacy_agreed_merge_ok_still_merges(self) -> None:
        # Regression check: the gate change must not break the legacy
        # 4-verdict path. task_type=None, MERGE-OK verdict produces
        # AGREED-MERGE-OK consensus; merge_pr IS invoked.
        small = "diff --git a/x b/x\n+1\n"
        with tempfile_dir() as out_dir:
            with patch.object(self.mod, "fetch_pr_meta",
                              return_value=self._meta()), \
                 patch.object(self.mod, "fetch_pr_diff", return_value=small), \
                 patch.object(self.mod, "merge_pr",
                              return_value="cafef00d") as merge_mock, \
                 patch.object(self.mod.subprocess, "run") as run:
                run.return_value = self._ok_proc(
                    "VERDICT: MERGE-OK\nRATIONALE: tiny tweak.\n"
                )
                rec = self.mod.review_one_pr(
                    104,
                    providers=["kimi"],
                    max_tokens=50,
                    timeout=5.0,
                    post_comments=False,
                    auto_merge=True,
                    output_dir=pathlib.Path(out_dir),
                    # task_type intentionally omitted -> legacy path.
                )
                self.assertIsNone(rec["task_type"])
                self.assertFalse(rec["requires_codex"])
                self.assertEqual(rec["consensus"], "AGREED-MERGE-OK")
                merge_mock.assert_called_once_with(104)
                self.assertEqual(rec.get("merge_sha"), "cafef00d")


if __name__ == "__main__":
    unittest.main()
