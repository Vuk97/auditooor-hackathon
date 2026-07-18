#!/usr/bin/env python3
"""V5 P0-01 / P0-02 — llm-dispatch + llm-pr-review hardening tests.

Hermetic stdlib-only coverage for:

- V5 P0-01 / Gap 1, Gap 12: default max_tokens bumped from 4000 to 16000
  for Kimi + MiniMax + Anthropic so long-context campaigns no longer
  truncate. ``--smoke-test`` selects the cheap budget for hello-world
  checks and overrides any explicit ``--max-tokens`` value.
- V5 P0-01 / Gap 7: thinking-only responses retry EXACTLY ONCE before
  raising ``RuntimeError("malformed-response: thinking-only-after-retry")``.
- V5 P0-02 / Gap 11: ``MINIMAX_TRUNCATION_NOTICE`` covers missing
  function/check/require/feature classes, not just missing files.
- V5 P0-02 / Gap 9: ``OOS_CHECKLIST.md`` path rules are inlined into
  source-mining and submission-review packets when a workspace is
  passed in.
- V5 P0-02 / Gap 13: sampled-pattern prompts emit
  ``covered_by_known: unknown`` by default and tell the model to mark
  ``false`` only on an unambiguous match.

All HTTPS boundaries are stubbed via ``unittest.mock.patch`` on
``urllib.request.urlopen``. The OAuth credentials path is overridden
via ``AUDITOOOR_KIMI_OAUTH_FILE`` so we never read the real
``~/.kimi/credentials/`` directory.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock


ROOT = Path(__file__).resolve().parents[2]
LLM_DISPATCH = ROOT / "tools" / "llm-dispatch.py"
LLM_PR_REVIEW = ROOT / "tools" / "llm-pr-review.py"


def _load(module_name: str, source_path: Path):
    """Import a hyphen-named tools/ module via spec_from_file_location."""
    spec = importlib.util.spec_from_file_location(module_name, source_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_dispatch():
    return _load("llm_dispatch_v5", LLM_DISPATCH)


def _load_pr_review():
    return _load("llm_pr_review_v5", LLM_PR_REVIEW)


def _fake_urlopen_200(payload: dict) -> MagicMock:
    rv = MagicMock()
    rv.status = 200
    rv.getcode.return_value = 200
    rv.read.return_value = json.dumps(payload).encode("utf-8")
    rv.close.return_value = None
    return rv


def _clean_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Strip provider-related env vars so tests are deterministic."""
    keep = {
        k: v for k, v in os.environ.items()
        if k not in (
            "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "KIMI_API_KEY",
            "MINIMAX_API_KEY", "AUDITOOOR_LLM_PROVIDER",
            "ANTHROPIC_BASE_URL", "ANTHROPIC_MODEL",
            "KIMI_ANTHROPIC_BASE_URL", "MINIMAX_ANTHROPIC_BASE_URL",
            "KIMI_MODEL", "MINIMAX_MODEL",
            "AUDITOOOR_LLM_AUTH_HEADER", "AUDITOOOR_KIMI_OAUTH_FILE",
            "AUDITOOOR_LLM_BUDGET_GUARD", "AUDITOOOR_WORKSPACE",
        )
    }
    if extra:
        keep.update(extra)
    return keep


# ===========================================================================
# Test 1, 2 — default max-tokens by provider (Kimi + Minimax = 16000)
# ===========================================================================


class DefaultMaxTokensTest(unittest.TestCase):
    """V5 P0-01 / Gap 1, Gap 12: default `max_tokens` is 16000 for both
    Kimi and MiniMax. The previous 4000-token default truncated long-
    context responses to a thinking-only block plus a clipped answer
    and forced operators to manually pass ``--max-tokens 16000`` on
    every campaign.
    """

    def _capture_body(self, recorded: list[dict]):
        def side_effect(req, *_a, **_kw):
            recorded.append(json.loads(req.data.decode("utf-8")))
            return _fake_urlopen_200(
                {"content": [{"type": "text", "text": "ok"}]}
            )
        return side_effect

    def _run_default_max_tokens(self, provider: str, env_extra: dict) -> int:
        """Drive llm-dispatch.main() with NO ``--max-tokens`` override.
        Returns the integer max_tokens that ended up in the POST body.
        """
        llm = _load_dispatch()
        recorded: list[dict] = []
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("hello", encoding="utf-8")
            audit_dir = tmp_path / "audit"
            env = _clean_env({
                **env_extra,
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
                # Point the OAuth file at a non-existent path so the
                # Kimi resolver never reads the real credentials file.
                "AUDITOOOR_KIMI_OAUTH_FILE": str(tmp_path / "no.json"),
            })
            argv = [
                "--prompt-file", str(prompt_file),
                "--provider", provider,
                "--audit-dir", str(audit_dir),
            ]
            buf = io.StringIO()
            err = io.StringIO()
            with patch.object(
                llm.urllib.request, "urlopen",
                side_effect=self._capture_body(recorded),
            ), patch.dict(os.environ, env, clear=True), \
               patch.object(llm.sys, "stdout", buf), \
               patch.object(llm.sys, "stderr", err):
                rc = llm.main(argv)
            self.assertEqual(rc, 0, f"stderr={err.getvalue()!r}")
            self.assertEqual(len(recorded), 1)
            return int(recorded[0]["max_tokens"])

    def test_kimi_default_is_16000(self) -> None:
        got = self._run_default_max_tokens(
            "kimi", {"KIMI_API_KEY": "kimi-key"}
        )
        self.assertEqual(got, 16000)
        # Defensive check: confirm the legacy default is no longer in use.
        self.assertNotEqual(got, 4000)

    def test_minimax_default_is_16000(self) -> None:
        got = self._run_default_max_tokens(
            "minimax", {"MINIMAX_API_KEY": "mm-key"}
        )
        self.assertEqual(got, 16000)
        self.assertNotEqual(got, 4000)

    def test_default_constant_is_16000(self) -> None:
        """Lock the constant so future drift is intentional."""
        llm = _load_dispatch()
        self.assertEqual(llm.DEFAULT_MAX_TOKENS, 16000)


# ===========================================================================
# Test 3 — smoke-test flag selects the cheap budget
# ===========================================================================


class SmokeTestBudgetTest(unittest.TestCase):
    """V5 P0-01 / Gap 1: ``--smoke-test`` selects the
    ``SMOKE_TEST_MAX_TOKENS`` budget (200) for hello-world checks.
    Explicit ``--max-tokens`` is overridden by ``--smoke-test`` so a
    cheap dry-run cannot accidentally promote into a long-context
    spend."""

    def _capture_body(self, recorded: list[dict]):
        def side_effect(req, *_a, **_kw):
            recorded.append(json.loads(req.data.decode("utf-8")))
            return _fake_urlopen_200(
                {"content": [{"type": "text", "text": "ok"}]}
            )
        return side_effect

    def _run(self, argv_extra: list[str]) -> int:
        llm = _load_dispatch()
        recorded: list[dict] = []
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("ping", encoding="utf-8")
            audit_dir = tmp_path / "audit"
            env = _clean_env({
                "KIMI_API_KEY": "kimi-key",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
                "AUDITOOOR_KIMI_OAUTH_FILE": str(tmp_path / "no.json"),
            })
            argv = [
                "--prompt-file", str(prompt_file),
                "--provider", "kimi",
                "--audit-dir", str(audit_dir),
            ] + argv_extra
            buf = io.StringIO()
            err = io.StringIO()
            with patch.object(
                llm.urllib.request, "urlopen",
                side_effect=self._capture_body(recorded),
            ), patch.dict(os.environ, env, clear=True), \
               patch.object(llm.sys, "stdout", buf), \
               patch.object(llm.sys, "stderr", err):
                rc = llm.main(argv)
            self.assertEqual(rc, 0, f"stderr={err.getvalue()!r}")
            return int(recorded[0]["max_tokens"])

    def test_smoke_test_flag_selects_low_budget(self) -> None:
        got = self._run(["--smoke-test"])
        self.assertEqual(got, 200)

    def test_smoke_test_overrides_explicit_max_tokens(self) -> None:
        # Operator passes --smoke-test and a stale --max-tokens 12345 from a
        # previous campaign script; the smoke test must win.
        got = self._run(["--smoke-test", "--max-tokens", "12345"])
        self.assertEqual(got, 200)

    def test_constant_is_200(self) -> None:
        llm = _load_dispatch()
        self.assertEqual(llm.SMOKE_TEST_MAX_TOKENS, 200)


# ===========================================================================
# Test 4 — thinking-only retries EXACTLY once (2 dispatch calls)
# Test 5 — after retry still thinking-only → thinking-only-after-retry
# ===========================================================================


class ThinkingOnlyRetryTest(unittest.TestCase):
    """V5 P0-01 / Gap 7: thinking-only responses retry exactly once.

    The retry budget is bounded by ``THINKING_ONLY_RETRY_LIMIT`` so a
    genuinely-stuck model cannot burn the operator's token budget. The
    first retry succeeds → success path. Two consecutive thinking-only
    responses → ``RuntimeError("malformed-response: "
    "thinking-only-after-retry ...")``.
    """

    THINKING_ONLY_PAYLOAD = {
        "content": [{"type": "thinking", "thinking": "Reasoning..."}],
        "model": "MiniMax-M2.7",
        "role": "assistant",
        "stop_reason": "end_turn",
    }
    TEXT_PAYLOAD = {
        "content": [{"type": "text", "text": "recovered-on-retry"}],
        "model": "MiniMax-M2.7",
        "role": "assistant",
        "stop_reason": "end_turn",
    }

    def _build_side_effect(self, payloads: list[dict], call_log: list[str]):
        """Return a urlopen side-effect that walks ``payloads`` in order
        and records each call so we can count dispatch attempts.
        """
        idx = {"i": 0}

        def side_effect(req, *_a, **_kw):
            i = idx["i"]
            call_log.append(req.full_url)
            payload = payloads[i] if i < len(payloads) else payloads[-1]
            idx["i"] = i + 1
            return _fake_urlopen_200(payload)

        return side_effect

    def _drive(self, payloads: list[dict]) -> tuple[int, str, str, list[str]]:
        llm = _load_dispatch()
        call_log: list[str] = []
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("review", encoding="utf-8")
            audit_dir = tmp_path / "audit"
            env = _clean_env({
                "MINIMAX_API_KEY": "mm-key",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
            })
            buf = io.StringIO()
            err = io.StringIO()
            with patch.object(
                llm.urllib.request, "urlopen",
                side_effect=self._build_side_effect(payloads, call_log),
            ), patch.dict(os.environ, env, clear=True), \
               patch.object(llm.sys, "stdout", buf), \
               patch.object(llm.sys, "stderr", err):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "minimax",
                    "--audit-dir", str(audit_dir),
                ])
        return rc, buf.getvalue(), err.getvalue(), call_log

    def test_thinking_then_text_retries_exactly_once(self) -> None:
        # First response: thinking-only. Second: usable text. Expect
        # success (rc=0) and EXACTLY 2 urlopen calls.
        rc, stdout, stderr, calls = self._drive(
            [self.THINKING_ONLY_PAYLOAD, self.TEXT_PAYLOAD]
        )
        self.assertEqual(rc, 0, f"stderr={stderr!r}")
        self.assertEqual(stdout, "recovered-on-retry")
        self.assertEqual(
            len(calls), 2,
            f"expected exactly 2 dispatch calls (one retry), got {len(calls)}",
        )
        # The retry diagnostic should be visible in stderr so operators
        # can see why the call took longer than usual.
        self.assertIn("thinking-only-response: retrying once", stderr)

    def test_two_thinking_responses_raises_after_retry(self) -> None:
        # Both responses are thinking-only — retry budget exhausted,
        # surface as a RuntimeError converted to rc=3 by main(), and
        # the new diagnostic must appear in stderr.
        rc, stdout, stderr, calls = self._drive(
            [self.THINKING_ONLY_PAYLOAD, self.THINKING_ONLY_PAYLOAD]
        )
        self.assertEqual(rc, 3)
        self.assertEqual(stdout, "")
        self.assertIn("thinking-only-after-retry", stderr)
        self.assertIn("dispatch-failed", stderr)
        self.assertEqual(
            len(calls), 2,
            "retry budget should bound calls at 2 (initial + one retry)",
        )

    def test_retry_limit_constant_is_one(self) -> None:
        """Lock the bound — anything other than 1 changes operator
        cost without an explicit operator-facing change.
        """
        llm = _load_dispatch()
        self.assertEqual(llm.THINKING_ONLY_RETRY_LIMIT, 1)

    def test_non_thinking_no_text_shape_does_not_retry(self) -> None:
        """Kimi M14-trap: confirm the retry shim does NOT mask other
        no-text-block shapes (e.g. tool_use only, content but no text
        field). Those have not been observed to recover on retry —
        retrying them would silently double the operator cost on a
        genuinely broken response. The strict equality check
        ``types_seen == ["thinking"]`` in ``_call_once_inner`` is what
        guarantees the masking does not happen; this test pins the
        contract from the outside.
        """
        # tool_use-only: types_seen == ["tool_use"] — should hard-fail
        # immediately on the FIRST attempt, no retry.
        tool_use_only = {
            "content": [{"type": "tool_use", "id": "x", "name": "y",
                          "input": {}}],
            "model": "MiniMax-M2.7",
            "role": "assistant",
            "stop_reason": "end_turn",
        }
        rc, stdout, stderr, calls = self._drive(
            [tool_use_only, tool_use_only]
        )
        self.assertEqual(rc, 3)
        self.assertEqual(stdout, "")
        # The error is the unchanged classic "no-text-block" — NOT
        # the new "thinking-only-after-retry" string.
        self.assertIn("no-text-block", stderr)
        self.assertNotIn("thinking-only-after-retry", stderr)
        self.assertEqual(
            len(calls), 1,
            "non-thinking malformed shape must NOT trigger the retry shim",
        )

    def test_mixed_thinking_and_tool_use_no_text_does_not_retry(self) -> None:
        """Mixed types (thinking + tool_use) is not the strict
        thinking-only shape and must NOT retry — same rationale as
        the tool_use-only case. Pins the strict-equality semantics of
        the masking guard.
        """
        mixed_only = {
            "content": [
                {"type": "thinking", "thinking": "..."},
                {"type": "tool_use", "id": "x", "name": "y",
                  "input": {}},
            ],
            "model": "MiniMax-M2.7",
            "role": "assistant",
            "stop_reason": "end_turn",
        }
        rc, stdout, stderr, calls = self._drive(
            [mixed_only, mixed_only]
        )
        self.assertEqual(rc, 3)
        self.assertIn("no-text-block", stderr)
        self.assertNotIn("thinking-only-after-retry", stderr)
        self.assertEqual(len(calls), 1)


# ===========================================================================
# Test 6 — truncation notice covers missing-function/check/require/feature
# ===========================================================================


class TruncationNoticeContentTest(unittest.TestCase):
    """V5 P0-02 / Gap 11: the truncation notice extends past missing-FILE
    to cover missing-function, missing-check, missing-require, and
    missing-feature classes — the dominant Minimax hallucination shape
    on long submission diffs.
    """

    REQUIRED_TERMS = (
        "missing-function",
        "missing-check",
        "missing-require",
        "missing-feature",
    )

    def test_notice_contains_all_required_classes(self) -> None:
        llm = _load_dispatch()
        notice = llm.MINIMAX_TRUNCATION_NOTICE.lower()
        for term in self.REQUIRED_TERMS:
            self.assertIn(
                term,
                notice,
                f"truncation notice missing required class `{term}`",
            )

    def test_notice_contains_indeterminate_clause(self) -> None:
        # The notice must explicitly tell the model to state INDETERMINATE
        # rather than fabricate absence.
        llm = _load_dispatch()
        self.assertIn("INDETERMINATE", llm.MINIMAX_TRUNCATION_NOTICE)


# ===========================================================================
# Test 7 — OOS path regex appears inline in generated packets
# ===========================================================================


class OOSPathRulesInlineTest(unittest.TestCase):
    """V5 P0-02 / Gap 9: when a workspace ships ``OOS_CHECKLIST.md`` and
    the packet is a submission-review (default 4-verdict path or
    submission-critical task type), the OOS path rules must be inlined
    above the prompt body — the model only sees what is in the packet.
    """

    CHECKLIST_BODY = """\
# OOS Checklist

## Out of scope paths

- src/v1/**
- tests/**/fixtures/*.sol
- vendored/openzeppelin/contracts/

## Severity caps

- All gas optimisations capped at info
"""

    def _make_workspace(self, tmp: Path) -> Path:
        ws = tmp / "ws"
        ws.mkdir()
        (ws / "OOS_CHECKLIST.md").write_text(
            self.CHECKLIST_BODY, encoding="utf-8"
        )
        return ws

    def test_extract_oos_returns_path_shaped_rules(self) -> None:
        prr = _load_pr_review()
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._make_workspace(Path(tmp))
            rules = prr._extract_oos_path_rules(ws)
        self.assertEqual(len(rules), 3)
        # Order is preserved; each rule is prefixed with OOS-N.
        self.assertTrue(rules[0].startswith("OOS-1: "))
        self.assertIn("src/v1/**", rules[0])
        self.assertIn("tests/", rules[1])
        self.assertIn("vendored/openzeppelin/", rules[2])
        # The non-path bullet is NOT included.
        joined = "\n".join(rules)
        self.assertNotIn("gas optimisations", joined)

    def test_extract_oos_no_workspace_returns_empty(self) -> None:
        prr = _load_pr_review()
        self.assertEqual(prr._extract_oos_path_rules(None), [])

    def test_extract_oos_missing_checklist_returns_empty(self) -> None:
        prr = _load_pr_review()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            self.assertEqual(prr._extract_oos_path_rules(ws), [])

    def test_format_section_includes_header_and_rules(self) -> None:
        prr = _load_pr_review()
        rules = ["OOS-1: src/v1/**", "OOS-2: tests/**"]
        section = prr._format_oos_packet_section(rules)
        self.assertIn(prr.OOS_PACKET_HEADER, section)
        self.assertIn("src/v1/**", section)
        self.assertIn("tests/**", section)
        # Empty rules → empty section so callers can unconditionally
        # concatenate without leaking a stray header.
        self.assertEqual(prr._format_oos_packet_section([]), "")

    def test_submission_critical_prompt_includes_oos_section(self) -> None:
        prr = _load_pr_review()
        rules = ["OOS-1: src/v1/**", "OOS-2: tests/**"]
        prompt = prr.build_task_prompt(
            "submission-critical",
            title="t", number=1, base="main",
            diff="<diff>", max_diff_chars=60_000,
            oos_rules=rules,
        )
        # Header lands BEFORE the task prompt body.
        header_idx = prompt.find(prr.OOS_PACKET_HEADER)
        diff_idx = prompt.find("<diff>")
        self.assertGreater(header_idx, -1, "header missing from packet")
        self.assertGreater(diff_idx, header_idx, "OOS section must precede diff")
        self.assertIn("src/v1/**", prompt)

    def test_detector_tier_b_prompt_does_not_inline_oos(self) -> None:
        # Tier-B is a mechanical smoke + cross-fire path; OOS scope
        # rules are not relevant and would dilute the small token
        # budget. Confirm the injection is gated on task type.
        prr = _load_pr_review()
        rules = ["OOS-1: src/v1/**"]
        prompt = prr.build_task_prompt(
            "detector-tier-b",
            title="t", number=1, base="main",
            diff="<diff>", max_diff_chars=60_000,
            oos_rules=rules,
        )
        self.assertNotIn(prr.OOS_PACKET_HEADER, prompt)
        self.assertNotIn("src/v1/**", prompt)


# ===========================================================================
# Test 8 — sampled-pattern prompt defaults `covered_by_known: unknown`
# ===========================================================================


class SampledPatternPromptTest(unittest.TestCase):
    """V5 P0-02 / Gap 13: when a packet only carries a sample of the
    detector library, the prompt must default ``covered_by_known`` to
    ``unknown`` and instruct the model to emit ``false`` only on an
    unambiguous match.
    """

    def test_prompt_includes_default_unknown_instruction(self) -> None:
        prr = _load_pr_review()
        prompt = prr.build_sampled_pattern_prompt(
            sample_count=60,
            total_count=1300,
            sample_names=["pattern.unchecked-call", "pattern.reentrancy"],
            finding_summary="Untested permit-claim path bypasses signature.",
        )
        self.assertIn("60 of 1300", prompt)
        self.assertIn("SAMPLE", prompt)
        self.assertIn('Default to', prompt)
        self.assertIn('unknown', prompt)
        # The instruction must explicitly bound when `false` is allowed.
        self.assertIn(
            "Mark `covered_by_known: false` ONLY when",
            prompt,
        )
        # The schema must explicitly include `unknown` as a valid value.
        self.assertIn("<true|false|unknown>", prompt)

    def test_default_constant_is_unknown(self) -> None:
        prr = _load_pr_review()
        self.assertEqual(prr.SAMPLED_PATTERN_DEFAULT, "unknown")

    def test_visible_sample_names_appear_in_prompt(self) -> None:
        prr = _load_pr_review()
        prompt = prr.build_sampled_pattern_prompt(
            sample_count=2,
            total_count=1300,
            sample_names=["pattern.signature-replay",
                          "pattern.unbounded-storage-loop"],
            finding_summary="A finding.",
        )
        self.assertIn("pattern.signature-replay", prompt)
        self.assertIn("pattern.unbounded-storage-loop", prompt)


if __name__ == "__main__":
    unittest.main()
