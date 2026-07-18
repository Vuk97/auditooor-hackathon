#!/usr/bin/env python3
"""Strategic-LLM policy gate tests for tools/llm-dispatch.py (V5-P0-22, Gap 42).

Per Codex's V5 P0 plan §"Items Claude Missed Or Underweighted" Gap 42:
strategic LLM policy belongs in docs and packet generation, not only
operator memory. Dispatch must refuse prompts that look strategic
unless the operator opts in via ``--strategic-llm-allowed``.

Tests:
  (a) prompt with "what should our roadmap be" rejected without override.
  (b) same prompt with --strategic-llm-allowed accepted.
  (c) routine review prompt is NOT mistaken for strategic — the
      heuristic is conservative but not absurdly broad.
  (d) refusal happens BEFORE any urlopen call (no network leak).

All tests stdlib-only and hermetic; ``urllib.request.urlopen`` is
patched so no real network call happens.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).resolve().parents[2]
LLM_TOOL = ROOT / "tools" / "llm-dispatch.py"


def _load_llm_dispatch():
    spec = importlib.util.spec_from_file_location(
        "llm_dispatch_strategic", LLM_TOOL,
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _clean_env(extra: dict | None = None) -> dict:
    drop = {
        "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
        "ANTHROPIC_MODEL", "KIMI_API_KEY", "KIMI_ANTHROPIC_BASE_URL",
        "KIMI_MODEL", "MINIMAX_API_KEY", "MINIMAX_ANTHROPIC_BASE_URL",
        "MINIMAX_MODEL", "AUDITOOOR_LLM_PROVIDER",
        "AUDITOOOR_LLM_AUTH_HEADER", "AUDITOOOR_LLM_NETWORK_CONSENT",
        "ADVERSARIAL_LIVE_CONSENT", "AUDITOOOR_LLM_BUDGET_GUARD",
    }
    base = {k: v for k, v in os.environ.items() if k not in drop}
    if extra:
        base.update(extra)
    return base


def _fake_urlopen_200() -> MagicMock:
    rv = MagicMock()
    rv.status = 200
    rv.getcode.return_value = 200
    rv.read.return_value = json.dumps({
        "content": [{"type": "text", "text": "ok"}],
        "model": "x", "role": "assistant", "stop_reason": "end_turn",
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }).encode("utf-8")
    rv.close.return_value = None
    return rv


class StrategicPromptRejectedTest(unittest.TestCase):
    def test_roadmap_prompt_refused_without_override(self) -> None:
        llm = _load_llm_dispatch()
        with tempfile.TemporaryDirectory() as tmp:
            prompt_file = Path(tmp) / "prompt.txt"
            prompt_file.write_text(
                "What should our roadmap be for next quarter?",
                encoding="utf-8",
            )
            audit_dir = Path(tmp) / "audit"

            env = _clean_env({
                "ANTHROPIC_API_KEY": "sk-test",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
                "AUDITOOOR_LLM_BUDGET_GUARD": "0",  # avoid guard import noise
            })
            urlopen_mock = MagicMock()

            buf = io.StringIO()
            err_buf = io.StringIO()
            with patch.object(
                llm.urllib.request, "urlopen", urlopen_mock,
            ), patch.dict(os.environ, env, clear=True), \
               patch.object(llm.sys, "stdout", buf), \
               patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "anthropic",
                    "--model", "claude-opus-4-5",
                    "--audit-dir", str(audit_dir),
                ])
        self.assertEqual(rc, llm.EXIT_CANNOT_RUN, err_buf.getvalue())
        # Network call must NOT have been issued.
        urlopen_mock.assert_not_called()
        stderr_text = err_buf.getvalue()
        self.assertIn("strategic-llm-disallowed", stderr_text)
        self.assertIn("matched_marker", stderr_text)
        # Refusal cites the matched substring.
        self.assertIn("roadmap", stderr_text)


class StrategicPromptAllowedWithOverrideTest(unittest.TestCase):
    def test_strategic_prompt_passes_with_override(self) -> None:
        llm = _load_llm_dispatch()
        with tempfile.TemporaryDirectory() as tmp:
            prompt_file = Path(tmp) / "prompt.txt"
            prompt_file.write_text(
                "What should our roadmap be for next quarter?",
                encoding="utf-8",
            )
            audit_dir = Path(tmp) / "audit"

            env = _clean_env({
                "ANTHROPIC_API_KEY": "sk-test",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
                "AUDITOOOR_LLM_BUDGET_GUARD": "0",
            })

            buf = io.StringIO()
            err_buf = io.StringIO()
            with patch.object(
                llm.urllib.request, "urlopen",
                return_value=_fake_urlopen_200(),
            ), patch.dict(os.environ, env, clear=True), \
               patch.object(llm.sys, "stdout", buf), \
               patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "anthropic",
                    "--model", "claude-opus-4-5",
                    "--audit-dir", str(audit_dir),
                    "--strategic-llm-allowed",
                ])
        self.assertEqual(rc, 0, err_buf.getvalue())
        self.assertIn("ok", buf.getvalue())


class RoutineReviewPromptNotRejectedTest(unittest.TestCase):
    """A normal PR-review prompt does not trip the heuristic."""

    def test_routine_pr_review_prompt_passes(self) -> None:
        llm = _load_llm_dispatch()
        with tempfile.TemporaryDirectory() as tmp:
            prompt_file = Path(tmp) / "prompt.txt"
            prompt_file.write_text(
                "Review the following diff and identify any logic bugs:\n"
                "@@ -1,2 +1,3 @@\n+    require(x > 0);\n",
                encoding="utf-8",
            )
            audit_dir = Path(tmp) / "audit"

            env = _clean_env({
                "ANTHROPIC_API_KEY": "sk-test",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
                "AUDITOOOR_LLM_BUDGET_GUARD": "0",
            })

            buf = io.StringIO()
            err_buf = io.StringIO()
            with patch.object(
                llm.urllib.request, "urlopen",
                return_value=_fake_urlopen_200(),
            ), patch.dict(os.environ, env, clear=True), \
               patch.object(llm.sys, "stdout", buf), \
               patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "anthropic",
                    "--model", "claude-opus-4-5",
                    "--audit-dir", str(audit_dir),
                ])
        self.assertEqual(rc, 0, err_buf.getvalue())

    def test_factory_liveness_advisory_task_routes_when_prompt_is_narrow(self) -> None:
        llm = _load_llm_dispatch()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text(
                "workspace_path: ~/audits/demo\n"
                "target_files:\n"
                "  - external/demo/contracts/Factory.sol:1-120\n"
                "hypotheses:\n"
                "  - factory-created child instances inherit mutable config\n"
                "prior_failed_attempts: none\n"
                "expected_output_shape: factory_config_liveness_candidate_v1 exactly\n",
                encoding="utf-8",
            )
            audit_dir = tmp_path / "audit"

            env = _clean_env({
                "KIMI_API_KEY": "kimi-key",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
                "AUDITOOOR_LLM_BUDGET_GUARD": "0",
                "AUDITOOOR_DISPATCH_PREFLIGHT_OK": (
                    "factory-config-liveness-extraction"
                ),
            })

            buf = io.StringIO()
            err_buf = io.StringIO()
            with patch.object(
                llm.urllib.request, "urlopen",
                return_value=_fake_urlopen_200(),
            ), patch.dict(os.environ, env, clear=True), \
               patch.object(llm.sys, "stdout", buf), \
               patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "kimi",
                    "--task-type", "factory-config-liveness-extraction",
                    "--audit-dir", str(audit_dir),
                ])
            self.assertEqual(rc, 0, err_buf.getvalue())
            self.assertIn("ok", buf.getvalue())
            record = json.loads(
                next(audit_dir.glob("llm_dispatch_*.json")).read_text()
            )
            self.assertEqual(record["provider"], "kimi")
            self.assertEqual(
                record["task_type"], "factory-config-liveness-extraction"
            )
            self.assertTrue(record["routing_status"]["advisory_only"])
            self.assertEqual(
                record["routing_status"]["reason"],
                "cannot-route: insufficient-data",
            )

    def test_factory_liveness_task_does_not_bypass_strategic_gate(self) -> None:
        llm = _load_llm_dispatch()
        with tempfile.TemporaryDirectory() as tmp:
            prompt_file = Path(tmp) / "prompt.txt"
            prompt_file.write_text(
                "workspace_path: ~/audits/demo\n"
                "target_files:\n"
                "  - external/demo/contracts/Factory.sol:1-120\n"
                "hypotheses:\n"
                "  - what should our roadmap be for liveness mining?\n"
                "prior_failed_attempts: none\n"
                "expected_output_shape: factory_config_liveness_candidate_v1 exactly\n",
                encoding="utf-8",
            )

            env = _clean_env({
                "KIMI_API_KEY": "kimi-key",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
                "AUDITOOOR_LLM_BUDGET_GUARD": "0",
                "AUDITOOOR_DISPATCH_PREFLIGHT_OK": (
                    "factory-config-liveness-extraction"
                ),
            })
            urlopen_mock = MagicMock()
            err_buf = io.StringIO()
            with patch.object(
                llm.urllib.request, "urlopen", urlopen_mock,
            ), patch.dict(os.environ, env, clear=True), \
               patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "kimi",
                    "--task-type", "factory-config-liveness-extraction",
                ])
        self.assertEqual(rc, llm.EXIT_CANNOT_RUN, err_buf.getvalue())
        self.assertIn("strategic-llm-disallowed", err_buf.getvalue())
        urlopen_mock.assert_not_called()


class StrategicHeuristicCaseInsensitiveTest(unittest.TestCase):
    """Catch all-caps / mixed-case strategic markers."""

    def test_uppercase_marker_caught(self) -> None:
        llm = _load_llm_dispatch()
        self.assertEqual(
            llm._detect_strategic_prompt("WHAT SHOULD WE BUILD NEXT?"),
            "what should we build next",
        )

    def test_no_marker_returns_none(self) -> None:
        llm = _load_llm_dispatch()
        self.assertIsNone(
            llm._detect_strategic_prompt("Please grade this commit message.")
        )


if __name__ == "__main__":
    unittest.main()
