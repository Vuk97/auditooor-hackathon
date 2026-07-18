#!/usr/bin/env python3
"""Mandatory-preflight gate tests for tools/llm-dispatch.py (PR #535).

Verifies that direct invocation of ``tools/llm-dispatch.py`` with
``--task-type`` matching one of the 5 mandatory task types is refused
unless either:

  - ``AUDITOOOR_DISPATCH_PREFLIGHT_OK=<task-type>`` (set by
    tools/dispatch-preflight.py after validation), or
  - ``BYPASS_DISPATCH_PREFLIGHT=1`` (audited emergency override).

All tests are hermetic. No real network call is made.
"""
from __future__ import annotations

import importlib.util
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
LLM_TOOL = ROOT / "tools" / "llm-dispatch.py"


def _load_llm_dispatch():
    spec = importlib.util.spec_from_file_location(
        "llm_dispatch_pf_gate", LLM_TOOL
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _clean_env(extra: dict | None = None) -> dict:
    """Hermetic env: STRIP every provider API key so a leaked test
    (preflight gate accidentally allows the call through) cannot reach
    a real provider. We want the gate to refuse, OR provider resolution
    to fail with no-api-key, not a real urlopen.
    """
    drop = {
        # All provider keys + auth tokens — strip every one so a gate
        # bypass can NEVER produce a real network call in tests.
        "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
        "ANTHROPIC_MODEL",
        "KIMI_API_KEY", "KIMI_ANTHROPIC_BASE_URL", "KIMI_MODEL",
        "MINIMAX_API_KEY", "MINIMAX_ANTHROPIC_BASE_URL", "MINIMAX_MODEL",
        "AUDITOOOR_LLM_PROVIDER", "AUDITOOOR_LLM_AUTH_HEADER",
        "AUDITOOOR_LLM_BUDGET_GUARD",
        "AUDITOOOR_DISPATCH_PREFLIGHT_OK",
        "BYPASS_DISPATCH_PREFLIGHT",
        "BYPASS_DISPATCH_PREFLIGHT_REASON",
    }
    base = {k: v for k, v in os.environ.items() if k not in drop}
    # Network consent on so the gate is what stops us (if the gate
    # didn't refuse, provider resolution would fail with no-api-key).
    base["AUDITOOOR_LLM_NETWORK_CONSENT"] = "1"
    if extra:
        base.update(extra)
    return base


class PreflightGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_llm_dispatch()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.prompt = Path(self.tmp.name) / "p.md"
        self.prompt.write_text("hello\n")

    def _argv(self, task_type: str) -> list[str]:
        return [
            "--prompt-file", str(self.prompt),
            "--task-type", task_type,
            "--provider", "kimi",
        ]

    def _run(self, argv: list[str], env: dict) -> int:
        # HARD network mute: replace urlopen with a raise so any test
        # that accidentally reaches the network fails loudly instead of
        # spending tokens. Combined with the cleared env this is
        # belt-and-braces.
        def _no_network(*a, **kw):
            raise RuntimeError("network call attempted in unit test")
        with patch.dict(os.environ, env, clear=True), \
             patch("urllib.request.urlopen", side_effect=_no_network), \
             patch.object(self.mod, "_settings_json_env", return_value={}):
            with patch("sys.stderr", new=io.StringIO()):
                return self.mod.main(argv)

    def test_mandatory_task_type_refused_without_preflight_or_bypass(self) -> None:
        for task in (
            "source-extract",
            "factory-config-liveness-extraction",
            "adversarial-kill",
            "factory-config-liveness-kill",
            "harness-plan",
            "fixture-map",
            "paste-ready-review",
        ):
            with self.subTest(task=task):
                rc = self._run(self._argv(task), _clean_env())
                self.assertEqual(
                    rc, self.mod.EXIT_CANNOT_RUN,
                    f"task '{task}' should be gated without preflight",
                )

    def _run_capture(self, argv: list[str], env: dict) -> tuple[int, str]:
        def _no_network(*a, **kw):
            raise RuntimeError("network call attempted in unit test")
        err_buf = io.StringIO()
        with patch.dict(os.environ, env, clear=True), \
             patch("urllib.request.urlopen", side_effect=_no_network), \
             patch.object(self.mod, "_settings_json_env", return_value={}):
            with patch("sys.stderr", new=err_buf):
                rc = self.mod.main(argv)
        return rc, err_buf.getvalue()

    def test_preflight_ok_env_allows_dispatch_through_gate(self) -> None:
        # The gate must allow this through. Provider resolution then
        # fails with no-api-key (we stripped keys) — but NOT with the
        # preflight-required error.
        env = _clean_env({"AUDITOOOR_DISPATCH_PREFLIGHT_OK": "source-extract"})
        rc, err = self._run_capture(self._argv("source-extract"), env)
        self.assertNotIn("dispatch-preflight-required", err)

    def test_factory_liveness_preflight_ok_env_allows_dispatch_through_gate(self) -> None:
        env = _clean_env({
            "AUDITOOOR_DISPATCH_PREFLIGHT_OK": (
                "factory-config-liveness-extraction"
            )
        })
        rc, err = self._run_capture(
            self._argv("factory-config-liveness-extraction"), env
        )
        self.assertNotIn("dispatch-preflight-required", err)

    def test_bypass_env_allows_dispatch_through_gate(self) -> None:
        env = _clean_env({
            "BYPASS_DISPATCH_PREFLIGHT": "1",
            "BYPASS_DISPATCH_PREFLIGHT_REASON": "unit-test emergency",
        })
        rc, err = self._run_capture(self._argv("adversarial-kill"), env)
        self.assertNotIn("dispatch-preflight-required", err)

    def test_bypass_env_requires_reason(self) -> None:
        env = _clean_env({"BYPASS_DISPATCH_PREFLIGHT": "1"})
        rc, err = self._run_capture(self._argv("adversarial-kill"), env)
        self.assertEqual(rc, self.mod.EXIT_CANNOT_RUN)
        self.assertIn("dispatch-preflight-bypass-reason-required", err)

    def test_non_mandatory_task_type_unaffected(self) -> None:
        # 'pr-review' is a documented but non-mandatory task type; the
        # gate must NOT touch it.
        env = _clean_env()
        rc, err = self._run_capture(self._argv("pr-review"), env)
        self.assertNotIn("dispatch-preflight-required", err)

    def test_preflight_ok_for_wrong_task_type_does_not_satisfy_gate(self) -> None:
        # Sentinel must match the requested task-type exactly.
        env = _clean_env({"AUDITOOOR_DISPATCH_PREFLIGHT_OK": "harness-plan"})
        rc, err = self._run_capture(self._argv("source-extract"), env)
        self.assertEqual(rc, self.mod.EXIT_CANNOT_RUN)
        self.assertIn("dispatch-preflight-required", err)

    def test_wrong_factory_liveness_preflight_ok_does_not_satisfy_gate(self) -> None:
        env = _clean_env({
            "AUDITOOOR_DISPATCH_PREFLIGHT_OK": "source-extract"
        })
        rc, err = self._run_capture(
            self._argv("factory-config-liveness-extraction"), env
        )
        self.assertEqual(rc, self.mod.EXIT_CANNOT_RUN)
        self.assertIn("dispatch-preflight-required", err)


if __name__ == "__main__":
    unittest.main()
