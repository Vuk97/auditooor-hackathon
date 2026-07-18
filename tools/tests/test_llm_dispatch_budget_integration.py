#!/usr/bin/env python3
"""Budget-guard integration tests for tools/llm-dispatch.py.

V5-P0-03 (Gap 39 + Gap 43) flipped the semantic: the guard now defaults
to ON. Operators must explicitly set ``AUDITOOOR_LLM_BUDGET_GUARD=0`` to
disable it. The tests below reflect the new contract:

  (a) env-var unset            -> guard IS constructed (default-on)
  (b) env-var=1 (allowed)      -> record_call invoked with parsed tokens
  (c) env-var=1 (exhausted)    -> ProviderFallback path -> next provider
  (d) env-var=0 (opt-out)      -> guard NOT constructed, loud stderr
                                  warn line written, manifest records
                                  ``budget_guard_disabled: true``
  (e) env-var="" (empty str)   -> still default-on (foot-gun #11 trap)

The budget-guard module is replaced in-process via a stub class injected
into the dispatch module's importlib loader: we patch
``_load_budget_guard_module`` to return a fake module exposing a
``LlmBudgetGuard`` whose methods are MagicMock instances we can assert
against. ``urllib.request.urlopen`` is also stubbed so no network call
ever happens.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).resolve().parents[2]
LLM_TOOL = ROOT / "tools" / "llm-dispatch.py"


def _load_llm_dispatch():
    """Import llm-dispatch.py as a module despite the hyphen in its name."""
    spec = importlib.util.spec_from_file_location(
        "llm_dispatch_budget", LLM_TOOL
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _clean_env(extra: dict | None = None) -> dict:
    """Scrubbed env that drops every dispatch-relevant variable."""
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


def _fake_urlopen_200(payload: dict) -> MagicMock:
    rv = MagicMock()
    rv.status = 200
    rv.getcode.return_value = 200
    rv.read.return_value = json.dumps(payload).encode("utf-8")
    rv.close.return_value = None
    return rv


def _payload_with_usage(text: str, in_tok: int, out_tok: int) -> dict:
    """Anthropic Messages API success body with a usage block."""
    return {
        "content": [{"type": "text", "text": text}],
        "model": "claude-opus-4-5",
        "role": "assistant",
        "stop_reason": "end_turn",
        "usage": {"input_tokens": in_tok, "output_tokens": out_tok},
    }


def _make_guard_module(may_call_returns, record_call_mock):
    """Build a fake llm_budget_guard module exposing LlmBudgetGuard.

    ``may_call_returns`` is a (allowed, reason) tuple the stub returns
    every call. ``record_call_mock`` is the MagicMock the test asserts
    against.
    """
    guard_instance = SimpleNamespace(
        may_call=MagicMock(return_value=may_call_returns),
        record_call=record_call_mock,
    )
    fake_class = MagicMock(return_value=guard_instance)
    return SimpleNamespace(LlmBudgetGuard=fake_class), guard_instance


class BudgetGuardDefaultOnTest(unittest.TestCase):
    """(a) V5-P0-03: env var unset -> guard IS constructed (default-on).

    The lazy loader IS invoked exactly once on first hop. record_call
    fires after a successful 2xx since the budget guard is wired in.
    """

    def test_env_var_unset_constructs_guard_default_on(self) -> None:
        llm = _load_llm_dispatch()
        payload = _payload_with_usage("ok-response", 100, 200)
        record_call_mock = MagicMock()
        fake_module, guard_instance = _make_guard_module(
            may_call_returns=(True, None),
            record_call_mock=record_call_mock,
        )

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("hello", encoding="utf-8")
            audit_dir = tmp_path / "audit"

            env = _clean_env({
                "ANTHROPIC_API_KEY": "sk-test",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
                # AUDITOOOR_LLM_BUDGET_GUARD intentionally NOT set —
                # V5-P0-03 says this means "default ON".
            })

            buf = io.StringIO()
            err_buf = io.StringIO()
            with patch.object(
                llm.urllib.request, "urlopen",
                return_value=_fake_urlopen_200(payload),
            ), patch.object(
                llm, "_load_budget_guard_module",
                return_value=fake_module,
            ), patch.dict(os.environ, env, clear=True), \
               patch.object(llm.sys, "stdout", buf), \
               patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "anthropic",
                    "--model", "claude-opus-4-5",
                    "--audit-dir", str(audit_dir),
                ])
            audit_files = sorted(audit_dir.glob("llm_dispatch_*.json"))
            self.assertEqual(len(audit_files), 1)
            record = json.loads(audit_files[0].read_text())

        self.assertEqual(rc, 0, f"main() rc={rc}; stderr={err_buf.getvalue()!r}")
        self.assertIn("ok-response", buf.getvalue())
        # Guard fired by default.
        guard_instance.may_call.assert_called_once_with(
            "anthropic", soft=False
        )
        record_call_mock.assert_called_once_with(
            "anthropic", 100 + 200, success=True
        )
        # Manifest records that the guard was NOT disabled.
        self.assertEqual(record["budget_guard_disabled"], False)


class BudgetGuardEmptyStringStillOnTest(unittest.TestCase):
    """(e) Empty-string env var (`export AUDITOOOR_LLM_BUDGET_GUARD=`) is treated as "not 0".

    Operators commonly clear an env var by setting it to an empty
    string in their shell profile. That MUST NOT silently disable the
    guard — only the literal string "0" disables it.
    """

    def test_empty_string_keeps_guard_on(self) -> None:
        llm = _load_llm_dispatch()
        payload = _payload_with_usage("ok-response", 1, 2)
        record_call_mock = MagicMock()
        fake_module, guard_instance = _make_guard_module(
            may_call_returns=(True, None),
            record_call_mock=record_call_mock,
        )

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("hello", encoding="utf-8")
            audit_dir = tmp_path / "audit"

            env = _clean_env({
                "ANTHROPIC_API_KEY": "sk-test",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
                "AUDITOOOR_LLM_BUDGET_GUARD": "",  # foot-gun trap
            })

            buf = io.StringIO()
            err_buf = io.StringIO()
            with patch.object(
                llm.urllib.request, "urlopen",
                return_value=_fake_urlopen_200(payload),
            ), patch.object(
                llm, "_load_budget_guard_module",
                return_value=fake_module,
            ), patch.dict(os.environ, env, clear=True), \
               patch.object(llm.sys, "stdout", buf), \
               patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "anthropic",
                    "--model", "claude-opus-4-5",
                    "--audit-dir", str(audit_dir),
                ])

        self.assertEqual(rc, 0, f"stderr={err_buf.getvalue()!r}")
        # Empty string did NOT disable the guard.
        guard_instance.may_call.assert_called_once()
        # No loud opt-out warn line was emitted (since the guard is on).
        self.assertNotIn(
            "operator explicitly disabled budget guard",
            err_buf.getvalue(),
        )


class BudgetGuardOptOutTest(unittest.TestCase):
    """(d) AUDITOOOR_LLM_BUDGET_GUARD=0 -> opt-out path.

    - Guard is NOT constructed (loader never called).
    - Loud stderr warn JSON line is emitted.
    - Manifest records ``budget_guard_disabled: true``.
    - Network call still proceeds (operator accepted the risk).
    """

    def test_explicit_zero_disables_guard_and_warns(self) -> None:
        llm = _load_llm_dispatch()
        payload = _payload_with_usage("ok-response", 50, 60)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("hello", encoding="utf-8")
            audit_dir = tmp_path / "audit"

            env = _clean_env({
                "ANTHROPIC_API_KEY": "sk-test",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
                "AUDITOOOR_LLM_BUDGET_GUARD": "0",  # explicit opt-out
            })

            buf = io.StringIO()
            err_buf = io.StringIO()
            loader_mock = MagicMock()
            with patch.object(
                llm.urllib.request, "urlopen",
                return_value=_fake_urlopen_200(payload),
            ), patch.object(
                llm, "_load_budget_guard_module", loader_mock,
            ), patch.dict(os.environ, env, clear=True), \
               patch.object(llm.sys, "stdout", buf), \
               patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "anthropic",
                    "--model", "claude-opus-4-5",
                    "--audit-dir", str(audit_dir),
                ])
            audit_files = sorted(audit_dir.glob("llm_dispatch_*.json"))
            self.assertEqual(len(audit_files), 1)
            record = json.loads(audit_files[0].read_text())

        self.assertEqual(rc, 0, f"stderr={err_buf.getvalue()!r}")
        # Guard loader is NOT invoked.
        loader_mock.assert_not_called()
        # Loud opt-out warning present in stderr (one of multiple lines).
        stderr_text = err_buf.getvalue()
        self.assertIn(
            "operator explicitly disabled budget guard",
            stderr_text,
        )
        self.assertIn("AUDITOOOR_LLM_BUDGET_GUARD=0", stderr_text)
        self.assertIn("Token-burn unbounded", stderr_text)
        # Warn line is JSON.
        warn_lines = [
            ln for ln in stderr_text.splitlines()
            if "operator explicitly disabled" in ln
        ]
        self.assertEqual(len(warn_lines), 1)
        json.loads(warn_lines[0])  # asserts JSON-parseable
        # Manifest records the disable flag.
        self.assertEqual(record["budget_guard_disabled"], True)


class BudgetGuardAllowedTest(unittest.TestCase):
    """(b) Env var set + budget allowed -> record_call invoked.

    Tokens passed to record_call must equal input_tokens + output_tokens
    parsed from the response usage block.
    """

    def test_allowed_call_records_parsed_tokens(self) -> None:
        llm = _load_llm_dispatch()
        payload = _payload_with_usage("budgeted-response", 123, 456)
        record_call_mock = MagicMock()
        fake_module, guard_instance = _make_guard_module(
            may_call_returns=(True, None),
            record_call_mock=record_call_mock,
        )

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("hello", encoding="utf-8")
            audit_dir = tmp_path / "audit"

            env = _clean_env({
                "ANTHROPIC_API_KEY": "sk-test",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
                "AUDITOOOR_LLM_BUDGET_GUARD": "1",
            })

            buf = io.StringIO()
            err_buf = io.StringIO()
            with patch.object(
                llm.urllib.request, "urlopen",
                return_value=_fake_urlopen_200(payload),
            ), patch.object(
                llm, "_load_budget_guard_module",
                return_value=fake_module,
            ), patch.dict(os.environ, env, clear=True), \
               patch.object(llm.sys, "stdout", buf), \
               patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "anthropic",
                    "--model", "claude-opus-4-5",
                    "--audit-dir", str(audit_dir),
                ])

        self.assertEqual(rc, 0, f"main() rc={rc}; stderr={err_buf.getvalue()!r}")
        self.assertIn("budgeted-response", buf.getvalue())
        # Pre-call gate fired exactly once for this single-provider chain.
        guard_instance.may_call.assert_called_once_with(
            "anthropic", soft=False
        )
        # Post-call accounting fired exactly once with the parsed total.
        record_call_mock.assert_called_once_with(
            "anthropic", 123 + 456, success=True
        )


class BudgetGuardExhaustedTest(unittest.TestCase):
    """(c) Env var set + exhausted budget -> fallback / clean exit.

    Explicit single-provider chain: when may_call returns (False, ...),
    the call must be skipped and dispatch must exit 3 with
    ``error: dispatch-failed`` and the budget-skip reason in
    ``fallback_reasons``. urlopen must NEVER be called.
    """

    def test_exhausted_budget_skips_provider_no_network_call(self) -> None:
        llm = _load_llm_dispatch()
        record_call_mock = MagicMock()
        fake_module, guard_instance = _make_guard_module(
            may_call_returns=(
                False,
                "calls budget exhausted: 30/30 in last 60min",
            ),
            record_call_mock=record_call_mock,
        )
        urlopen_mock = MagicMock()

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("hello", encoding="utf-8")
            audit_dir = tmp_path / "audit"

            env = _clean_env({
                "ANTHROPIC_API_KEY": "sk-test",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
                "AUDITOOOR_LLM_BUDGET_GUARD": "1",
            })

            buf = io.StringIO()
            err_buf = io.StringIO()
            with patch.object(
                llm.urllib.request, "urlopen", urlopen_mock,
            ), patch.object(
                llm, "_load_budget_guard_module",
                return_value=fake_module,
            ), patch.dict(os.environ, env, clear=True), \
               patch.object(llm.sys, "stdout", buf), \
               patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "anthropic",
                    "--model", "claude-opus-4-5",
                    "--audit-dir", str(audit_dir),
                ])

            # All assertions inside the TemporaryDirectory `with` block
            # so the on-disk audit dir still exists when we glob it.
            # No provider succeeded -> exit 3.
            self.assertEqual(rc, 3, f"expected exit 3, got {rc}")
            # Budget gate fired but the network call did not.
            guard_instance.may_call.assert_called_once_with(
                "anthropic", soft=False
            )
            urlopen_mock.assert_not_called()
            record_call_mock.assert_not_called()
            # Structured error mentions the budget-skip reason.
            stderr_text = err_buf.getvalue()
            self.assertIn("error: dispatch-failed", stderr_text)
            self.assertIn("budget-skip", stderr_text)
            # Audit trail captured the budget-skip outcome.
            audit_files = sorted(audit_dir.glob("llm_dispatch_*.json"))
            self.assertEqual(len(audit_files), 1)
            record = json.loads(audit_files[0].read_text())
            self.assertTrue(
                record["outcome"].startswith("budget-skip:")
            )
            self.assertEqual(record["http_status"], 429)


if __name__ == "__main__":
    unittest.main()
