#!/usr/bin/env python3
"""Tests for the two real-world bugs surfaced in `tools/llm-dispatch.py`:

Bug 1 — Kimi rc=2 "no-api-key": dispatch only read `KIMI_API_KEY` from env.
        The user's harness (and `tools/llm-pr-review.py`) already had a
        working pattern of pulling `ANTHROPIC_AUTH_TOKEN` from
        `~/.claude/settings.json` for Minimax. The fix mirrors that fallback
        for Kimi (and consolidates the Minimax fallback into dispatch
        itself, so direct CLI users get the same routing the wrapper does).

Bug 2 — Minimax rc=3 "missing-content[0].text": Minimax responses can have
        `content[0]` of `type:"thinking"` and the actual answer in a later
        block of `type:"text"`. The parser must iterate `content[]` looking
        for the first `{type: "text"}` block, not blindly assume `[0]`.
        See foot-gun #13d in `feedback_recurring_agent_mistakes.md`.

All tests are hermetic: no network, no real settings.json read, no live API.
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
LLM_TOOL = ROOT / "tools" / "llm-dispatch.py"


def _load_llm_dispatch():
    """Import llm-dispatch.py as a module despite the hyphen in its name.

    Uses a unique module name so it doesn't clash with sibling test files
    that import the same source under a different alias.
    """
    spec = importlib.util.spec_from_file_location(
        "llm_dispatch_settings_content", LLM_TOOL
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _clean_env(extra: dict | None = None) -> dict:
    """Return a scrubbed env dict that drops every provider-related var.

    Mirrors the helper in test_llm_dispatch_providers.py so these tests
    don't pick up dev-shell provider keys. Also pins
    `AUDITOOOR_KIMI_OAUTH_FILE` to a path that cannot exist so the kimi
    OAuth fallback (added later in the dispatch tool) does not leak the
    operator's real `~/.kimi/credentials/kimi-code.json` into Bug-1
    settings.json fallback tests below.
    """
    drop = {
        "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
        "ANTHROPIC_MODEL", "KIMI_API_KEY", "KIMI_ANTHROPIC_BASE_URL",
        "KIMI_MODEL", "MINIMAX_API_KEY", "MINIMAX_ANTHROPIC_BASE_URL",
        "MINIMAX_MODEL", "AUDITOOOR_LLM_PROVIDER",
        "AUDITOOOR_LLM_AUTH_HEADER", "AUDITOOOR_LLM_NETWORK_CONSENT",
        "ADVERSARIAL_LIVE_CONSENT", "AUDITOOOR_KIMI_OAUTH_FILE",
        "AUDITOOOR_LLM_BUDGET_GUARD",
        "AUDITOOOR_ANTHROPIC_PROMPT_CACHING",
    }
    base = {k: v for k, v in os.environ.items() if k not in drop}
    # V5-P0-03: budget guard now defaults ON. These tests exercise
    # auth-resolution and prompt-content paths, not budget bookkeeping;
    # opt out so they don't depend on the on-disk
    # `tools/calibration/llm_budget_log.jsonl` state.
    base["AUDITOOOR_LLM_BUDGET_GUARD"] = "0"
    # Force a missing path for the kimi OAuth file so step-2 of the
    # resolution chain returns None and step-3 (settings.json) is the
    # one under test in this file.
    base.setdefault(
        "AUDITOOOR_KIMI_OAUTH_FILE",
        "/dev/null/no-such-kimi-credentials.json",
    )
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


# -----------------------------------------------------------------------------
# Bug 1 — Kimi credential resolution (env + settings.json fallback chain)
# -----------------------------------------------------------------------------

class KimiKeyFromEnvTest(unittest.TestCase):
    """Existing path: KIMI_API_KEY in env wins; settings.json is not consulted."""

    def test_kimi_key_from_env_takes_precedence_over_settings_json(self) -> None:
        llm = _load_llm_dispatch()
        captured_auth: list[str] = []

        def side_effect(req, *_a, **_kw):
            captured_auth.append(req.headers.get("X-api-key", ""))
            return _fake_urlopen_200(
                {"content": [{"type": "text", "text": "kimi-env-ok"}]}
            )

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("ping", encoding="utf-8")
            audit_dir = tmp_path / "audit"

            env = _clean_env({
                "KIMI_API_KEY": "from-env-key",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
            })
            buf = io.StringIO()
            err_buf = io.StringIO()
            with patch.object(llm.urllib.request, "urlopen", side_effect=side_effect), \
                 patch.object(
                     llm, "_settings_json_env",
                     return_value={"KIMI_API_KEY": "from-settings-key",
                                   "ANTHROPIC_AUTH_TOKEN": "settings-anthropic-tok"},
                 ), \
                 patch.dict(os.environ, env, clear=True), \
                 patch.object(llm.sys, "stdout", buf), \
                 patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "kimi",
                    "--audit-dir", str(audit_dir),
                ])
            self.assertEqual(rc, 0, f"stderr={err_buf.getvalue()!r}")
            self.assertIn("kimi-env-ok", buf.getvalue())
            self.assertEqual(captured_auth, ["from-env-key"])


class KimiKeyFromSettingsJsonTest(unittest.TestCase):
    """Fallback path: KIMI_API_KEY absent → load from ~/.claude/settings.json."""

    def test_kimi_key_resolved_from_settings_json_kimi_key(self) -> None:
        """Provider-specific KIMI_API_KEY in settings.json wins over auth-token."""
        llm = _load_llm_dispatch()
        captured_auth: list[str] = []

        def side_effect(req, *_a, **_kw):
            captured_auth.append(req.headers.get("X-api-key", ""))
            return _fake_urlopen_200(
                {"content": [{"type": "text", "text": "kimi-from-settings"}]}
            )

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("ping", encoding="utf-8")
            audit_dir = tmp_path / "audit"

            env = _clean_env({"AUDITOOOR_LLM_NETWORK_CONSENT": "1"})
            buf = io.StringIO()
            err_buf = io.StringIO()
            with patch.object(llm.urllib.request, "urlopen", side_effect=side_effect), \
                 patch.object(
                     llm, "_settings_json_env",
                     return_value={"KIMI_API_KEY": "settings-kimi-key",
                                   "ANTHROPIC_AUTH_TOKEN": "settings-anthropic-tok"},
                 ), \
                 patch.dict(os.environ, env, clear=True), \
                 patch.object(llm.sys, "stdout", buf), \
                 patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "kimi",
                    "--audit-dir", str(audit_dir),
                ])
            self.assertEqual(rc, 0, f"stderr={err_buf.getvalue()!r}")
            self.assertIn("kimi-from-settings", buf.getvalue())
            self.assertEqual(captured_auth, ["settings-kimi-key"])

    def test_kimi_key_resolved_from_settings_json_anthropic_auth_token(self) -> None:
        """No provider-specific KIMI_API_KEY → fall through to ANTHROPIC_AUTH_TOKEN."""
        llm = _load_llm_dispatch()
        captured_auth: list[str] = []

        def side_effect(req, *_a, **_kw):
            captured_auth.append(req.headers.get("X-api-key", ""))
            return _fake_urlopen_200(
                {"content": [{"type": "text", "text": "kimi-fallback-tok"}]}
            )

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("ping", encoding="utf-8")
            audit_dir = tmp_path / "audit"

            env = _clean_env({"AUDITOOOR_LLM_NETWORK_CONSENT": "1"})
            buf = io.StringIO()
            err_buf = io.StringIO()
            with patch.object(llm.urllib.request, "urlopen", side_effect=side_effect), \
                 patch.object(
                     llm, "_settings_json_env",
                     return_value={"ANTHROPIC_AUTH_TOKEN": "shared-anthropic-tok"},
                 ), \
                 patch.dict(os.environ, env, clear=True), \
                 patch.object(llm.sys, "stdout", buf), \
                 patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "kimi",
                    "--audit-dir", str(audit_dir),
                ])
            self.assertEqual(rc, 0, f"stderr={err_buf.getvalue()!r}")
            self.assertIn("kimi-fallback-tok", buf.getvalue())
            self.assertEqual(captured_auth, ["shared-anthropic-tok"])


class KimiKeyAbsentEverywhereTest(unittest.TestCase):
    """Bug-1 negative path: env empty AND settings.json empty → exit 2 / no-api-key."""

    def test_kimi_key_absent_returns_no_api_key(self) -> None:
        llm = _load_llm_dispatch()
        urlopen_mock = MagicMock()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("ping", encoding="utf-8")
            audit_dir = tmp_path / "audit"

            env = _clean_env({"AUDITOOOR_LLM_NETWORK_CONSENT": "1"})
            buf = io.StringIO()
            err_buf = io.StringIO()
            with patch.object(llm.urllib.request, "urlopen", urlopen_mock), \
                 patch.object(llm, "_settings_json_env", return_value={}), \
                 patch.dict(os.environ, env, clear=True), \
                 patch.object(llm.sys, "stdout", buf), \
                 patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "kimi",
                    "--audit-dir", str(audit_dir),
                ])
            self.assertEqual(rc, 2)
            stderr_text = err_buf.getvalue()
            self.assertIn("cannot-run: no-api-key", stderr_text)
            self.assertIn("kimi", stderr_text)
            urlopen_mock.assert_not_called()
            self.assertEqual(buf.getvalue(), "")


# -----------------------------------------------------------------------------
# Bug 2 — content[] iteration (Minimax thinking + text)
# -----------------------------------------------------------------------------

class MinimaxThinkingThenTextTest(unittest.TestCase):
    """Minimax shape: content[0]=thinking, content[1]=text → returns text[1]."""

    def test_thinking_block_skipped_text_block_returned(self) -> None:
        llm = _load_llm_dispatch()
        # Real-world Minimax shape (foot-gun #13d).
        payload = {
            "id": "msg_01",
            "type": "message",
            "role": "assistant",
            "model": "MiniMax-M2.7",
            "content": [
                {
                    "type": "thinking",
                    "thinking": "Let me reason through this problem carefully...",
                },
                {
                    "type": "text",
                    "text": "VERDICT MERGE-OK\nRATIONALE: looks fine.",
                },
            ],
            "stop_reason": "end_turn",
        }

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
            err_buf = io.StringIO()
            with patch.object(
                llm.urllib.request, "urlopen",
                return_value=_fake_urlopen_200(payload),
            ), patch.dict(os.environ, env, clear=True), \
               patch.object(llm.sys, "stdout", buf), \
               patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "minimax",
                    "--audit-dir", str(audit_dir),
                ])
            self.assertEqual(rc, 0, f"stderr={err_buf.getvalue()!r}")
            stdout = buf.getvalue()
            # Returns the text-block content, NOT the thinking-block content.
            self.assertIn("VERDICT MERGE-OK", stdout)
            self.assertIn("RATIONALE: looks fine.", stdout)
            self.assertNotIn("Let me reason through", stdout)


class MinimaxOnlyTextTest(unittest.TestCase):
    """Conventional shape: content=[text-only] still works."""

    def test_only_text_block_returns_text(self) -> None:
        llm = _load_llm_dispatch()
        payload = {
            "content": [{"type": "text", "text": "single-text-only"}],
            "model": "MiniMax-M2.7",
            "role": "assistant",
        }
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
            err_buf = io.StringIO()
            with patch.object(
                llm.urllib.request, "urlopen",
                return_value=_fake_urlopen_200(payload),
            ), patch.dict(os.environ, env, clear=True), \
               patch.object(llm.sys, "stdout", buf), \
               patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "minimax",
                    "--audit-dir", str(audit_dir),
                ])
            self.assertEqual(rc, 0, f"stderr={err_buf.getvalue()!r}")
            self.assertEqual(buf.getvalue(), "single-text-only")


class MinimaxOnlyThinkingTest(unittest.TestCase):
    """Pathological shape: content=[thinking-only] → graceful failure (rc=3)."""

    def test_only_thinking_block_fails_gracefully(self) -> None:
        llm = _load_llm_dispatch()
        # No text-block at all — the response was truncated mid-stream
        # or the model emitted only a reasoning trace. Should NOT crash;
        # should surface a structured "no-text-block" error.
        payload = {
            "content": [
                {
                    "type": "thinking",
                    "thinking": "Reasoning... but never produced final text.",
                },
            ],
            "model": "MiniMax-M2.7",
            "role": "assistant",
            "stop_reason": "end_turn",
        }
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
            err_buf = io.StringIO()
            with patch.object(
                llm.urllib.request, "urlopen",
                return_value=_fake_urlopen_200(payload),
            ), patch.dict(os.environ, env, clear=True), \
               patch.object(llm.sys, "stdout", buf), \
               patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "minimax",
                    "--audit-dir", str(audit_dir),
                ])
            self.assertEqual(rc, 3)
            stderr_text = err_buf.getvalue()
            self.assertIn("dispatch-failed", stderr_text)
            # V5 P0-01 (Gap 7): thinking-only responses now retry once
            # before raising. Both attempts return the same mocked
            # thinking-only payload here, so the surfaced reason is the
            # post-retry classification (`thinking-only-after-retry`)
            # rather than the original `no-text-block`.
            self.assertIn("thinking-only-after-retry", stderr_text)
            # Discriminating signal — the surfaced types include "thinking".
            self.assertIn("thinking", stderr_text)
            self.assertEqual(buf.getvalue(), "")


# -----------------------------------------------------------------------------
# Foot-gun #13d (queue iter 17) — `--input-is-truncated` Minimax notice prepend
# -----------------------------------------------------------------------------

class TruncationNoticePrependTest(unittest.TestCase):
    """Mock the request and assert the truncation notice is/is-not present.

    The notice closes the absence-hallucination foot-gun: MiniMax-M2.7
    has been observed claiming "missing files" / "missing sections" when
    given a truncated diff (PR #172). When the caller passes
    `--input-is-truncated` AND the provider resolves to `minimax`,
    dispatch must prepend a system-instruction string to the user
    message body. For kimi/anthropic the flag is a no-op.

    These tests inspect the JSON body posted to the mocked urlopen, so
    they directly verify the wire-level behaviour (not just the import
    surface).
    """

    def _capture_body(self, recorded: list[dict]) -> "callable":  # noqa: F821
        """Return a urlopen side-effect that records the JSON body and
        returns a canned 200 with a one-text-block content array.
        """
        def side_effect(req, *_a, **_kw):
            recorded.append(json.loads(req.data.decode("utf-8")))
            return _fake_urlopen_200(
                {"content": [{"type": "text", "text": "ok"}]}
            )
        return side_effect

    def _run(self, *, provider: str, truncated: bool, env_extra: dict,
             prompt_text: str = "PROMPT-CORE") -> dict:
        llm = _load_llm_dispatch()
        recorded: list[dict] = []
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text(prompt_text, encoding="utf-8")
            audit_dir = tmp_path / "audit"

            env = _clean_env({
                **env_extra,
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
            })
            buf = io.StringIO()
            err_buf = io.StringIO()
            argv = [
                "--prompt-file", str(prompt_file),
                "--provider", provider,
                "--audit-dir", str(audit_dir),
            ]
            if truncated:
                argv.append("--input-is-truncated")
            with patch.object(
                llm.urllib.request, "urlopen",
                side_effect=self._capture_body(recorded),
            ), patch.dict(os.environ, env, clear=True), \
               patch.object(llm.sys, "stdout", buf), \
               patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main(argv)
            self.assertEqual(rc, 0, f"stderr={err_buf.getvalue()!r}")
            self.assertEqual(len(recorded), 1, "expected exactly one POST")
            return recorded[0]

    # ---- positive case: minimax + flag → notice prepended ---------------

    def test_minimax_truncated_input_prepends_notice(self) -> None:
        body = self._run(
            provider="minimax",
            truncated=True,
            env_extra={"MINIMAX_API_KEY": "mm-key"},
            prompt_text="DIFF-PAYLOAD",
        )
        msg = body["messages"][0]
        self.assertEqual(msg["role"], "user")
        content = msg["content"]
        self.assertIsInstance(content, str)
        # The notice must appear BEFORE the original prompt body.
        self.assertTrue(
            content.startswith("NOTE: The diff/document above is truncated."),
            f"notice should lead the user content, got: {content[:80]!r}",
        )
        self.assertIn(
            "Do NOT claim missing files or sections based on absence",
            content,
        )
        self.assertIn("DIFF-PAYLOAD", content)
        # Notice ends with the V5 P0-02 (Gap 11) extension —
        # missing-feature class language is followed by the
        # INDETERMINATE clause, then a blank line, then the original
        # content.
        self.assertIn("State INDETERMINATE if you cannot see it.\n\nDIFF-PAYLOAD", content)

    # ---- negative case: minimax WITHOUT flag → no notice ----------------

    def test_minimax_default_no_truncation_notice(self) -> None:
        body = self._run(
            provider="minimax",
            truncated=False,
            env_extra={"MINIMAX_API_KEY": "mm-key"},
            prompt_text="DIFF-PAYLOAD",
        )
        content = body["messages"][0]["content"]
        # Default behaviour preserved byte-for-byte.
        self.assertEqual(content, "DIFF-PAYLOAD")
        self.assertNotIn("NOTE: The diff/document above is truncated", content)

    # ---- non-minimax: flag is a no-op ----------------------------------

    def test_kimi_truncated_flag_is_noop(self) -> None:
        body = self._run(
            provider="kimi",
            truncated=True,
            env_extra={"KIMI_API_KEY": "kimi-key"},
            prompt_text="DIFF-PAYLOAD",
        )
        content = body["messages"][0]["content"]
        # Kimi has not exhibited the failure mode — flag must NOT alter
        # the prompt for it.
        self.assertEqual(content, "DIFF-PAYLOAD")
        self.assertNotIn("NOTE: The diff/document above is truncated", content)

    def test_anthropic_truncated_flag_is_noop(self) -> None:
        body = self._run(
            provider="anthropic",
            truncated=True,
            env_extra={"ANTHROPIC_API_KEY": "anthropic-key"},
            prompt_text="DIFF-PAYLOAD",
        )
        content = body["messages"][0]["content"]
        self.assertEqual(content, "DIFF-PAYLOAD")
        self.assertNotIn("NOTE: The diff/document above is truncated", content)

    # ---- module-level constant sanity check ----------------------------

    def test_notice_constant_is_stable(self) -> None:
        """Lock the exact notice text — drift here would silently change
        prompts in production for every truncated MiniMax hop, so any
        future edit must update this assertion deliberately.

        V5 P0-02 (Gap 11) extended the notice past the original
        missing-FILE class to cover missing-function, missing-check,
        missing-require, and missing-feature classes. The full string
        is locked here so any further extension also updates this
        assertion.
        """
        llm = _load_llm_dispatch()
        self.assertEqual(
            llm.MINIMAX_TRUNCATION_NOTICE,
            (
                "NOTE: The diff/document above is truncated. Do NOT claim "
                "missing files or sections based on absence — only flag "
                "inconsistencies you can directly observe in the visible "
                "content. This rule extends to missing-function, "
                "missing-check, missing-require, and missing-feature "
                "classes: do not claim a function/check/require/feature "
                "is missing based on its absence in the truncated "
                "content. State INDETERMINATE if you cannot see it."
            ),
        )


# -----------------------------------------------------------------------------
# PHASE-I.4 — Anthropic Messages prompt-caching request annotations
# -----------------------------------------------------------------------------

class AnthropicPromptCachingTest(unittest.TestCase):
    """Payload-level coverage for Anthropic-only cache_control support."""

    def _capture_body(self, recorded: list[dict]) -> "callable":  # noqa: F821
        def side_effect(req, *_a, **_kw):
            recorded.append(json.loads(req.data.decode("utf-8")))
            return _fake_urlopen_200(
                {"content": [{"type": "text", "text": "ok"}]}
            )
        return side_effect

    def _run(self, *, provider: str, env_extra: dict, prompt_text: str) -> dict:
        llm = _load_llm_dispatch()
        recorded: list[dict] = []
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text(prompt_text, encoding="utf-8")
            audit_dir = tmp_path / "audit"
            env = _clean_env({
                **env_extra,
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
            })
            buf = io.StringIO()
            err_buf = io.StringIO()
            with patch.object(
                llm.urllib.request,
                "urlopen",
                side_effect=self._capture_body(recorded),
            ), patch.dict(os.environ, env, clear=True), \
               patch.object(llm.sys, "stdout", buf), \
               patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", provider,
                    "--audit-dir", str(audit_dir),
                ])
            self.assertEqual(rc, 0, f"stderr={err_buf.getvalue()!r}")
            self.assertEqual(len(recorded), 1, "expected exactly one POST")
            return recorded[0]

    def test_anthropic_marks_prebrief_prefix_as_cacheable_content_block(self) -> None:
        prompt_text = (
            "<!-- BEGIN dispatch-agent-with-prebriefing META-1 block -->\n"
            "## Section 15a - Lane-specific R-rules you MUST address\n"
            "_Source: `vault_codified_rules_digest` | pack `rules:abc`_\n"
            "<!-- END dispatch-agent-with-prebriefing META-1 block -->\n\n"
            "WORKER TASK BODY"
        )
        body = self._run(
            provider="anthropic",
            env_extra={"ANTHROPIC_API_KEY": "anthropic-key"},
            prompt_text=prompt_text,
        )

        content = body["messages"][0]["content"]
        self.assertIsInstance(content, list)
        self.assertEqual(content[0]["type"], "text")
        self.assertIn("dispatch-agent-with-prebriefing META-1 block", content[0]["text"])
        self.assertEqual(content[0]["cache_control"], {"type": "ephemeral"})
        self.assertEqual(content[1], {"type": "text", "text": "WORKER TASK BODY"})

    def test_anthropic_marks_codified_rules_digest_section_as_cacheable(self) -> None:
        prompt_text = (
            "## Section 15a - Lane-specific R-rules you MUST address\n\n"
            "_Source: `vault_codified_rules_digest` | pack `rules:def`_\n\n"
            "- **R29**\n\n"
            "## Section 15b - Rule-section skeleton templates\n\n"
            "WORKER TASK BODY"
        )
        body = self._run(
            provider="anthropic",
            env_extra={"ANTHROPIC_API_KEY": "anthropic-key"},
            prompt_text=prompt_text,
        )

        content = body["messages"][0]["content"]
        self.assertIsInstance(content, list)
        self.assertIn("vault_codified_rules_digest", content[0]["text"])
        self.assertEqual(content[0]["cache_control"], {"type": "ephemeral"})
        self.assertEqual(
            content[1]["text"],
            "\n## Section 15b - Rule-section skeleton templates\n\nWORKER TASK BODY",
        )

    def test_kimi_does_not_receive_anthropic_cache_control(self) -> None:
        prompt_text = (
            "<!-- BEGIN dispatch-agent-with-prebriefing META-1 block -->\n"
            "stable rules\n"
            "<!-- END dispatch-agent-with-prebriefing META-1 block -->\n\n"
            "WORKER TASK BODY"
        )
        body = self._run(
            provider="kimi",
            env_extra={"KIMI_API_KEY": "kimi-key"},
            prompt_text=prompt_text,
        )

        content = body["messages"][0]["content"]
        self.assertIsInstance(content, str)
        self.assertIn("dispatch-agent-with-prebriefing", content)
        self.assertNotIn("cache_control", json.dumps(body))

    def test_anthropic_system_and_tool_definitions_get_cache_control(self) -> None:
        llm = _load_llm_dispatch()
        with patch.dict(os.environ, _clean_env(), clear=True):
            body = llm._build_messages_body(
                {"name": "anthropic", "model": "claude-opus-4-5"},
                max_tokens=100,
                user_content="WORKER TASK BODY",
                system_content="stable system rules",
                tools=[
                    {
                        "name": "lookup_rules",
                        "description": "stable tool schema",
                        "input_schema": {"type": "object", "properties": {}},
                    }
                ],
            )

        self.assertEqual(body["system"][0]["text"], "stable system rules")
        self.assertEqual(body["system"][0]["cache_control"], {"type": "ephemeral"})
        self.assertEqual(body["tools"][0]["cache_control"], {"type": "ephemeral"})
        self.assertEqual(body["messages"][0]["content"], "WORKER TASK BODY")

    def test_anthropic_prompt_caching_env_can_disable_annotations(self) -> None:
        llm = _load_llm_dispatch()
        env = _clean_env({"AUDITOOOR_ANTHROPIC_PROMPT_CACHING": "0"})
        with patch.dict(os.environ, env, clear=True):
            body = llm._build_messages_body(
                {"name": "anthropic", "model": "claude-opus-4-5"},
                max_tokens=100,
                user_content="WORKER TASK BODY",
                system_content="stable system rules",
                tools=[{"name": "lookup_rules", "input_schema": {"type": "object"}}],
            )

        self.assertEqual(body["system"], "stable system rules")
        self.assertNotIn("cache_control", json.dumps(body))


# -----------------------------------------------------------------------------
# Sanity check on the helper itself
# -----------------------------------------------------------------------------

class SettingsJsonHelperTest(unittest.TestCase):
    """Direct unit coverage of `_settings_json_env` resilience."""

    def test_missing_file_returns_empty_dict(self) -> None:
        llm = _load_llm_dispatch()
        with tempfile.TemporaryDirectory() as tmp:
            fake_home = Path(tmp)
            with patch.object(llm.pathlib.Path, "home", return_value=fake_home):
                self.assertEqual(llm._settings_json_env(), {})

    def test_malformed_json_returns_empty_dict(self) -> None:
        llm = _load_llm_dispatch()
        with tempfile.TemporaryDirectory() as tmp:
            fake_home = Path(tmp)
            cdir = fake_home / ".claude"
            cdir.mkdir()
            (cdir / "settings.json").write_text("{not-json", encoding="utf-8")
            with patch.object(llm.pathlib.Path, "home", return_value=fake_home):
                self.assertEqual(llm._settings_json_env(), {})

    def test_well_formed_settings_returns_env_map(self) -> None:
        llm = _load_llm_dispatch()
        with tempfile.TemporaryDirectory() as tmp:
            fake_home = Path(tmp)
            cdir = fake_home / ".claude"
            cdir.mkdir()
            (cdir / "settings.json").write_text(
                json.dumps({"env": {"ANTHROPIC_AUTH_TOKEN": "tok-xyz"}}),
                encoding="utf-8",
            )
            with patch.object(llm.pathlib.Path, "home", return_value=fake_home):
                got = llm._settings_json_env()
            self.assertEqual(got, {"ANTHROPIC_AUTH_TOKEN": "tok-xyz"})


if __name__ == "__main__":
    unittest.main()
