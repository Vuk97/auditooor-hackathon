#!/usr/bin/env python3
"""FIX-7B — provider abstraction tests for tools/llm-dispatch.py.

Six hermetic tests locking the Codex fix-spec for provider resolution:
  1. Consent gate precedes all `urlopen` calls.
  2. Auto mode prefers Kimi when KIMI_API_KEY is present.
  3. Auto mode falls back from Kimi 5xx to MiniMax.
  4. Non-429 4xx / malformed responses do NOT trigger fallback.
  5. Explicit `--provider` with missing key exits 2 without fallback.
  6. `<PROVIDER>_ANTHROPIC_BASE_URL` env builds the correct `<base>/v1/messages` URL.

All network is mocked via `unittest.mock.patch.object` on the in-module
`urllib.request.urlopen`.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch, MagicMock


ROOT = Path(__file__).resolve().parents[2]
LLM_TOOL = ROOT / "tools" / "llm-dispatch.py"


def _load_llm_dispatch():
    """Import llm-dispatch.py as a module despite the hyphen in its name."""
    spec = importlib.util.spec_from_file_location("llm_dispatch_fix7b", LLM_TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _clean_env(extra: dict | None = None) -> dict:
    """Return a scrubbed env dict that drops every provider-related var.

    Also pins `AUDITOOOR_KIMI_OAUTH_FILE` to a path that cannot exist so
    the kimi OAuth fallback added in dispatch does not leak the
    operator's real `~/.kimi/credentials/kimi-code.json` into kimi-flow
    tests below.
    """
    drop = {
        "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
        "ANTHROPIC_MODEL", "KIMI_API_KEY", "KIMI_ANTHROPIC_BASE_URL",
        "KIMI_MODEL", "MINIMAX_API_KEY", "MINIMAX_ANTHROPIC_BASE_URL",
        "MINIMAX_MODEL", "MIMO_API_KEY", "MIMO_BASE_URL", "MIMO_MODEL",
        "AUDITOOOR_LLM_PROVIDER",
        "AUDITOOOR_LLM_AUTH_HEADER", "AUDITOOOR_LLM_NETWORK_CONSENT",
        "ADVERSARIAL_LIVE_CONSENT", "AUDITOOOR_KIMI_OAUTH_FILE",
        "AUDITOOOR_LLM_BUDGET_GUARD",
        "AUDITOOOR_LLM_DISABLED_PROVIDERS",
    }
    base = {k: v for k, v in os.environ.items() if k not in drop}
    # V5-P0-03: budget guard now defaults ON. Provider-resolution tests
    # don't exercise budget bookkeeping; opt out so they don't depend on
    # ambient `tools/calibration/llm_budget_log.jsonl` state.
    base["AUDITOOOR_LLM_BUDGET_GUARD"] = "0"
    # These tests exercise HTTP provider routing; keep an installed local
    # Codex CLI from changing the auto-chain under test.
    base["AUDITOOOR_LLM_DISABLED_PROVIDERS"] = "local-cli"
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


def _fake_http_error(code: int, body: bytes = b"{}") -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        url="https://example.invalid/v1/messages",
        code=code,
        msg=f"HTTP {code}",
        hdrs=None,  # type: ignore[arg-type]
        fp=io.BytesIO(body),
    )


class NoConsentTest(unittest.TestCase):
    """Test #1 — key present but consent missing → cannot-run: no-consent."""

    def test_no_consent_with_key_present_exits_with_cannot_run_no_consent(self) -> None:
        llm = _load_llm_dispatch()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("x", encoding="utf-8")
            audit_dir = tmp_path / "audit"
            env = _clean_env({"ANTHROPIC_API_KEY": "sk-test"})
            # Explicitly NO consent var. Mock urlopen so we can also prove
            # it is never called when consent is absent.
            urlopen_mock = MagicMock()
            buf = io.StringIO()
            err_buf = io.StringIO()
            with patch.object(llm.urllib.request, "urlopen", urlopen_mock), \
                 patch.dict(os.environ, env, clear=True), \
                 patch.object(llm.sys, "stdout", buf), \
                 patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "anthropic",
                    "--audit-dir", str(audit_dir),
                ])
            self.assertEqual(rc, 2)
            self.assertIn("cannot-run: no-consent", err_buf.getvalue())
            urlopen_mock.assert_not_called()

    def test_cli_operator_consent_allows_call_and_is_audited(self) -> None:
        llm = _load_llm_dispatch()
        payload = {"content": [{"type": "text", "text": "consented"}]}
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("x", encoding="utf-8")
            audit_dir = tmp_path / "audit"
            env = _clean_env({"ANTHROPIC_API_KEY": "sk-test"})
            buf = io.StringIO()
            err_buf = io.StringIO()
            with patch.object(llm.urllib.request, "urlopen", return_value=_fake_urlopen_200(payload)) as urlopen_mock, \
                 patch.dict(os.environ, env, clear=True), \
                 patch.object(llm.sys, "stdout", buf), \
                 patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "anthropic",
                    "--audit-dir", str(audit_dir),
                    "--operator-live-network-consent",
                ])
            self.assertEqual(rc, 0, f"stderr={err_buf.getvalue()!r}")
            self.assertIn("consented", buf.getvalue())
            urlopen_mock.assert_called_once()
            ok_records = [
                json.loads(p.read_text()) for p in audit_dir.glob("llm_dispatch_*.json")
                if json.loads(p.read_text()).get("outcome") == "ok"
            ]
            self.assertEqual(len(ok_records), 1)
            self.assertEqual(
                ok_records[0]["network_consent_source"],
                "cli:--operator-live-network-consent",
            )


class AutoPrefersKimiTest(unittest.TestCase):
    """Test #2 — auto mode with all 3 keys hits Kimi URL first."""

    def test_auto_prefers_kimi_when_kimi_key_present(self) -> None:
        llm = _load_llm_dispatch()
        payload = {"content": [{"type": "text", "text": "kimi-reply"}]}
        captured_urls: list[str] = []

        def side_effect(req, *_a, **_kw):
            captured_urls.append(req.full_url)
            return _fake_urlopen_200(payload)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("x", encoding="utf-8")
            audit_dir = tmp_path / "audit"
            env = _clean_env({
                "KIMI_API_KEY": "kimi-key",
                "MINIMAX_API_KEY": "mm-key",
                "ANTHROPIC_API_KEY": "sk-test",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
            })
            buf = io.StringIO()
            err_buf = io.StringIO()
            with patch.object(llm.urllib.request, "urlopen", side_effect=side_effect), \
                 patch.dict(os.environ, env, clear=True), \
                 patch.object(llm.sys, "stdout", buf), \
                 patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--audit-dir", str(audit_dir),
                ])
            self.assertEqual(rc, 0, f"stderr={err_buf.getvalue()!r}")
            self.assertIn("kimi-reply", buf.getvalue())
            # First call must be Kimi.
            self.assertEqual(len(captured_urls), 1)
            self.assertIn("kimi.com", captured_urls[0])
            self.assertTrue(captured_urls[0].endswith("/v1/messages"))
            # Audit record should show provider=kimi.
            ok_records = [
                json.loads(p.read_text()) for p in audit_dir.glob("llm_dispatch_*.json")
                if json.loads(p.read_text()).get("outcome") == "ok"
            ]
            self.assertEqual(len(ok_records), 1)
            self.assertEqual(ok_records[0]["provider"], "kimi")


class AutoProviderOrderIncludesMimoTest(unittest.TestCase):
    """P3: auto mode tries MiMo after MiniMax and before Anthropic."""

    def _auto_provider_names(self, env_extra: dict[str, str]) -> list[str]:
        llm = _load_llm_dispatch()
        env = _clean_env(env_extra)
        with patch.object(llm, "_settings_json_env", return_value={}), \
             patch.dict(os.environ, env, clear=True):
            chain, explicit_name = llm._resolve_provider_chain("auto", None)
        self.assertIsNone(explicit_name)
        return [cfg["name"] for cfg in chain]

    def test_auto_provider_order_includes_mimo_when_key_is_set(self) -> None:
        names = self._auto_provider_names({
            "KIMI_API_KEY": "kimi-key",
            "MINIMAX_API_KEY": "mm-key",
            "MIMO_API_KEY": "mimo-key",
            "ANTHROPIC_API_KEY": "sk-test",
        })
        self.assertEqual(names, ["kimi", "minimax", "mimo", "anthropic"])

    def test_auto_provider_order_omits_mimo_cleanly_when_key_unset(self) -> None:
        names = self._auto_provider_names({
            "KIMI_API_KEY": "kimi-key",
            "MINIMAX_API_KEY": "mm-key",
            "ANTHROPIC_API_KEY": "sk-test",
        })
        self.assertEqual(names, ["kimi", "minimax", "anthropic"])


class AutoFallbackOnKimi5xxTest(unittest.TestCase):
    """Test #3 — Kimi 503 → MiniMax success.

    Ensures transport-level 5xx from provider A triggers fallback to B.
    """

    def test_auto_falls_back_to_minimax_on_kimi_5xx(self) -> None:
        llm = _load_llm_dispatch()
        payload = {"content": [{"type": "text", "text": "minimax-reply"}]}
        captured_urls: list[str] = []
        call_count = {"n": 0}

        def side_effect(req, *_a, **_kw):
            captured_urls.append(req.full_url)
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise _fake_http_error(503, b"{}")
            return _fake_urlopen_200(payload)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("x", encoding="utf-8")
            audit_dir = tmp_path / "audit"
            env = _clean_env({
                "KIMI_API_KEY": "kimi-key",
                "MINIMAX_API_KEY": "mm-key",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
            })
            buf = io.StringIO()
            err_buf = io.StringIO()
            with patch.object(llm.urllib.request, "urlopen", side_effect=side_effect), \
                 patch.dict(os.environ, env, clear=True), \
                 patch.object(llm.sys, "stdout", buf), \
                 patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--audit-dir", str(audit_dir),
                ])
            self.assertEqual(rc, 0, f"stderr={err_buf.getvalue()!r}")
            self.assertIn("minimax-reply", buf.getvalue())
            # First attempt Kimi, then fallback MiniMax.
            self.assertEqual(len(captured_urls), 2)
            self.assertIn("kimi.com", captured_urls[0])
            self.assertIn("minimax", captured_urls[1])


class NonRetryable4xxNoFallbackTest(unittest.TestCase):
    """Test #4 — Kimi 400 → exit 3, no MiniMax attempt."""

    def test_auto_does_not_fall_back_on_non_429_4xx(self) -> None:
        llm = _load_llm_dispatch()
        captured_urls: list[str] = []

        def side_effect(req, *_a, **_kw):
            captured_urls.append(req.full_url)
            raise _fake_http_error(400, b'{"error": "bad request"}')

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("x", encoding="utf-8")
            audit_dir = tmp_path / "audit"
            env = _clean_env({
                "KIMI_API_KEY": "kimi-key",
                "MINIMAX_API_KEY": "mm-key",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
            })
            buf = io.StringIO()
            err_buf = io.StringIO()
            with patch.object(llm.urllib.request, "urlopen", side_effect=side_effect), \
                 patch.dict(os.environ, env, clear=True), \
                 patch.object(llm.sys, "stdout", buf), \
                 patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--audit-dir", str(audit_dir),
                ])
            self.assertEqual(rc, 3)
            self.assertIn("dispatch-failed", err_buf.getvalue())
            # Only 1 attempt — no MiniMax fallback.
            self.assertEqual(len(captured_urls), 1)
            self.assertIn("kimi.com", captured_urls[0])
            self.assertEqual(buf.getvalue(), "")


class ExplicitProviderMissingKeyNoFallbackTest(unittest.TestCase):
    """Test #5 — --provider minimax with no MINIMAX_API_KEY → exit 2, no urlopen."""

    def test_explicit_provider_missing_key_does_not_fall_back(self) -> None:
        llm = _load_llm_dispatch()
        urlopen_mock = MagicMock()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("x", encoding="utf-8")
            audit_dir = tmp_path / "audit"
            # Provide KIMI + ANTHROPIC keys to prove explicit picks NEITHER.
            env = _clean_env({
                "KIMI_API_KEY": "kimi-key",
                "ANTHROPIC_API_KEY": "sk-test",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
            })
            buf = io.StringIO()
            err_buf = io.StringIO()
            # Force settings.json fallback to empty so this test is
            # hermetic — the dev workstation may have ANTHROPIC_AUTH_TOKEN
            # in ~/.claude/settings.json which would otherwise (correctly)
            # populate MINIMAX_API_KEY via the new fallback chain.
            with patch.object(llm.urllib.request, "urlopen", urlopen_mock), \
                 patch.object(llm, "_settings_json_env", return_value={}), \
                 patch.dict(os.environ, env, clear=True), \
                 patch.object(llm.sys, "stdout", buf), \
                 patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "minimax",
                    "--audit-dir", str(audit_dir),
                ])
            self.assertEqual(rc, 2)
            self.assertIn("cannot-run: no-api-key", err_buf.getvalue())
            self.assertIn("minimax", err_buf.getvalue())
            urlopen_mock.assert_not_called()


class BaseUrlOverrideTest(unittest.TestCase):
    """Test #6 — custom KIMI_ANTHROPIC_BASE_URL builds the right URL."""

    def test_base_url_override_builds_correct_api_url(self) -> None:
        llm = _load_llm_dispatch()
        payload = {"content": [{"type": "text", "text": "ok"}]}
        captured_urls: list[str] = []

        def side_effect(req, *_a, **_kw):
            captured_urls.append(req.full_url)
            return _fake_urlopen_200(payload)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("x", encoding="utf-8")
            audit_dir = tmp_path / "audit"
            env = _clean_env({
                "KIMI_API_KEY": "kimi-key",
                "KIMI_ANTHROPIC_BASE_URL": "https://example.test/v1",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
            })
            buf = io.StringIO()
            err_buf = io.StringIO()
            with patch.object(llm.urllib.request, "urlopen", side_effect=side_effect), \
                 patch.dict(os.environ, env, clear=True), \
                 patch.object(llm.sys, "stdout", buf), \
                 patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "kimi",
                    "--audit-dir", str(audit_dir),
                ])
            self.assertEqual(rc, 0, f"stderr={err_buf.getvalue()!r}")
            self.assertEqual(len(captured_urls), 1)
            self.assertEqual(captured_urls[0], "https://example.test/v1/messages")
            # Audit host captures only the hostname.
            ok_records = [
                json.loads(p.read_text()) for p in audit_dir.glob("llm_dispatch_*.json")
                if json.loads(p.read_text()).get("outcome") == "ok"
            ]
            self.assertEqual(len(ok_records), 1)
            self.assertEqual(ok_records[0]["api_url_host"], "example.test")


class DisabledProvidersEnforcementTest(unittest.TestCase):
    """AUDITOOOR_LLM_DISABLED_PROVIDERS drops dead providers (creds-present but
    account dead, e.g. Kimi 402 / DeepSeek 401) from the chain so the funnel
    FAILS FAST instead of hanging/retrying. The orchestrator then runs the
    Tier-2 in-session Agent(model=sonnet) hunt. Without the env, behavior is
    unchanged (regression guard)."""

    def test_auto_chain_excludes_disabled_providers(self) -> None:
        llm = _load_llm_dispatch()
        env = _clean_env({
            "KIMI_API_KEY": "k", "MINIMAX_API_KEY": "m", "MIMO_API_KEY": "mi",
            "ANTHROPIC_API_KEY": "a",
            "AUDITOOOR_LLM_DISABLED_PROVIDERS": "kimi,minimax,mimo,anthropic",
        })
        with patch.dict(os.environ, env, clear=True):
            chain, _ = llm._resolve_provider_chain("auto", None)
        names = [c.get("name") for c in chain]
        for dead in ("kimi", "minimax", "mimo", "anthropic"):
            self.assertNotIn(dead, names, f"{dead} must be dropped when disabled")

    def test_explicit_disabled_provider_fails_fast_empty_chain(self) -> None:
        llm = _load_llm_dispatch()
        env = _clean_env({"KIMI_API_KEY": "k", "AUDITOOOR_LLM_DISABLED_PROVIDERS": "kimi"})
        with patch.dict(os.environ, env, clear=True):
            chain, explicit = llm._resolve_provider_chain("kimi", None)
        self.assertEqual(chain, [], "explicit disabled provider must yield empty chain (fast skip)")
        self.assertEqual(explicit, "kimi")

    def test_no_env_leaves_chain_unchanged(self) -> None:
        llm = _load_llm_dispatch()
        env = _clean_env({"KIMI_API_KEY": "k", "MINIMAX_API_KEY": "m"})
        with patch.dict(os.environ, env, clear=True):
            chain, _ = llm._resolve_provider_chain("auto", None)
        names = [c.get("name") for c in chain]
        self.assertIn("kimi", names, "without the disable env, kimi stays in the chain")


if __name__ == "__main__":
    unittest.main()
