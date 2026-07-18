#!/usr/bin/env python3
"""Hermetic tests for tools/llm-preflight-auth.py (V5-P0-04, Gap 44).

Coverage:
- ``--dry-run`` with NO auth resolved for any provider exits 0 in multi
  mode and reports per-provider ``no-key``.
- ``--dry-run --provider kimi`` with valid env-provided key exits 0 and
  reports ``env-provider-key`` resolution.
- ``--dry-run --provider kimi`` with NO auth path exits 1 and reports
  ``none`` / ``no-key``.
- Audit trail JSON never embeds API keys, OAuth file contents, or
  response bodies.
- Live smoke dispatch (urlopen mocked) returns ``usable: true`` on 200
  and ``http-401`` on 401 — secrets never echoed in error_class.
- Settings.json + OAuth-file fallbacks resolve the right symbolic path
  label.

All tests stdlib-only and hermetic; ``urllib.request.urlopen`` is
patched in live tests so no real network call happens.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "llm-preflight-auth.py"


def _load_module():
    cache_key = "_test_llm_preflight_auth"
    if cache_key in sys.modules:
        return sys.modules[cache_key]
    spec = importlib.util.spec_from_file_location(cache_key, TOOL)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[cache_key] = module
    spec.loader.exec_module(module)
    return module


def _empty_settings_patch(module):
    """Force ``_settings_json_env`` to return ``{}`` so workstation
    settings.json never leaks into a test."""
    return patch.object(module, "_settings_json_env", return_value={})


def _clean_env(extra: dict | None = None) -> dict:
    """Scrubbed env that drops every preflight-relevant variable.

    The ``AUDITOOOR_KIMI_OAUTH_FILE`` env var is set to a path under
    ``/tmp/no-such-dir-...`` so the kimi OAuth-file fallback ALWAYS
    resolves to "missing" unless a test deliberately overrides it. This
    is necessary because ``_KIMI_OAUTH_FILE_DEFAULT`` is captured at
    module import using the real ``HOME`` and we don't want a
    workstation OAuth file leaking into the test result.
    """
    drop = {
        "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
        "ANTHROPIC_MODEL", "KIMI_API_KEY", "KIMI_ANTHROPIC_BASE_URL",
        "KIMI_MODEL", "MINIMAX_API_KEY", "MINIMAX_ANTHROPIC_BASE_URL",
        "MINIMAX_MODEL", "AUDITOOOR_LLM_PROVIDER",
        "AUDITOOOR_LLM_AUTH_HEADER", "AUDITOOOR_LLM_NETWORK_CONSENT",
        "ADVERSARIAL_LIVE_CONSENT", "AUDITOOOR_LLM_BUDGET_GUARD",
        "AUDITOOOR_KIMI_OAUTH_FILE",
    }
    base = {k: v for k, v in os.environ.items() if k not in drop}
    # Force the kimi OAuth-file fallback to "missing" by default.
    base["AUDITOOOR_KIMI_OAUTH_FILE"] = (
        "/tmp/auditooor-test-no-such-oauth-file.json"
    )
    if extra:
        base.update(extra)
    return base


def _fake_urlopen_200() -> MagicMock:
    rv = MagicMock()
    rv.status = 200
    rv.getcode.return_value = 200
    rv.read.return_value = json.dumps({
        "content": [{"type": "text", "text": "OK"}],
        "model": "x",
        "role": "assistant",
        "stop_reason": "end_turn",
    }).encode("utf-8")
    rv.close.return_value = None
    return rv


class DryRunNoAuthExitZeroMultiTest(unittest.TestCase):
    """Spec: ``Exit 0 if all attempted providers usable OR --dry-run``.

    No-key in multi-provider dry-run is a soft state.
    """

    def test_multi_dry_run_no_keys_exits_zero(self) -> None:
        m = _load_module()
        env = _clean_env()
        buf = io.StringIO()
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ, env, clear=True
        ), _empty_settings_patch(m), patch.object(
            m.sys, "stdout", buf,
        ), patch.object(m.sys, "stderr", err):
            rc = m.main([
                "--dry-run",
                "--audit-dir", tmp,
                "--json",
            ])
            audits = sorted(Path(tmp).glob("llm_preflight_*.json"))
            self.assertEqual(len(audits), 1)
            payload = json.loads(audits[0].read_text())
        self.assertEqual(rc, 0, f"stderr={err.getvalue()!r}")
        # Every provider reports no-key + path=none.
        for line in buf.getvalue().splitlines():
            rec = json.loads(line)
            self.assertEqual(rec["resolution_path"], m.PATH_NONE)
            self.assertEqual(rec["error_class"], m.ERR_NO_KEY)
            self.assertFalse(rec["usable"])
        # Audit trail never contains key-shaped strings.
        text = json.dumps(payload)
        self.assertNotIn("api_key", text)
        self.assertNotIn("access_token", text)


class DryRunExplicitKimiResolvesEnvKeyTest(unittest.TestCase):
    """Spec test #5: ``--provider kimi --dry-run`` returns 0 with valid env."""

    def test_kimi_env_key_dry_run_exit_zero(self) -> None:
        m = _load_module()
        env = _clean_env({"KIMI_API_KEY": "fake-kimi-key"})
        buf = io.StringIO()
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ, env, clear=True
        ), _empty_settings_patch(m), patch.object(
            m.sys, "stdout", buf,
        ), patch.object(m.sys, "stderr", err):
            rc = m.main([
                "--provider", "kimi",
                "--dry-run",
                "--audit-dir", tmp,
                "--json",
            ])
            audit_files = sorted(Path(tmp).glob("llm_preflight_*.json"))
            self.assertEqual(len(audit_files), 1)
            audit_text = audit_files[0].read_text()
        self.assertEqual(rc, 0, f"stderr={err.getvalue()!r}")
        rec = json.loads(buf.getvalue().strip())
        self.assertTrue(rec["usable"])
        self.assertEqual(rec["resolution_path"], m.PATH_ENV_PROVIDER_KEY)
        self.assertIsNone(rec["error_class"])
        # Secret never appears in stdout or audit trail.
        self.assertNotIn("fake-kimi-key", buf.getvalue())
        self.assertNotIn("fake-kimi-key", audit_text)


class DryRunExplicitKimiNoAuthExitsOneTest(unittest.TestCase):
    """Spec test #6: ``--provider kimi --dry-run`` returns 1 when no path resolves."""

    def test_kimi_no_auth_path_dry_run_exit_one(self) -> None:
        m = _load_module()
        env = _clean_env()  # no KIMI_API_KEY, no settings.json, no OAuth file
        buf = io.StringIO()
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ, env, clear=True
        ), _empty_settings_patch(m), patch.object(
            m.sys, "stdout", buf,
        ), patch.object(m.sys, "stderr", err):
            rc = m.main([
                "--provider", "kimi",
                "--dry-run",
                "--audit-dir", tmp,
                "--json",
            ])
        self.assertEqual(rc, 1, f"stdout={buf.getvalue()!r}")
        rec = json.loads(buf.getvalue().strip())
        self.assertFalse(rec["usable"])
        self.assertEqual(rec["resolution_path"], m.PATH_NONE)
        self.assertEqual(rec["error_class"], m.ERR_NO_KEY)


class OAuthFileFallbackResolvesTest(unittest.TestCase):
    """Kimi OAuth file fallback resolves to ``kimi-oauth-file`` path label."""

    def test_oauth_file_path_label_used(self) -> None:
        m = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            oauth_path = Path(tmp) / "kimi-code.json"
            oauth_path.write_text(
                json.dumps({"access_token": "secret-jwt-token"}),
                encoding="utf-8",
            )
            env = _clean_env({
                "AUDITOOOR_KIMI_OAUTH_FILE": str(oauth_path),
            })
            buf = io.StringIO()
            err = io.StringIO()
            with patch.dict(os.environ, env, clear=True), \
                 _empty_settings_patch(m), \
                 patch.object(m.sys, "stdout", buf), \
                 patch.object(m.sys, "stderr", err):
                rc = m.main([
                    "--provider", "kimi",
                    "--dry-run",
                    "--audit-dir", tmp,
                    "--json",
                ])
            audit_files = sorted(Path(tmp).glob("llm_preflight_*.json"))
            audit_text = audit_files[0].read_text()
        self.assertEqual(rc, 0)
        rec = json.loads(buf.getvalue().strip())
        self.assertTrue(rec["usable"])
        self.assertEqual(rec["resolution_path"], m.PATH_KIMI_OAUTH_FILE)
        self.assertEqual(rec["oauth_file"], str(oauth_path))
        # Token never echoed in stdout or audit trail.
        self.assertNotIn("secret-jwt-token", buf.getvalue())
        self.assertNotIn("secret-jwt-token", audit_text)


class LiveSmokeDispatchSuccessTest(unittest.TestCase):
    """When --dry-run is OFF and consent is granted, urlopen 200 -> usable=True."""

    def test_live_smoke_200_marks_usable(self) -> None:
        m = _load_module()
        env = _clean_env({
            "ANTHROPIC_API_KEY": "fake-anthropic-key",
            "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
        })
        buf = io.StringIO()
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ, env, clear=True
        ), _empty_settings_patch(m), patch.object(
            m.sys, "stdout", buf,
        ), patch.object(m.sys, "stderr", err), patch.object(
            m.urllib.request, "urlopen",
            return_value=_fake_urlopen_200(),
        ):
            rc = m.main([
                "--provider", "anthropic",
                "--audit-dir", tmp,
                "--json",
            ])
            audit_files = sorted(Path(tmp).glob("llm_preflight_*.json"))
            audit_text = audit_files[0].read_text()
        self.assertEqual(rc, 0, f"stderr={err.getvalue()!r}")
        rec = json.loads(buf.getvalue().strip())
        self.assertTrue(rec["usable"])
        self.assertIsNone(rec["error_class"])
        self.assertEqual(rec["resolution_path"], m.PATH_ENV_ANTHROPIC_KEY)
        # Secret never echoed.
        self.assertNotIn("fake-anthropic-key", buf.getvalue())
        self.assertNotIn("fake-anthropic-key", audit_text)


class LiveSmokeDispatchHttp401Test(unittest.TestCase):
    """urlopen raises HTTPError(401) -> error_class=http-401, no body leakage."""

    def test_live_smoke_401_classified(self) -> None:
        m = _load_module()
        env = _clean_env({
            "ANTHROPIC_API_KEY": "stale-key",
            "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
        })
        # Build an HTTPError that "echoes" the auth header in its body —
        # exactly the leak we must NOT propagate.
        import urllib.error as ue

        leaky_body = b"Bearer stale-key was rejected"
        http_err = ue.HTTPError(
            url="http://x/v1/messages", code=401, msg="Unauthorized",
            hdrs=None, fp=io.BytesIO(leaky_body),
        )

        buf = io.StringIO()
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ, env, clear=True
        ), _empty_settings_patch(m), patch.object(
            m.sys, "stdout", buf,
        ), patch.object(m.sys, "stderr", err), patch.object(
            m.urllib.request, "urlopen", side_effect=http_err,
        ):
            rc = m.main([
                "--provider", "anthropic",
                "--audit-dir", tmp,
                "--json",
            ])
            audit_files = sorted(Path(tmp).glob("llm_preflight_*.json"))
            audit_text = audit_files[0].read_text()
        self.assertEqual(rc, 1)
        rec = json.loads(buf.getvalue().strip())
        self.assertFalse(rec["usable"])
        self.assertEqual(rec["error_class"], m.ERR_HTTP_401)
        # The body's "stale-key" string never reaches stdout / stderr / audit.
        self.assertNotIn("stale-key", buf.getvalue())
        self.assertNotIn("stale-key", err.getvalue())
        self.assertNotIn("stale-key", audit_text)
        self.assertNotIn("Bearer ", audit_text)


class NoConsentLiveDispatchRefusedTest(unittest.TestCase):
    """Live mode requires the same network-consent env as llm-dispatch."""

    def test_no_consent_marks_no_consent_error(self) -> None:
        m = _load_module()
        env = _clean_env({"ANTHROPIC_API_KEY": "fake"})
        # Note: NO AUDITOOOR_LLM_NETWORK_CONSENT.
        urlopen_mock = MagicMock()
        buf = io.StringIO()
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ, env, clear=True
        ), _empty_settings_patch(m), patch.object(
            m.sys, "stdout", buf,
        ), patch.object(m.sys, "stderr", err), patch.object(
            m.urllib.request, "urlopen", urlopen_mock,
        ):
            rc = m.main([
                "--provider", "anthropic",
                "--audit-dir", tmp,
                "--json",
            ])
        self.assertEqual(rc, 1)
        rec = json.loads(buf.getvalue().strip())
        self.assertFalse(rec["usable"])
        self.assertEqual(rec["error_class"], m.ERR_NO_CONSENT)
        urlopen_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
