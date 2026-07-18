#!/usr/bin/env python3
"""Tests for the Kimi OAuth-token fallback in `tools/llm-dispatch.py`.

Background
----------
The managed `kimi` CLI binary uses an OAuth flow and writes its access
token to `~/.kimi/credentials/kimi-code.json`. Operators on managed-Kimi
setups never set `KIMI_API_KEY` directly. Before this fallback was
added, dispatch returned HTTP 401 even when a valid OAuth session was
active (see `/tmp/poly_v4_run/` campaign — Kimi=0 findings, lost the
cross-check vs Minimax).

Resolution chain for kimi (from `_resolve_api_key`):
  1. env.KIMI_API_KEY
  2. ~/.kimi/credentials/kimi-code.json (overridable via
     AUDITOOOR_KIMI_OAUTH_FILE for tests)
  3. settings.json env.KIMI_API_KEY
  4. settings.json env.ANTHROPIC_AUTH_TOKEN

Test matrix (4 cases, all hermetic):
  (a) KIMI_API_KEY set                         -> uses env (regression)
  (b) env unset + valid OAuth file             -> uses oauth token
  (c) env unset + oauth file missing           -> falls through, no key
  (d) env unset + oauth file malformed JSON    -> warn emitted, skip

All tests mock urllib.request.urlopen and override the OAuth file path
via the AUDITOOOR_KIMI_OAUTH_FILE env var so no real `~/.kimi/` access
occurs. settings.json is also mocked to {} so we isolate the OAuth
behaviour.
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
    """Import llm-dispatch.py as a module despite the hyphen in its name."""
    spec = importlib.util.spec_from_file_location(
        "llm_dispatch_kimi_oauth", LLM_TOOL
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _clean_env(extra: dict | None = None) -> dict:
    """Drop every provider-related var so dev-shell keys don't leak in."""
    drop = {
        "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
        "ANTHROPIC_MODEL", "KIMI_API_KEY", "KIMI_ANTHROPIC_BASE_URL",
        "KIMI_MODEL", "MINIMAX_API_KEY", "MINIMAX_ANTHROPIC_BASE_URL",
        "MINIMAX_MODEL", "AUDITOOOR_LLM_PROVIDER",
        "AUDITOOOR_LLM_AUTH_HEADER", "AUDITOOOR_LLM_NETWORK_CONSENT",
        "ADVERSARIAL_LIVE_CONSENT", "AUDITOOOR_KIMI_OAUTH_FILE",
        "AUDITOOOR_LLM_BUDGET_GUARD",
    }
    base = {k: v for k, v in os.environ.items() if k not in drop}
    # V5-P0-03: budget guard defaults ON; this kimi OAuth test exercises
    # auth resolution only — opt out so the on-disk budget log doesn't
    # interfere.
    base["AUDITOOOR_LLM_BUDGET_GUARD"] = "0"
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
# (a) env-set: KIMI_API_KEY in env wins; oauth file is not consulted.
# -----------------------------------------------------------------------------

class KimiEnvKeyTakesPrecedenceOverOAuthTest(unittest.TestCase):
    """Regression: KIMI_API_KEY set -> oauth file is never read."""

    def test_env_key_wins_oauth_not_read(self) -> None:
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
            # OAuth file present with a different token; must NOT be picked
            # up because env wins.
            oauth_file = tmp_path / "kimi-code.json"
            oauth_file.write_text(
                json.dumps({"access_token": "oauth-token-DO-NOT-USE"}),
                encoding="utf-8",
            )

            env = _clean_env({
                "KIMI_API_KEY": "from-env-key",
                "AUDITOOOR_KIMI_OAUTH_FILE": str(oauth_file),
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
            })
            buf = io.StringIO()
            err_buf = io.StringIO()
            with patch.object(llm.urllib.request, "urlopen", side_effect=side_effect), \
                 patch.object(llm, "_settings_json_env", return_value={}), \
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
            # OAuth-fallback info line must NOT have been emitted.
            self.assertNotIn("OAuth token", err_buf.getvalue())


# -----------------------------------------------------------------------------
# (b) env-unset + oauth file present -> uses oauth token, info line emitted.
# -----------------------------------------------------------------------------

class KimiOAuthFallbackUsesTokenFileTest(unittest.TestCase):
    """env empty -> read access_token from kimi-code.json, use as bearer."""

    def test_oauth_token_used_when_env_unset(self) -> None:
        llm = _load_llm_dispatch()
        captured_auth: list[str] = []

        def side_effect(req, *_a, **_kw):
            captured_auth.append(req.headers.get("X-api-key", ""))
            return _fake_urlopen_200(
                {"content": [{"type": "text", "text": "kimi-oauth-ok"}]}
            )

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("ping", encoding="utf-8")
            audit_dir = tmp_path / "audit"
            oauth_file = tmp_path / "kimi-code.json"
            oauth_file.write_text(
                json.dumps({
                    "access_token": "jwt-from-oauth-file",
                    "refresh_token": "refresh-token-ignored",
                    "expires_at": 1777211447.35817,
                    "scope": "kimi-code",
                    "token_type": "Bearer",
                }),
                encoding="utf-8",
            )

            env = _clean_env({
                "AUDITOOOR_KIMI_OAUTH_FILE": str(oauth_file),
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
            })
            buf = io.StringIO()
            err_buf = io.StringIO()
            with patch.object(llm.urllib.request, "urlopen", side_effect=side_effect), \
                 patch.object(llm, "_settings_json_env", return_value={}), \
                 patch.dict(os.environ, env, clear=True), \
                 patch.object(llm.sys, "stdout", buf), \
                 patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "kimi",
                    "--audit-dir", str(audit_dir),
                ])
            self.assertEqual(rc, 0, f"stderr={err_buf.getvalue()!r}")
            self.assertIn("kimi-oauth-ok", buf.getvalue())
            self.assertEqual(captured_auth, ["jwt-from-oauth-file"])
            # Info line confirms which credential path won.
            self.assertIn("OAuth token", err_buf.getvalue())
            self.assertIn(str(oauth_file), err_buf.getvalue())


# -----------------------------------------------------------------------------
# (c) env-unset + oauth file missing -> existing skip behaviour preserved.
# -----------------------------------------------------------------------------

class KimiOAuthFileMissingFallsThroughTest(unittest.TestCase):
    """No env, no oauth file, no settings.json -> exit 2 / no-api-key."""

    def test_missing_oauth_file_falls_through_to_no_api_key(self) -> None:
        llm = _load_llm_dispatch()
        urlopen_mock = MagicMock()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("ping", encoding="utf-8")
            audit_dir = tmp_path / "audit"
            # Pointer at a file that does not exist.
            oauth_file = tmp_path / "does-not-exist.json"
            self.assertFalse(oauth_file.exists())

            env = _clean_env({
                "AUDITOOOR_KIMI_OAUTH_FILE": str(oauth_file),
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
            })
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
            # Silent fall-through: no warn or info noise emitted.
            self.assertNotIn("kimi-credentials-malformed", stderr_text)
            self.assertNotIn("OAuth token", stderr_text)


# -----------------------------------------------------------------------------
# (d) env-unset + oauth file malformed -> warn emitted, provider skipped.
# -----------------------------------------------------------------------------

class KimiOAuthFileMalformedEmitsWarnTest(unittest.TestCase):
    """File present but garbage JSON -> warn + skip provider."""

    def test_malformed_oauth_file_warns_and_skips(self) -> None:
        llm = _load_llm_dispatch()
        urlopen_mock = MagicMock()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("ping", encoding="utf-8")
            audit_dir = tmp_path / "audit"
            oauth_file = tmp_path / "kimi-code.json"
            # Not valid JSON.
            oauth_file.write_text("this is not json {{{", encoding="utf-8")

            env = _clean_env({
                "AUDITOOOR_KIMI_OAUTH_FILE": str(oauth_file),
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
            })
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
            # warn was emitted ...
            self.assertIn("kimi-credentials-malformed", stderr_text)
            # ... and provider was skipped (no real call).
            urlopen_mock.assert_not_called()
            self.assertIn("cannot-run: no-api-key", stderr_text)


# -----------------------------------------------------------------------------
# I9 (#320) — OAuth token expiry helpers + refresh path.
# -----------------------------------------------------------------------------

class KimiOAuthExpiresAtParserTest(unittest.TestCase):
    """The `_kimi_oauth_expires_at` helper extracts the float
    `expires_at` from the credentials file or returns None on any
    malformation. Used by the refresh path to decide whether to roll
    the token before dispatch."""

    def test_returns_float_for_well_formed_file(self) -> None:
        llm = _load_llm_dispatch()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kimi-code.json"
            path.write_text(
                json.dumps({"access_token": "x", "expires_at": 1234567890.5}),
                encoding="utf-8",
            )
            self.assertEqual(llm._kimi_oauth_expires_at(path), 1234567890.5)

    def test_returns_none_when_file_missing(self) -> None:
        llm = _load_llm_dispatch()
        self.assertIsNone(
            llm._kimi_oauth_expires_at(Path("/nonexistent-/-nope-12345"))
        )

    def test_returns_none_when_expires_at_missing(self) -> None:
        llm = _load_llm_dispatch()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kimi-code.json"
            path.write_text(
                json.dumps({"access_token": "x"}),  # no expires_at
                encoding="utf-8",
            )
            self.assertIsNone(llm._kimi_oauth_expires_at(path))

    def test_returns_none_when_expires_at_not_numeric(self) -> None:
        llm = _load_llm_dispatch()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kimi-code.json"
            path.write_text(
                json.dumps({"access_token": "x", "expires_at": "soon"}),
                encoding="utf-8",
            )
            self.assertIsNone(llm._kimi_oauth_expires_at(path))

    def test_returns_none_on_malformed_json(self) -> None:
        llm = _load_llm_dispatch()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kimi-code.json"
            path.write_text("not json {{{", encoding="utf-8")
            self.assertIsNone(llm._kimi_oauth_expires_at(path))


class KimiOAuthRefreshDisabledTest(unittest.TestCase):
    """The refresh helper honours `AUDITOOOR_KIMI_OAUTH_REFRESH_DISABLED=1`
    so tests can deterministically exercise the "refresh failed" branch
    without invoking the real `kimi` CLI."""

    def test_disabled_env_returns_false_without_invoking_cli(self) -> None:
        llm = _load_llm_dispatch()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kimi-code.json"
            path.write_text(
                json.dumps({"access_token": "x", "expires_at": 0}),
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {"AUDITOOOR_KIMI_OAUTH_REFRESH_DISABLED": "1"},
                clear=False,
            ), patch.object(
                llm.subprocess, "run",
                side_effect=AssertionError("refresh CLI must not be invoked"),
            ):
                self.assertFalse(llm._kimi_oauth_refresh_via_cli(path))


class KimiOAuthRefreshCliMissingTest(unittest.TestCase):
    """When `kimi` is not on PATH, refresh fails fast with a clear warn
    instead of crashing."""

    def test_cli_missing_returns_false(self) -> None:
        llm = _load_llm_dispatch()
        err_buf = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kimi-code.json"
            path.write_text(
                json.dumps({"access_token": "x", "expires_at": 0}),
                encoding="utf-8",
            )
            with patch.object(llm.shutil, "which", return_value=None), \
                 patch.dict(os.environ, {}, clear=False), \
                 patch.object(llm.sys, "stderr", err_buf):
                # Ensure the disabled-env override isn't set from an
                # earlier test.
                os.environ.pop(
                    "AUDITOOOR_KIMI_OAUTH_REFRESH_DISABLED", None
                )
                self.assertFalse(llm._kimi_oauth_refresh_via_cli(path))
        self.assertIn("kimi-cli-not-on-path", err_buf.getvalue())


class KimiOAuthRefreshSucceedsWhenCliRewritesFileTest(unittest.TestCase):
    """When the (mocked) `kimi` CLI rewrites the credentials file with
    a fresh `expires_at` in the future, the helper returns True."""

    def test_refresh_returns_true_on_fresh_token(self) -> None:
        import time as _time
        llm = _load_llm_dispatch()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kimi-code.json"
            # Stale starting state.
            path.write_text(
                json.dumps({
                    "access_token": "old",
                    "expires_at": _time.time() - 3600,
                }),
                encoding="utf-8",
            )

            def fake_run(cmd, **kw):
                # Simulate the CLI rotating the token in place: bump the
                # expires_at into the future. This is exactly what the
                # real CLI does on first invocation when the token is
                # near-expiry.
                path.write_text(
                    json.dumps({
                        "access_token": "new",
                        "expires_at": _time.time() + 900,
                    }),
                    encoding="utf-8",
                )
                rv = MagicMock()
                rv.returncode = 0
                rv.stdout = ""
                rv.stderr = ""
                return rv

            with patch.object(llm.shutil, "which",
                              return_value="/usr/local/bin/kimi"), \
                 patch.object(llm.subprocess, "run", side_effect=fake_run), \
                 patch.dict(os.environ, {}, clear=False):
                os.environ.pop(
                    "AUDITOOOR_KIMI_OAUTH_REFRESH_DISABLED", None
                )
                self.assertTrue(llm._kimi_oauth_refresh_via_cli(path))
            # Verify the new token actually landed.
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["access_token"], "new")


class KimiOAuthRefreshFailsWhenCliDoesNotRefreshTest(unittest.TestCase):
    """If the (mocked) CLI exits 0 but doesn't rewrite the file, the
    helper detects the still-stale `expires_at` and returns False with
    a warn. This catches a future regression where the CLI's refresh
    flow silently no-ops."""

    def test_returns_false_when_token_still_expired_after_cli(self) -> None:
        import time as _time
        llm = _load_llm_dispatch()
        err_buf = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kimi-code.json"
            path.write_text(
                json.dumps({
                    "access_token": "stale",
                    "expires_at": _time.time() - 60,
                }),
                encoding="utf-8",
            )

            def fake_run(cmd, **kw):
                rv = MagicMock()
                rv.returncode = 0
                rv.stdout = ""
                rv.stderr = ""
                return rv  # Note: file untouched

            with patch.object(llm.shutil, "which",
                              return_value="/usr/local/bin/kimi"), \
                 patch.object(llm.subprocess, "run", side_effect=fake_run), \
                 patch.dict(os.environ, {}, clear=False), \
                 patch.object(llm.sys, "stderr", err_buf):
                os.environ.pop(
                    "AUDITOOOR_KIMI_OAUTH_REFRESH_DISABLED", None
                )
                self.assertFalse(llm._kimi_oauth_refresh_via_cli(path))
        self.assertIn("token-still-expired-after-cli-invocation",
                      err_buf.getvalue())


if __name__ == "__main__":
    unittest.main()
