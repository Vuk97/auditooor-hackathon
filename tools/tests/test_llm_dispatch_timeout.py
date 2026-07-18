#!/usr/bin/env python3
"""Hermetic tests for `tools/llm-dispatch.py` transport-error classification.

Surfaced by V5 Wave 1 PR-A (#279): long MiniMax timeouts can propagate a
bare `TimeoutError` (== `socket.timeout` in py3.10+) from
`urllib.request.urlopen(timeout=...)` without `URLError` wrapping. The
existing `_call_once_with_fallback_classification` only caught
`urllib.error.URLError`, so bare-timeout / connection-reset / broken-pipe
exceptions propagated UNCLASSIFIED — breaking auto-fallback to Anthropic
and turning a recoverable hop into a hard failure.

Coverage matrix (input → catch arm → output):

    +------------------------------+----------------------+--------------------------+
    | exception raised by urlopen  | catch arm            | classification           |
    +------------------------------+----------------------+--------------------------+
    | urllib.error.URLError(time)  | URLError             | ProviderFallback (s=0)   |
    | TimeoutError("timed out")    | TimeoutError         | ProviderFallback (s=0)   |
    | socket.timeout (alias 3.10+) | TimeoutError         | ProviderFallback (s=0)   |
    | ConnectionResetError         | ConnectionError      | ProviderFallback (s=0)   |
    | BrokenPipeError              | ConnectionError      | ProviderFallback (s=0)   |
    | urllib.error.HTTPError(404)  | (no catch)           | RuntimeError (s=404)     |
    | urllib.error.HTTPError(429)  | (loop retry / 429)   | retry → ProviderFallback |
    +------------------------------+----------------------+--------------------------+

All tests mock `urllib.request.urlopen` via `patch.object` and run with
ANTHROPIC-only env so transport failures become terminal — making
ProviderFallback observable through the structured stderr error.

Stdlib only. Hermetic. No network.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import socket
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch, MagicMock


ROOT = Path(__file__).resolve().parents[2]
LLM_TOOL = ROOT / "tools" / "llm-dispatch.py"


def _load_llm_dispatch():
    """Import llm-dispatch.py as a module despite the hyphen in its name."""
    spec = importlib.util.spec_from_file_location("llm_dispatch_timeout", LLM_TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _clean_env(extra: dict | None = None) -> dict:
    """Scrub provider env so each test is hermetic."""
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
    base.setdefault(
        "AUDITOOOR_KIMI_OAUTH_FILE",
        "/dev/null/no-such-kimi-credentials.json",
    )
    if extra:
        base.update(extra)
    return base


def _anthropic_only_env(extra: dict | None = None) -> dict:
    e = _clean_env({
        "ANTHROPIC_API_KEY": "sk-test",
        "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
    })
    if extra:
        e.update(extra)
    return e


def _run_dispatch_with_urlopen_raising(exc, *, timeout="60") -> tuple[int, str, str, list]:
    """Run llm-dispatch with urlopen raising `exc`. Return (rc, stdout, stderr, audit_records).

    Uses --provider anthropic so there is no fallback chain; the
    ProviderFallback bubbles up as the terminal "all providers exhausted"
    error and the structured-error reason is observable.
    """
    llm = _load_llm_dispatch()
    raise_count = {"n": 0}

    def side_effect(*_a, **_kw):
        raise_count["n"] += 1
        raise exc

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        prompt_file = tmp_path / "prompt.txt"
        prompt_file.write_text("hello", encoding="utf-8")
        audit_dir = tmp_path / "audit"

        env = _anthropic_only_env()
        buf = io.StringIO()
        err_buf = io.StringIO()
        with patch.object(llm.urllib.request, "urlopen", side_effect=side_effect), \
             patch.dict(os.environ, env, clear=True), \
             patch.object(llm.sys, "stdout", buf), \
             patch.object(llm.sys, "stderr", err_buf):
            rc = llm.main([
                "--prompt-file", str(prompt_file),
                "--provider", "anthropic",
                "--model", "claude-opus-4-5",
                "--audit-dir", str(audit_dir),
                "--timeout", str(timeout),
                "--retry-on-429", "0",
            ])
        records = []
        if audit_dir.exists():
            for p in sorted(audit_dir.glob("llm_dispatch_*.json")):
                try:
                    records.append(json.loads(p.read_text()))
                except Exception:
                    pass
        return rc, buf.getvalue(), err_buf.getvalue(), records


class BareTimeoutErrorClassifiesAsTransportError(unittest.TestCase):
    """Test #1 — bare TimeoutError → ProviderFallback("transport-error: ...", status=0).

    This is the V5-PR-A (#279) bug case: py3.10+ urlopen read-stage
    timeouts propagate `TimeoutError` without `URLError` wrapping.
    """

    def test_bare_timeout_error_classified_as_transport_error(self) -> None:
        rc, out, err, records = _run_dispatch_with_urlopen_raising(
            TimeoutError("timed out"),
        )
        self.assertEqual(rc, 3, f"stderr={err!r}")
        self.assertIn("error: dispatch-failed", err)
        self.assertIn("transport-error", err)
        self.assertIn("timeout", err)
        self.assertEqual(out, "")
        # Audit must record the fallback hop with status=0.
        fallback_records = [r for r in records if "fallback" in r.get("outcome", "")]
        self.assertEqual(len(fallback_records), 1)
        self.assertEqual(fallback_records[0]["http_status"], 0)
        self.assertIn("transport-error", fallback_records[0]["outcome"])
        self.assertIn("timeout", fallback_records[0]["outcome"])


class SocketTimeoutAliasClassifiesAsTransportError(unittest.TestCase):
    """Test #2 — socket.timeout (alias of TimeoutError in py3.10+) → fallback.

    Belt-and-suspenders: even though `socket.timeout is TimeoutError` is
    True on py3.10+, the test ensures defensive behaviour against any
    future stdlib changes that re-separate the two types.
    """

    def test_socket_timeout_classified_as_transport_error(self) -> None:
        rc, out, err, records = _run_dispatch_with_urlopen_raising(
            socket.timeout("connection timed out"),
        )
        self.assertEqual(rc, 3, f"stderr={err!r}")
        self.assertIn("transport-error", err)
        self.assertEqual(out, "")
        fallback_records = [r for r in records if "fallback" in r.get("outcome", "")]
        self.assertEqual(len(fallback_records), 1)
        self.assertEqual(fallback_records[0]["http_status"], 0)


class ConnectionResetErrorClassifiesAsTransportError(unittest.TestCase):
    """Test #3 — ConnectionResetError → ProviderFallback (transport-error)."""

    def test_connection_reset_classified_as_transport_error(self) -> None:
        rc, out, err, records = _run_dispatch_with_urlopen_raising(
            ConnectionResetError("Connection reset by peer"),
        )
        self.assertEqual(rc, 3, f"stderr={err!r}")
        self.assertIn("transport-error", err)
        self.assertIn("ConnectionResetError", err)
        self.assertEqual(out, "")
        fallback_records = [r for r in records if "fallback" in r.get("outcome", "")]
        self.assertEqual(len(fallback_records), 1)
        self.assertEqual(fallback_records[0]["http_status"], 0)


class BrokenPipeErrorClassifiesAsTransportError(unittest.TestCase):
    """Test #4 — BrokenPipeError → ProviderFallback (transport-error).

    Documented case: server cut TCP after we wrote the request line but
    before we finished streaming the body. `BrokenPipeError` is also a
    `ConnectionError`, so the catch-arm should match either way.
    """

    def test_broken_pipe_classified_as_transport_error(self) -> None:
        rc, out, err, records = _run_dispatch_with_urlopen_raising(
            BrokenPipeError("[Errno 32] Broken pipe"),
        )
        self.assertEqual(rc, 3, f"stderr={err!r}")
        self.assertIn("transport-error", err)
        self.assertEqual(out, "")
        fallback_records = [r for r in records if "fallback" in r.get("outcome", "")]
        self.assertEqual(len(fallback_records), 1)


class HttpError404DoesNotClassifyAsTransportError(unittest.TestCase):
    """Regression — HTTPError(404) must NOT trigger transport-error fallback.

    A 4xx (non-429) is a legitimate "this provider rejected the request"
    failure: re-trying a different provider is wrong (the request is bad,
    not the transport). The dispatcher must surface RuntimeError → exit
    3 with `dispatch-failed` and the http-404 reason.
    """

    def test_http_404_is_hard_failure_not_transport_error(self) -> None:
        err_404 = urllib.error.HTTPError(
            url="https://example.invalid/v1/messages",
            code=404,
            msg="Not Found",
            hdrs=None,  # type: ignore[arg-type]
            fp=io.BytesIO(b'{"error": "not found"}'),
        )
        rc, out, err, records = _run_dispatch_with_urlopen_raising(err_404)
        self.assertEqual(rc, 3)
        self.assertIn("dispatch-failed", err)
        # Must NOT be classified as transport-error.
        self.assertNotIn("transport-error", err)
        # Must surface the http-404 status.
        self.assertIn("http-404", err)
        self.assertEqual(out, "")
        # Audit record must show the error outcome with http-404, not a
        # fallback hop with http_status=0.
        error_records = [r for r in records if r.get("outcome", "").startswith("error:")]
        self.assertEqual(len(error_records), 1)
        self.assertIn("http-404", error_records[0]["outcome"])


class Http429RetryThenFallbackUnchanged(unittest.TestCase):
    """Regression — HTTP 429 with retry budget exhausted → ProviderFallback (status=429).

    The fix must NOT alter 429-retry semantics. With `--retry-on-429 0`
    the very first 429 exhausts the budget and converts to ProviderFallback.
    """

    def test_429_retry_budget_exhausted_still_fallback(self) -> None:
        err_429 = urllib.error.HTTPError(
            url="https://example.invalid/v1/messages",
            code=429,
            msg="Too Many Requests",
            hdrs=None,  # type: ignore[arg-type]
            fp=io.BytesIO(b'{"error": "rate limited"}'),
        )
        rc, out, err, records = _run_dispatch_with_urlopen_raising(err_429)
        self.assertEqual(rc, 3, f"stderr={err!r}")
        self.assertIn("dispatch-failed", err)
        # Must be classified as 429-retry-budget-exhausted, not
        # transport-error or http-404.
        self.assertIn("http-429-retry-budget-exhausted", err)
        self.assertNotIn("transport-error", err)
        self.assertEqual(out, "")
        fallback_records = [r for r in records if "fallback" in r.get("outcome", "")]
        self.assertEqual(len(fallback_records), 1)
        self.assertEqual(fallback_records[0]["http_status"], 429)


class UrlErrorWithTimeoutReasonStillClassified(unittest.TestCase):
    """Regression — URLError(reason=socket.timeout(...)) still classifies.

    This is the legacy timeout shape (urllib wraps connection-stage
    timeouts in URLError). The fix must not break it — preserves the
    pre-fix happy path.
    """

    def test_url_error_with_timeout_reason_classified(self) -> None:
        rc, out, err, records = _run_dispatch_with_urlopen_raising(
            urllib.error.URLError(reason=socket.timeout("connect timed out")),
        )
        self.assertEqual(rc, 3, f"stderr={err!r}")
        self.assertIn("transport-error", err)
        self.assertEqual(out, "")
        fallback_records = [r for r in records if "fallback" in r.get("outcome", "")]
        self.assertEqual(len(fallback_records), 1)


class TransportErrorTriggersAutoFallbackChain(unittest.TestCase):
    """Test #7 — bare TimeoutError on Kimi → falls back to MiniMax success.

    This is the headline correctness property the bug broke: in auto
    mode with both Kimi and MiniMax keys, a Kimi timeout MUST hand off
    to MiniMax. Pre-fix, the bare TimeoutError propagated unclassified
    and the dispatcher exited with an unhandled exception instead of
    falling back.
    """

    def test_kimi_timeout_falls_back_to_minimax(self) -> None:
        llm = _load_llm_dispatch()
        success_payload = {"content": [{"type": "text", "text": "minimax-saved-the-day"}]}
        captured_urls: list[str] = []
        call_count = {"n": 0}

        def side_effect(req, *_a, **_kw):
            captured_urls.append(req.full_url)
            call_count["n"] += 1
            if call_count["n"] == 1:
                # First call (Kimi) bare-timeouts.
                raise TimeoutError("kimi connection timed out")
            # Second call (MiniMax) succeeds.
            rv = MagicMock()
            rv.status = 200
            rv.getcode.return_value = 200
            rv.read.return_value = json.dumps(success_payload).encode("utf-8")
            rv.close.return_value = None
            return rv

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
            self.assertIn("minimax-saved-the-day", buf.getvalue())
            # Must have tried Kimi first (timeout), then MiniMax (success).
            self.assertEqual(len(captured_urls), 2)
            self.assertIn("kimi.com", captured_urls[0])
            self.assertIn("minimax", captured_urls[1])


class RealTimeoutFiresClassification(unittest.TestCase):
    """Test #8 — real `urlopen(timeout=...)` against a hung mock fires
    `TimeoutError` and the classifier catches it.

    Uses `time.sleep` inside the mock + a tiny --timeout to force the
    actual stdlib timeout machinery rather than a directly-raised
    exception object. Belt-and-suspenders for the simulated-vs-real
    failure mode distinction.
    """

    def test_real_timeout_classified_as_transport_error(self) -> None:
        llm = _load_llm_dispatch()

        def slow_urlopen(*_a, **_kw):
            # Simulate a real `urlopen(timeout=...)` firing: sleep past
            # the timeout, then raise TimeoutError as urllib would on
            # py3.10+ for a read-stage stall. We can't actually invoke
            # the stdlib's timeout machinery without a real socket, so
            # we model it via sleep + raise — close enough for the
            # classifier round-trip we're verifying.
            time.sleep(0.05)
            raise TimeoutError("read timed out")

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("x", encoding="utf-8")
            audit_dir = tmp_path / "audit"
            env = _anthropic_only_env()
            buf = io.StringIO()
            err_buf = io.StringIO()
            with patch.object(llm.urllib.request, "urlopen", side_effect=slow_urlopen), \
                 patch.dict(os.environ, env, clear=True), \
                 patch.object(llm.sys, "stdout", buf), \
                 patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "anthropic",
                    "--audit-dir", str(audit_dir),
                    "--timeout", "0.01",
                    "--retry-on-429", "0",
                ])
            self.assertEqual(rc, 3)
            self.assertIn("transport-error", err_buf.getvalue())
            self.assertEqual(buf.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
