#!/usr/bin/env python3
"""capability-v3 iter-v3-5 T1 — llm-dispatch + swarm SWARM_REAL_DISPATCH tests.

Hermetic: no live Anthropic API, no network. All HTTPS boundaries are
stubbed via `unittest.mock.patch` on `urllib.request.urlopen`. One
regression test locks the default-mode (printer) byte-for-byte output
of `tools/swarm-orchestrator.py --dispatch` — the contract that the
existing iter-v3-3 T2 dry-run artefacts depend on.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch, MagicMock


ROOT = Path(__file__).resolve().parents[2]
LLM_TOOL = ROOT / "tools" / "llm-dispatch.py"
SWARM_TOOL = ROOT / "tools" / "swarm-orchestrator.py"


def _load_llm_dispatch():
    """Import llm-dispatch.py as a module despite the hyphen in its name."""
    spec = importlib.util.spec_from_file_location("llm_dispatch", LLM_TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _fake_urlopen_200(payload: dict) -> MagicMock:
    """Build an urllib.request.urlopen-shaped mock for a 200 OK response."""
    rv = MagicMock()
    rv.status = 200
    rv.getcode.return_value = 200
    rv.read.return_value = json.dumps(payload).encode("utf-8")
    rv.close.return_value = None
    return rv


def _fake_urlopen_429() -> MagicMock:
    """Mock a 429 HTTPError (urlopen raises HTTPError on non-2xx)."""
    # HTTPError needs (url, code, msg, hdrs, fp)
    err = urllib.error.HTTPError(
        url="https://api.anthropic.com/v1/messages",
        code=429,
        msg="Too Many Requests",
        hdrs=None,  # type: ignore[arg-type]
        fp=io.BytesIO(b'{"error": "rate_limited"}'),
    )
    return err


def _fake_urlopen_200_malformed(body: bytes) -> MagicMock:
    rv = MagicMock()
    rv.status = 200
    rv.getcode.return_value = 200
    rv.read.return_value = body
    rv.close.return_value = None
    return rv


class LlmDispatchHappyPathTest(unittest.TestCase):
    """Test #1 — happy path: 200 → stdout carries response text."""

    def test_happy_path_returns_response_text_to_stdout(self) -> None:
        llm = _load_llm_dispatch()
        payload = {
            "content": [{"type": "text", "text": "VERDICT CONTESTED: mutex racey."}],
            "model": "claude-opus-4-5",
            "role": "assistant",
            "stop_reason": "end_turn",
        }
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("contest these verdicts:\n- DUPE\n", encoding="utf-8")

            # Explicit anthropic provider with only ANTHROPIC_API_KEY set
            # avoids auto-mode picking up Kimi/MiniMax from a dev shell.
            cleaned_env = {
                k: v for k, v in os.environ.items()
                if k not in (
                    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "KIMI_API_KEY",
                    "MINIMAX_API_KEY", "AUDITOOOR_LLM_PROVIDER",
                    "ANTHROPIC_BASE_URL", "ANTHROPIC_MODEL",
                    "KIMI_ANTHROPIC_BASE_URL", "MINIMAX_ANTHROPIC_BASE_URL",
                    "AUDITOOOR_LLM_AUTH_HEADER",
                )
            }
            env = dict(cleaned_env)
            env.update({
                "ANTHROPIC_API_KEY": "sk-test",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
                # V5-P0-03: budget guard defaults ON; opt out for the
                # auth/content-shape tests that don't exercise it.
                "AUDITOOOR_LLM_BUDGET_GUARD": "0",
            })
            audit_dir = tmp_path / "audit"

            # Patch urlopen at the module-local binding.
            with patch.object(
                llm.urllib.request, "urlopen",
                return_value=_fake_urlopen_200(payload),
            ):
                # Capture stdout from main().
                buf = io.StringIO()
                err_buf = io.StringIO()
                with patch.dict(os.environ, env, clear=True), \
                     patch.object(llm.sys, "stdout", buf), \
                     patch.object(llm.sys, "stderr", err_buf):
                    rc = llm.main([
                        "--prompt-file", str(prompt_file),
                        "--provider", "anthropic",
                        "--model", "claude-opus-4-5",
                        "--max-tokens", "100",
                        "--audit-dir", str(audit_dir),
                    ])
            self.assertEqual(rc, 0, f"main() returned {rc}; stderr={err_buf.getvalue()!r}")
            self.assertIn("VERDICT CONTESTED", buf.getvalue())
            # Audit trail written, no prompt/response body inside.
            audit_files = list(audit_dir.glob("llm_dispatch_*.json"))
            self.assertEqual(len(audit_files), 1)
            record = json.loads(audit_files[0].read_text())
            self.assertEqual(record["http_status"], 200)
            self.assertEqual(record["model"], "claude-opus-4-5")
            self.assertEqual(record["retry_count"], 0)
            self.assertEqual(record["outcome"], "ok")
            self.assertEqual(record["provider"], "anthropic")
            self.assertIn("api_url_host", record)
            self.assertNotIn("sk-test", audit_files[0].read_text())
            # Prompt/response bodies NOT leaked into audit trail.
            self.assertNotIn("VERDICT CONTESTED", audit_files[0].read_text())
            self.assertNotIn("contest these verdicts", audit_files[0].read_text())

    def test_advisory_dispatch_records_routing_status(self) -> None:
        llm = _load_llm_dispatch()
        payload = {
            "content": [{"type": "text", "text": "OK advisory output"}],
            "model": "claude-opus-4-5",
            "role": "assistant",
            "stop_reason": "end_turn",
        }
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("summarize docs", encoding="utf-8")
            audit_dir = tmp_path / "audit"
            env = {
                "ANTHROPIC_API_KEY": "sk-test",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
                "AUDITOOOR_LLM_BUDGET_GUARD": "0",
            }
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
                    "--provider", "anthropic",
                    "--model", "claude-opus-4-5",
                    "--task-type", "docs-integration",
                    "--audit-dir", str(audit_dir),
                ])
            self.assertEqual(rc, 0, err_buf.getvalue())
            self.assertIn("OK advisory output", buf.getvalue())
            record = json.loads(next(audit_dir.glob("llm_dispatch_*.json")).read_text())
            self.assertEqual(record["task_type"], "docs-integration")
            self.assertTrue(record["routing_status"]["advisory_only"])
            self.assertEqual(record["routing_status"]["provider"], "claude")

    def test_promotion_dispatch_fails_closed_when_precision_missing(self) -> None:
        llm = _load_llm_dispatch()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("wire poc", encoding="utf-8")
            audit_dir = tmp_path / "audit"
            env = {
                "ANTHROPIC_API_KEY": "sk-test",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
                "AUDITOOOR_LLM_BUDGET_GUARD": "0",
            }
            buf = io.StringIO()
            err_buf = io.StringIO()
            with patch.object(llm.urllib.request, "urlopen") as urlopen_mock, \
                 patch.dict(os.environ, env, clear=True), \
                 patch.object(llm.sys, "stdout", buf), \
                 patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "anthropic",
                    "--model", "claude-opus-4-5",
                    "--task-type", "poc-wiring",
                    "--routing-purpose", "promotion",
                    "--audit-dir", str(audit_dir),
                ])
            self.assertEqual(rc, 2)
            urlopen_mock.assert_not_called()
            self.assertIn("cannot-run: advisory-only-routing", err_buf.getvalue())
            self.assertEqual(buf.getvalue(), "")
            record = json.loads(next(audit_dir.glob("llm_dispatch_*.json")).read_text())
            # P0-3 burn-down (2026-04-29): the seed calibration matrix at
            # reference/llm_calibration_seed.json refuses lanes with no
            # row (cannot-route: no-calibration) before the JSONL ledger
            # is consulted. ``poc-wiring`` is not present in the seed
            # (the lane was split into harness-implementation /
            # fixture-wiring), so dispatch sees the no-calibration
            # refusal rather than the legacy missing-precision-data path.
            self.assertEqual(
                record["outcome"], "routing-skip: cannot-route: no-calibration"
            )
            self.assertTrue(record["routing_status"]["advisory_only"])


class LlmDispatchMissingKeyTest(unittest.TestCase):
    """Test #2 — missing ANTHROPIC_API_KEY → exit 2 + cannot-run."""

    def test_missing_api_key_exits_with_cannot_run_code(self) -> None:
        llm = _load_llm_dispatch()
        with tempfile.TemporaryDirectory() as tmp:
            prompt_file = Path(tmp) / "prompt.txt"
            prompt_file.write_text("x", encoding="utf-8")

            buf = io.StringIO()
            err_buf = io.StringIO()
            # Strip ALL provider keys so that --provider anthropic explicitly
            # falls back to the no-api-key path. Consent is granted so we
            # exercise the *second* gate (missing key), not the consent gate.
            cleaned_env = {
                k: v for k, v in os.environ.items()
                if k not in (
                    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
                    "KIMI_API_KEY", "MINIMAX_API_KEY",
                    "AUDITOOOR_LLM_PROVIDER",
                )
            }
            cleaned_env["AUDITOOOR_LLM_NETWORK_CONSENT"] = "1"
            # V5-P0-03: budget guard defaults ON; opt out for tests that
            # don't exercise budget bookkeeping.
            cleaned_env["AUDITOOOR_LLM_BUDGET_GUARD"] = "0"
            with patch.dict(os.environ, cleaned_env, clear=True), \
                 patch.object(llm.sys, "stdout", buf), \
                 patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "anthropic",
                    "--model", "claude-opus-4-5",
                ])
            self.assertEqual(rc, 2)
            # Structured error JSON on stderr.
            stderr_text = err_buf.getvalue()
            self.assertIn("cannot-run: no-api-key", stderr_text)
            # stdout stays empty.
            self.assertEqual(buf.getvalue(), "")


class LlmDispatchTimeoutTest(unittest.TestCase):
    """Test #3 — URLError (timeout / transport fail) → exit 3 + error."""

    def test_timeout_exits_with_error_code(self) -> None:
        llm = _load_llm_dispatch()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("x", encoding="utf-8")
            audit_dir = tmp_path / "audit"

            def raise_url_error(*_a, **_kw):
                raise urllib.error.URLError("timed out")

            # Explicit anthropic provider — no auto fallback chain —
            # so transport-error becomes the terminal failure.
            cleaned_env = {
                k: v for k, v in os.environ.items()
                if k not in (
                    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "KIMI_API_KEY",
                    "MINIMAX_API_KEY", "AUDITOOOR_LLM_PROVIDER",
                )
            }
            cleaned_env.update({
                "ANTHROPIC_API_KEY": "sk-test",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
                # V5-P0-03: budget guard defaults ON; opt out for the
                # auth/content-shape tests that don't exercise it.
                "AUDITOOOR_LLM_BUDGET_GUARD": "0",
            })
            buf = io.StringIO()
            err_buf = io.StringIO()
            with patch.object(llm.urllib.request, "urlopen", side_effect=raise_url_error), \
                 patch.dict(os.environ, cleaned_env, clear=True), \
                 patch.object(llm.sys, "stdout", buf), \
                 patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "anthropic",
                    "--model", "claude-opus-4-5",
                    "--audit-dir", str(audit_dir),
                ])
            self.assertEqual(rc, 3)
            self.assertIn("error: dispatch-failed", err_buf.getvalue())
            self.assertIn("transport-error", err_buf.getvalue())
            self.assertEqual(buf.getvalue(), "")


class LlmDispatch429RetryTest(unittest.TestCase):
    """Test #4 — 429 with retry budget: first N raise 429, then 200 OK."""

    def test_429_retries_then_succeeds(self) -> None:
        llm = _load_llm_dispatch()
        payload = {
            "content": [{"type": "text", "text": "VERDICT HOLDS: ok."}],
        }
        # Sequence: 429, 429, 200 (retry budget = 2).
        fake_200 = _fake_urlopen_200(payload)
        call_log = {"n": 0}

        def side_effect(*_a, **_kw):
            call_log["n"] += 1
            if call_log["n"] <= 2:
                raise _fake_urlopen_429()
            return fake_200

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("x", encoding="utf-8")
            audit_dir = tmp_path / "audit"

            cleaned_env = {
                k: v for k, v in os.environ.items()
                if k not in (
                    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "KIMI_API_KEY",
                    "MINIMAX_API_KEY", "AUDITOOOR_LLM_PROVIDER",
                )
            }
            cleaned_env.update({
                "ANTHROPIC_API_KEY": "sk-test",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
                # V5-P0-03: budget guard defaults ON; opt out for the
                # auth/content-shape tests that don't exercise it.
                "AUDITOOOR_LLM_BUDGET_GUARD": "0",
            })
            buf = io.StringIO()
            err_buf = io.StringIO()
            # Also stub time.sleep so the test is fast.
            with patch.object(llm.urllib.request, "urlopen", side_effect=side_effect), \
                 patch.object(llm.time, "sleep", return_value=None), \
                 patch.dict(os.environ, cleaned_env, clear=True), \
                 patch.object(llm.sys, "stdout", buf), \
                 patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "anthropic",
                    "--model", "claude-opus-4-5",
                    "--retry-on-429", "2",
                    "--audit-dir", str(audit_dir),
                ])
            self.assertEqual(rc, 0, f"main() rc={rc}; stderr={err_buf.getvalue()!r}")
            self.assertIn("VERDICT HOLDS", buf.getvalue())
            # Audit records 2 retries. In explicit mode there may be one
            # fallback hop-record + one success record, but for
            # anthropic-only with retries-then-200 the outcome record is
            # unique and deterministic.
            audit_files = sorted(audit_dir.glob("llm_dispatch_*.json"))
            # There should be exactly one "ok" audit record.
            ok_records = [
                json.loads(p.read_text()) for p in audit_files
                if json.loads(p.read_text()).get("outcome") == "ok"
            ]
            self.assertEqual(len(ok_records), 1)
            record = ok_records[0]
            self.assertEqual(record["retry_count"], 2)
            self.assertEqual(record["http_status"], 200)


class LlmDispatchMalformedResponseTest(unittest.TestCase):
    """Test #5 — 200 with malformed JSON / missing content → exit 3."""

    def test_malformed_response_exits_with_error_code(self) -> None:
        llm = _load_llm_dispatch()
        # Valid JSON but missing `content`.
        malformed_body = json.dumps({"role": "assistant", "stop_reason": "end_turn"}).encode("utf-8")

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("x", encoding="utf-8")
            audit_dir = tmp_path / "audit"

            cleaned_env = {
                k: v for k, v in os.environ.items()
                if k not in (
                    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "KIMI_API_KEY",
                    "MINIMAX_API_KEY", "AUDITOOOR_LLM_PROVIDER",
                )
            }
            cleaned_env.update({
                "ANTHROPIC_API_KEY": "sk-test",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
                # V5-P0-03: budget guard defaults ON; opt out for the
                # auth/content-shape tests that don't exercise it.
                "AUDITOOOR_LLM_BUDGET_GUARD": "0",
            })
            buf = io.StringIO()
            err_buf = io.StringIO()
            with patch.object(
                llm.urllib.request, "urlopen",
                return_value=_fake_urlopen_200_malformed(malformed_body),
            ), patch.dict(os.environ, cleaned_env, clear=True), \
               patch.object(llm.sys, "stdout", buf), \
               patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "anthropic",
                    "--model", "claude-opus-4-5",
                    "--audit-dir", str(audit_dir),
                ])
            self.assertEqual(rc, 3)
            self.assertIn("malformed-response", err_buf.getvalue())
            self.assertEqual(buf.getvalue(), "")


class SwarmDispatchDefaultModeRegressionTest(unittest.TestCase):
    """Test #6 — SWARM_REAL_DISPATCH=0 default is byte-identical to printer.

    Locks the backwards-compat contract with iter-v3-3 T2 dry-run fixtures:
    absent the env var, `swarm-orchestrator.py --dispatch` must produce the
    operator-facing prompt printer output verbatim.
    """

    EXPECTED_LINES_ANCHOR = [
        "[swarm] Phase 2: Dispatch commands for 1 briefs (max 11 parallel)",
        "COPY AND PASTE THE FOLLOWING INTO YOUR Claude Code CONVERSATION:",
        "--- Agent 1: TestContract ---",
        "Launch an agent with the brief at",
        "Agent type: explore (read-only analysis)",
        "Timeout: 900 seconds",
        "After agents complete, run: python3 tools/swarm-orchestrator.py {workspace} --synthesize",
    ]

    def _write_workspace(self, tmp: Path) -> None:
        swarm_dir = tmp / "swarm"
        swarm_dir.mkdir(parents=True, exist_ok=True)
        manifest = {
            "workspace": str(tmp),
            "generated_at": "2026-04-24",
            "total_contracts": 1,
            "briefs_written": 1,
            "groups": {},
            "brief_metadata": {
                "TestContract": {
                    "contract": "TestContract",
                    "has_mining_proof_context": False,
                }
            },
        }
        (swarm_dir / "manifest.json").write_text(json.dumps(manifest))
        (swarm_dir / "brief_TestContract.md").write_text("# stub\n")

    def test_swarm_dispatch_default_mode_is_unchanged_printer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            self._write_workspace(tmp_path)

            env = {k: v for k, v in os.environ.items()
                   if k not in ("SWARM_REAL_DISPATCH", "ANTHROPIC_API_KEY")}
            cmd = [sys.executable, str(SWARM_TOOL), str(tmp_path), "--dispatch"]
            proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
            self.assertEqual(proc.returncode, 0, f"stderr={proc.stderr}")
            stdout = proc.stdout
            for anchor in self.EXPECTED_LINES_ANCHOR:
                self.assertIn(
                    anchor, stdout,
                    f"default-mode printer regression: missing anchor {anchor!r}",
                )
            # Hard regression: no LLM-only text leaks into default output.
            self.assertNotIn("You are the adversarial co-pilot", stdout)
            self.assertNotIn("VERDICT CONTESTED", stdout)
            self.assertNotIn("cannot-run: no-api-key", stdout)


if __name__ == "__main__":
    unittest.main()
