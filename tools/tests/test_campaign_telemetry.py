#!/usr/bin/env python3
"""Tests for tools/campaign-telemetry.py and the campaign hook in
tools/llm-dispatch.py.

Codex's required test list (V5 PR 6):

  1. Budget guard cannot silently disable (verify the loud-warn from
     PR-B #278 still fires AND a budget-skip telemetry row is written
     when the guard blocks a call).
  2. Provider timeout creates a hold artifact instead of success
     (verify against PR #285's TimeoutError classification).
  3. Telemetry roll-up correctly attributes a finding to its source
     campaign.
  4. Lane vs accepted-finding aggregation produces sliceable stats
     per Codex's Section 6 questions.

Stdlib-only — `unittest`, `tempfile`, `pathlib`, `unittest.mock`. No
pytest, no third-party deps. The campaign-telemetry library and the
dispatch tool are loaded via ``importlib.util.spec_from_file_location``
(both filenames are hyphenated).
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
TELEMETRY_TOOL = ROOT / "tools" / "campaign-telemetry.py"
LLM_TOOL = ROOT / "tools" / "llm-dispatch.py"


def _load(path: Path, mod_name: str):
    spec = importlib.util.spec_from_file_location(mod_name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_telemetry():
    return _load(TELEMETRY_TOOL, "campaign_telemetry_test_subject")


def _load_llm_dispatch():
    return _load(LLM_TOOL, "llm_dispatch_campaign_test_subject")


# ---------------------------------------------------------------------------
# Library API tests
# ---------------------------------------------------------------------------


class RecordDispatchTest(unittest.TestCase):
    """The campaign-dispatch ledger is append-only and validates inputs."""

    def test_record_dispatch_appends_one_row(self) -> None:
        ct = _load_telemetry()
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "dispatch.jsonl"
            ct.record_dispatch(
                campaign_id="src-mine-2026-04-26-001",
                provider="kimi",
                model="kimi-for-coding",
                tokens_used=12345,
                outcome="ok",
                audit_path="agent_outputs/llm_dispatch_x.json",
                role="candidate-extraction",
                workspace="monetrix",
                lane="source_mine",
                log_path=log_path,
            )
            self.assertTrue(log_path.exists())
            rows = log_path.read_text().splitlines()
            self.assertEqual(len(rows), 1)
            entry = json.loads(rows[0])
            self.assertEqual(entry["schema_version"], "campaign-dispatch.v1")
            self.assertEqual(entry["campaign_id"], "src-mine-2026-04-26-001")
            self.assertEqual(entry["provider"], "kimi")
            self.assertEqual(entry["lane"], "source_mine")
            self.assertEqual(entry["tokens_used"], 12345)
            self.assertEqual(entry["outcome"], "ok")
            self.assertFalse(entry["budget_guard_disabled"])

    def test_record_dispatch_rejects_invalid_inputs(self) -> None:
        ct = _load_telemetry()
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "dispatch.jsonl"
            with self.assertRaises(ValueError):
                ct.record_dispatch(
                    campaign_id="",
                    provider="kimi",
                    model="kimi-for-coding",
                    tokens_used=10,
                    outcome="ok",
                    log_path=log_path,
                )
            with self.assertRaises(ValueError):
                ct.record_dispatch(
                    campaign_id="c",
                    provider="kimi",
                    model="kimi-for-coding",
                    tokens_used=-1,
                    outcome="ok",
                    log_path=log_path,
                )

    def test_record_opus_dispatch_auto_stubs_escalation_row(self) -> None:
        """A dispatch routed to Opus must auto-stub a row in the
        opus_escalations ledger so 'was Opus worth it?' can never miss
        an Opus call (Kimi pre-review concern: orphaned Opus rows)."""
        ct = _load_telemetry()
        with tempfile.TemporaryDirectory() as tmp:
            d_path = Path(tmp) / "dispatch.jsonl"
            o_path = Path(tmp) / "opus.jsonl"
            ct.record_dispatch(
                campaign_id="c1",
                provider="anthropic",
                model="claude-opus-4-5",
                tokens_used=4242,
                outcome="ok",
                audit_path="agent_outputs/x.json",
                log_path=d_path,
                opus_log_path=o_path,
            )
            self.assertTrue(o_path.exists())
            o_rows = [json.loads(ln) for ln in o_path.read_text().splitlines()]
            self.assertEqual(len(o_rows), 1)
            self.assertTrue(o_rows[0]["auto_stub"])
            self.assertEqual(o_rows[0]["follow_up_outcome"], "pending")


class SubmissionMetadataTest(unittest.TestCase):
    """Section 6 metadata schema enforcement."""

    BASE = {
        "finding_id": "monetrix-W-03",
        "workspace": "monetrix",
        "source_campaign_id": "src-mine-2026-04-26-001",
        "fuzz_campaign_id": None,
        "symbolic_campaign_id": None,
        "deep_campaign_id": None,
        "models_used": [
            {"model": "kimi", "role": "candidate-extraction"},
            {"model": "minimax", "role": "redteam"},
        ],
        "tests_run": [
            {"command": "forge test", "output_path": "logs/forge.txt"},
        ],
        "scope_verdict": "in-scope",
        "oos_clauses_checked": ["clause-1.2"],
        "prior_art_result": "novel",
        "triager_outcome": "pending",
    }

    def test_record_submission_round_trips(self) -> None:
        ct = _load_telemetry()
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "subs.jsonl"
            entry = ct.record_submission(dict(self.BASE), log_path=log_path)
            self.assertEqual(entry["finding_id"], "monetrix-W-03")
            self.assertEqual(entry["schema_version"],
                             "campaign-submission.v1")
            rows = log_path.read_text().splitlines()
            self.assertEqual(len(rows), 1)

    def test_validation_rejects_missing_required_fields(self) -> None:
        ct = _load_telemetry()
        bad = dict(self.BASE)
        bad.pop("scope_verdict")
        errors = ct.validate_submission_metadata(
            {**bad, "schema_version": "campaign-submission.v1",
             "ts": "2026-04-26T00:00:00Z"}
        )
        self.assertTrue(any("scope_verdict" in e for e in errors))

    def test_validation_rejects_bad_enums(self) -> None:
        ct = _load_telemetry()
        bad = {**self.BASE,
               "schema_version": "campaign-submission.v1",
               "ts": "2026-04-26T00:00:00Z",
               "prior_art_result": "made-up-value"}
        errors = ct.validate_submission_metadata(bad)
        self.assertTrue(any("prior_art_result" in e for e in errors))

    def test_record_triager_appends_followup_with_parent_link(self) -> None:
        ct = _load_telemetry()
        with tempfile.TemporaryDirectory() as tmp:
            sub_path = Path(tmp) / "subs.jsonl"
            opus_path = Path(tmp) / "opus.jsonl"
            ct.record_submission(dict(self.BASE), log_path=sub_path)
            ct.record_triager_outcome(
                finding_id="monetrix-W-03",
                outcome="accepted",
                log_path=sub_path,
                opus_log_path=opus_path,
            )
            rows = [json.loads(ln) for ln in sub_path.read_text().splitlines()]
            self.assertEqual(len(rows), 2)
            self.assertTrue(rows[1]["follow_up"])
            self.assertEqual(rows[1]["triager_outcome"], "accepted")
            # Parent link mirrored into follow-up.
            self.assertEqual(
                rows[1]["source_campaign_id"], "src-mine-2026-04-26-001",
            )


# ---------------------------------------------------------------------------
# Codex test #1: budget-guard cannot silently disable
# ---------------------------------------------------------------------------


def _clean_env(extra: dict | None = None) -> dict:
    drop = {
        "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
        "ANTHROPIC_MODEL", "KIMI_API_KEY", "KIMI_ANTHROPIC_BASE_URL",
        "KIMI_MODEL", "MINIMAX_API_KEY", "MINIMAX_ANTHROPIC_BASE_URL",
        "MINIMAX_MODEL", "AUDITOOOR_LLM_PROVIDER",
        "AUDITOOOR_LLM_AUTH_HEADER", "AUDITOOOR_LLM_NETWORK_CONSENT",
        "ADVERSARIAL_LIVE_CONSENT", "AUDITOOOR_LLM_BUDGET_GUARD",
        "AUDITOOOR_CAMPAIGN_ID", "AUDITOOOR_CAMPAIGN_LANE",
        "AUDITOOOR_CAMPAIGN_ROLE", "AUDITOOOR_CAMPAIGN_WORKSPACE",
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
    return {
        "content": [{"type": "text", "text": text}],
        "model": "claude-opus-4-5",
        "role": "assistant",
        "stop_reason": "end_turn",
        "usage": {"input_tokens": in_tok, "output_tokens": out_tok},
    }


def _make_guard_module(may_call_returns, record_call_mock):
    guard_instance = SimpleNamespace(
        may_call=MagicMock(return_value=may_call_returns),
        record_call=record_call_mock,
    )
    fake_class = MagicMock(return_value=guard_instance)
    return SimpleNamespace(LlmBudgetGuard=fake_class), guard_instance


class CodexTest1_BudgetGuardCannotSilentlyDisableTest(unittest.TestCase):
    """Codex test #1: budget guard cannot silently disable.

    - When AUDITOOOR_LLM_BUDGET_GUARD=0, the loud stderr warn line MUST
      still fire and the dispatch audit trail MUST stamp
      ``budget_guard_disabled: true``. The campaign telemetry hook
      records the same flag so a downstream report can flag any
      campaign that ran with the guard off.
    - When budget is exhausted, the dispatch hook records the
      budget-skip outcome; the audit row carries
      ``http_status: 429`` AND outcome starts with ``budget-skip:``;
      AND the campaign-telemetry ledger captures the same outcome so
      the report can show how often gates fire (Section 6 Q3).
    """

    def test_explicit_zero_warns_and_telemetry_records_the_flag(self) -> None:
        llm = _load_llm_dispatch()
        ct = _load_telemetry()
        payload = _payload_with_usage("ok-response", 50, 60)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("hello", encoding="utf-8")
            audit_dir = tmp_path / "audit"
            telemetry_log = tmp_path / "campaign_dispatch_log.jsonl"
            opus_log = tmp_path / "opus.jsonl"

            env = _clean_env({
                "ANTHROPIC_API_KEY": "sk-test",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
                "AUDITOOOR_LLM_BUDGET_GUARD": "0",
                "AUDITOOOR_CAMPAIGN_ID": "src-mine-2026-04-26-001",
                "AUDITOOOR_CAMPAIGN_LANE": "source_mine",
                "AUDITOOOR_CAMPAIGN_ROLE": "candidate-extraction",
                "AUDITOOOR_CAMPAIGN_WORKSPACE": "monetrix",
            })

            buf = io.StringIO()
            err_buf = io.StringIO()

            # Inject the test telemetry log path by monkeypatching the
            # default constants on the loaded module before dispatch
            # imports it lazily.
            def _patched_loader():
                ct.DISPATCH_LOG_DEFAULT = telemetry_log
                ct.OPUS_LOG_DEFAULT = opus_log
                return ct

            with patch.object(
                llm.urllib.request, "urlopen",
                return_value=_fake_urlopen_200(payload),
            ), patch.object(
                llm, "_load_campaign_telemetry_module",
                _patched_loader,
            ), patch.dict(os.environ, env, clear=True), \
               patch.object(llm.sys, "stdout", buf), \
               patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "anthropic",
                    "--model", "claude-opus-4-5",
                    "--audit-dir", str(audit_dir),
                ])

            self.assertEqual(rc, 0, f"rc={rc}; stderr={err_buf.getvalue()!r}")
            stderr_text = err_buf.getvalue()
            # Loud warn line still fires.
            self.assertIn(
                "operator explicitly disabled budget guard",
                stderr_text,
            )
            # Dispatch audit trail records budget_guard_disabled=true.
            audit_files = sorted(audit_dir.glob("llm_dispatch_*.json"))
            self.assertEqual(len(audit_files), 1)
            audit = json.loads(audit_files[0].read_text())
            self.assertTrue(audit["budget_guard_disabled"])
            # Campaign telemetry row was written and carries the flag.
            self.assertTrue(telemetry_log.exists())
            t_rows = [
                json.loads(ln) for ln in
                telemetry_log.read_text().splitlines() if ln.strip()
            ]
            self.assertEqual(len(t_rows), 1)
            self.assertTrue(t_rows[0]["budget_guard_disabled"])
            self.assertEqual(t_rows[0]["campaign_id"],
                             "src-mine-2026-04-26-001")
            self.assertEqual(t_rows[0]["lane"], "source_mine")

    def test_budget_skip_records_hold_in_telemetry(self) -> None:
        llm = _load_llm_dispatch()
        ct = _load_telemetry()
        record_call_mock = MagicMock()
        fake_module, guard_instance = _make_guard_module(
            may_call_returns=(
                False, "calls budget exhausted: 30/30 in last 60min",
            ),
            record_call_mock=record_call_mock,
        )
        urlopen_mock = MagicMock()

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("hello", encoding="utf-8")
            audit_dir = tmp_path / "audit"
            telemetry_log = tmp_path / "campaign_dispatch_log.jsonl"
            opus_log = tmp_path / "opus.jsonl"

            env = _clean_env({
                "ANTHROPIC_API_KEY": "sk-test",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
                "AUDITOOOR_LLM_BUDGET_GUARD": "1",
                "AUDITOOOR_CAMPAIGN_ID": "src-mine-2026-04-26-001",
                "AUDITOOOR_CAMPAIGN_LANE": "source_mine",
            })

            buf = io.StringIO()
            err_buf = io.StringIO()

            def _patched_loader():
                ct.DISPATCH_LOG_DEFAULT = telemetry_log
                ct.OPUS_LOG_DEFAULT = opus_log
                return ct

            with patch.object(
                llm.urllib.request, "urlopen", urlopen_mock,
            ), patch.object(
                llm, "_load_budget_guard_module",
                return_value=fake_module,
            ), patch.object(
                llm, "_load_campaign_telemetry_module",
                _patched_loader,
            ), patch.dict(os.environ, env, clear=True), \
               patch.object(llm.sys, "stdout", buf), \
               patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "anthropic",
                    "--model", "claude-opus-4-5",
                    "--audit-dir", str(audit_dir),
                ])

            self.assertEqual(rc, 3, f"expected exit 3, got {rc}")
            urlopen_mock.assert_not_called()
            # Telemetry captured the budget-skip outcome.
            self.assertTrue(telemetry_log.exists())
            t_rows = [
                json.loads(ln) for ln in
                telemetry_log.read_text().splitlines() if ln.strip()
            ]
            self.assertEqual(len(t_rows), 1)
            self.assertTrue(
                t_rows[0]["outcome"].startswith("budget-skip:")
            )
            self.assertEqual(t_rows[0]["campaign_id"],
                             "src-mine-2026-04-26-001")


# ---------------------------------------------------------------------------
# Codex test #2: provider timeout creates a hold artifact, not success
# ---------------------------------------------------------------------------


class CodexTest2_TimeoutCreatesHoldArtifactTest(unittest.TestCase):
    """Codex test #2: a TimeoutError (PR #285's transport-error
    classification) must produce a HOLD telemetry row, not an OK one.

    We trigger ``ProviderFallback`` via raising ``TimeoutError`` from
    urlopen. The dispatch audit trail outcome starts with
    ``fallback: transport-error: timeout``, and the campaign-telemetry
    row outcome starts with ``hold: transport-error: timeout`` so a
    downstream Section 6 report distinguishes timed-out hops from
    successful ones.
    """

    def test_timeout_writes_hold_row_not_success(self) -> None:
        llm = _load_llm_dispatch()
        ct = _load_telemetry()

        def _raise_timeout(*_args, **_kwargs):
            raise TimeoutError("read timed out")

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            prompt_file = tmp_path / "prompt.txt"
            prompt_file.write_text("hello", encoding="utf-8")
            audit_dir = tmp_path / "audit"
            telemetry_log = tmp_path / "campaign_dispatch_log.jsonl"
            opus_log = tmp_path / "opus.jsonl"

            env = _clean_env({
                "ANTHROPIC_API_KEY": "sk-test",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
                "AUDITOOOR_LLM_BUDGET_GUARD": "0",
                "AUDITOOOR_CAMPAIGN_ID": "src-mine-2026-04-26-001",
                "AUDITOOOR_CAMPAIGN_LANE": "source_mine",
            })

            buf = io.StringIO()
            err_buf = io.StringIO()

            def _patched_loader():
                ct.DISPATCH_LOG_DEFAULT = telemetry_log
                ct.OPUS_LOG_DEFAULT = opus_log
                return ct

            with patch.object(
                llm.urllib.request, "urlopen",
                side_effect=_raise_timeout,
            ), patch.object(
                llm, "_load_campaign_telemetry_module",
                _patched_loader,
            ), patch.dict(os.environ, env, clear=True), \
               patch.object(llm.sys, "stdout", buf), \
               patch.object(llm.sys, "stderr", err_buf):
                rc = llm.main([
                    "--prompt-file", str(prompt_file),
                    "--provider", "anthropic",
                    "--model", "claude-opus-4-5",
                    "--audit-dir", str(audit_dir),
                    "--timeout", "1",
                    "--retry-on-429", "0",
                ])

            self.assertEqual(rc, 3, f"expected exit 3, got {rc}; "
                                    f"stderr={err_buf.getvalue()!r}")
            # Audit row records fallback.
            audit_files = sorted(audit_dir.glob("llm_dispatch_*.json"))
            self.assertEqual(len(audit_files), 1)
            audit = json.loads(audit_files[0].read_text())
            self.assertTrue(
                audit["outcome"].startswith("fallback: transport-error"),
                f"unexpected outcome: {audit['outcome']!r}",
            )
            # Telemetry row records HOLD, not OK.
            self.assertTrue(telemetry_log.exists())
            t_rows = [
                json.loads(ln) for ln in
                telemetry_log.read_text().splitlines() if ln.strip()
            ]
            self.assertEqual(len(t_rows), 1)
            self.assertTrue(
                t_rows[0]["outcome"].startswith("hold: transport-error"),
                f"unexpected telemetry outcome: {t_rows[0]['outcome']!r}",
            )
            self.assertNotEqual(t_rows[0]["outcome"], "ok")


# ---------------------------------------------------------------------------
# Codex test #3: telemetry roll-up attributes a finding to its source campaign
# ---------------------------------------------------------------------------


class CodexTest3_FindingAttributedToSourceCampaignTest(unittest.TestCase):
    """Codex test #3: a submitted finding rolls up under the campaign
    that produced it.

    Scenario: a source-mining campaign produces 3 dispatches and 1
    submission. After the triager accepts the submission, the
    Section 6 report must show:

      - by_lane["source_mine"].submitted == 1
      - by_lane["source_mine"].accepted == 1
      - by_workspace["monetrix"].accepted == 1
    """

    def test_finding_rolls_up_under_source_campaign(self) -> None:
        ct = _load_telemetry()
        with tempfile.TemporaryDirectory() as tmp:
            d_path = Path(tmp) / "dispatch.jsonl"
            o_path = Path(tmp) / "opus.jsonl"
            s_path = Path(tmp) / "subs.jsonl"

            for tokens in (1000, 2000, 3000):
                ct.record_dispatch(
                    campaign_id="src-mine-2026-04-26-001",
                    provider="kimi",
                    model="kimi-for-coding",
                    tokens_used=tokens,
                    outcome="ok",
                    role="candidate-extraction",
                    workspace="monetrix",
                    lane="source_mine",
                    log_path=d_path,
                    opus_log_path=o_path,
                )

            ct.record_submission(
                {
                    "finding_id": "monetrix-W-03",
                    "workspace": "monetrix",
                    "source_campaign_id": "src-mine-2026-04-26-001",
                    "fuzz_campaign_id": None,
                    "symbolic_campaign_id": None,
                    "deep_campaign_id": None,
                    "models_used": [
                        {"model": "kimi", "role": "candidate-extraction"},
                    ],
                    "tests_run": [{"command": "forge test"}],
                    "scope_verdict": "in-scope",
                    "oos_clauses_checked": ["c-1.2"],
                    "prior_art_result": "novel",
                    "triager_outcome": "pending",
                },
                log_path=s_path,
            )

            ct.record_triager_outcome(
                finding_id="monetrix-W-03",
                outcome="accepted",
                log_path=s_path,
                opus_log_path=o_path,
            )

            report = ct.aggregate(
                dispatch_log=d_path,
                opus_log=o_path,
                submission_log=s_path,
            )

        self.assertEqual(report["totals"]["dispatches"], 3)
        self.assertEqual(report["totals"]["submissions"], 1)
        # Lane attribution.
        self.assertIn("source_mine", report["by_lane"])
        sm = report["by_lane"]["source_mine"]
        self.assertEqual(sm["dispatches"], 3)
        self.assertEqual(sm["submitted"], 1)
        self.assertEqual(sm["accepted"], 1)
        self.assertEqual(sm["accept_rate"], 1.0)
        self.assertEqual(sm["tokens_used"], 6000)
        # Workspace attribution.
        self.assertIn("monetrix", report["by_workspace"])
        ws = report["by_workspace"]["monetrix"]
        self.assertEqual(ws["source_mine_dispatches"], 3)
        self.assertEqual(ws["accepted"], 1)


# ---------------------------------------------------------------------------
# Codex test #4: lane vs accepted-finding aggregation produces sliceable stats
# ---------------------------------------------------------------------------


class CodexTest4_LaneVsAcceptedAggregationTest(unittest.TestCase):
    """Codex test #4: Section 6 Q1-Q4 must each be answerable from the
    aggregate output. We exercise:

    - source_mine produces an accepted finding.
    - fuzz produces a rejected finding.
    - one model has 2 hold dispatches (=> high hold-rate).
    - workspace 'A' is mining-heavy, workspace 'B' is fuzz-heavy.
    - Opus had 1 escalation that ended accepted (after triager mirror).
    """

    def test_full_section_6_aggregation(self) -> None:
        ct = _load_telemetry()
        with tempfile.TemporaryDirectory() as tmp:
            d_path = Path(tmp) / "dispatch.jsonl"
            o_path = Path(tmp) / "opus.jsonl"
            s_path = Path(tmp) / "subs.jsonl"

            # source_mine, kimi, ok.
            ct.record_dispatch(
                campaign_id="cam-A", provider="kimi",
                model="kimi-for-coding", tokens_used=10,
                outcome="ok", role="extract", workspace="A",
                lane="source_mine", log_path=d_path,
                opus_log_path=o_path,
            )
            # source_mine, minimax, hold (timeout).
            ct.record_dispatch(
                campaign_id="cam-A", provider="minimax",
                model="MiniMax-M2.7", tokens_used=0,
                outcome="hold: transport-error: timeout",
                role="redteam", workspace="A",
                lane="source_mine", log_path=d_path,
                opus_log_path=o_path,
            )
            # source_mine, minimax, hold again.
            ct.record_dispatch(
                campaign_id="cam-A", provider="minimax",
                model="MiniMax-M2.7", tokens_used=0,
                outcome="hold: 5xx", role="redteam", workspace="A",
                lane="source_mine", log_path=d_path,
                opus_log_path=o_path,
            )
            # fuzz dispatch on workspace B.
            ct.record_dispatch(
                campaign_id="cam-B-fuzz", provider="kimi",
                model="kimi-for-coding", tokens_used=5,
                outcome="ok", role="generate", workspace="B",
                lane="fuzz", log_path=d_path,
                opus_log_path=o_path,
            )
            # Opus escalation tied to cam-A.
            ct.record_dispatch(
                campaign_id="cam-A", provider="anthropic",
                model="claude-opus-4-5", tokens_used=20000,
                outcome="ok", role="escalation", workspace="A",
                lane="source_mine", log_path=d_path,
                opus_log_path=o_path,
            )

            # Submissions: 1 accepted from source_mine, 1 rejected from fuzz.
            ct.record_submission(
                {
                    "finding_id": "fA-1", "workspace": "A",
                    "source_campaign_id": "cam-A",
                    "fuzz_campaign_id": None,
                    "symbolic_campaign_id": None,
                    "deep_campaign_id": None,
                    "models_used": [
                        {"model": "kimi", "role": "extract"},
                    ],
                    "tests_run": [{"command": "forge test"}],
                    "scope_verdict": "in-scope",
                    "oos_clauses_checked": [],
                    "prior_art_result": "novel",
                    "triager_outcome": "pending",
                },
                log_path=s_path,
            )
            ct.record_submission(
                {
                    "finding_id": "fB-1", "workspace": "B",
                    "source_campaign_id": None,
                    "fuzz_campaign_id": "cam-B-fuzz",
                    "symbolic_campaign_id": None,
                    "deep_campaign_id": None,
                    "models_used": [
                        {"model": "kimi", "role": "generate"},
                    ],
                    "tests_run": [{"command": "forge test"}],
                    "scope_verdict": "in-scope",
                    "oos_clauses_checked": [],
                    "prior_art_result": "novel",
                    "triager_outcome": "pending",
                },
                log_path=s_path,
            )
            ct.record_triager_outcome(
                finding_id="fA-1", outcome="accepted",
                log_path=s_path, opus_log_path=o_path,
            )
            ct.record_triager_outcome(
                finding_id="fB-1", outcome="rejected",
                log_path=s_path, opus_log_path=o_path,
            )

            report = ct.aggregate(
                dispatch_log=d_path,
                opus_log=o_path,
                submission_log=s_path,
            )

        # Q1: which lanes produce accepted findings?
        self.assertEqual(report["by_lane"]["source_mine"]["accepted"], 1)
        self.assertEqual(report["by_lane"]["fuzz"]["accepted"], 0)
        self.assertEqual(report["by_lane"]["fuzz"]["rejected"], 1)
        # accept_rate computed correctly.
        self.assertEqual(
            report["by_lane"]["source_mine"]["accept_rate"], 1.0,
        )
        self.assertEqual(report["by_lane"]["fuzz"]["accept_rate"], 0.0)

        # Q2: which models are noisy? minimax has 2 holds out of 2 dispatches.
        minimax_key = "minimax:MiniMax-M2.7"
        self.assertIn(minimax_key, report["by_model"])
        mm = report["by_model"][minimax_key]
        self.assertEqual(mm["dispatches"], 2)
        self.assertEqual(mm["hold_dispatches"], 2)
        self.assertEqual(mm["hold_rate"], 1.0)
        # Kimi has 2 OK + 0 hold (cam-A extract + cam-B-fuzz generate).
        kimi_key = "kimi:kimi-for-coding"
        self.assertIn(kimi_key, report["by_model"])
        kk = report["by_model"][kimi_key]
        self.assertEqual(kk["dispatches"], 2)
        self.assertEqual(kk["ok_dispatches"], 2)
        self.assertEqual(kk["hold_dispatches"], 0)

        # Q4: workspace mining-vs-fuzz share. Workspace A has 4 source_mine
        # dispatches (3 kimi/minimax + 1 Opus escalation tagged source_mine);
        # workspace B has 1 fuzz dispatch.
        self.assertEqual(
            report["by_workspace"]["A"]["source_mine_dispatches"], 4,
        )
        self.assertEqual(report["by_workspace"]["A"]["fuzz_dispatches"], 0)
        self.assertEqual(report["by_workspace"]["A"]["mining_share"], 1.0)
        self.assertEqual(report["by_workspace"]["B"]["fuzz_dispatches"], 1)
        self.assertEqual(report["by_workspace"]["B"]["fuzz_share"], 1.0)

        # Was Opus worth it? cam-A had at least 1 escalation auto-stubbed
        # by the dispatch-record path. After triager 'fA-1' accepted, the
        # opus_escalations follow-up row carries follow_up_outcome=accepted.
        self.assertIn("cam-A", report["opus_value"])
        op = report["opus_value"]["cam-A"]
        self.assertGreaterEqual(op["escalations"], 1)
        # Accepted at least once via the triager-mirrored follow-up.
        self.assertGreaterEqual(op["accepted"], 1)


if __name__ == "__main__":
    unittest.main()
