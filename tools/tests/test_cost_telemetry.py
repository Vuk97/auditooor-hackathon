#!/usr/bin/env python3
"""PR 210 — cost-telemetry offline unit tests.

No network. No subprocess to real LLM APIs. Exercises:

- record_stage writes the expected JSON shape + duration > 0
- LLM rate-card math is exact for a known input
- subprocess stage (model=None) → est_cost_usd == 0
- summarize_workspace tolerates missing cost_runs/
- summarize_workspace aggregates multi-stage fixtures correctly
- COST_RATE_CARD_PATH env override changes the cost output
"""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "cost-telemetry.py"


def _load_module():
    """Load tools/cost-telemetry.py by file path (hyphenated name is not a
    valid Python module identifier, so importlib is the clean path)."""
    spec = importlib.util.spec_from_file_location("cost_telemetry", MODULE_PATH)
    assert spec and spec.loader, f"could not load spec for {MODULE_PATH}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cost_telemetry = _load_module()


class RecordStageDurationTests(unittest.TestCase):
    """JSON artifact is emitted, has every required key, duration > 0."""

    def test_records_stage_duration(self) -> None:
        cost_telemetry.reset_run()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            cost_telemetry.start_run("20260101T000000Z")
            with cost_telemetry.record_stage("noop", ws):
                time.sleep(0.01)  # ensure duration_s > 0 even on fast machines

            run_dir = ws / "cost_runs" / "20260101T000000Z"
            self.assertTrue(run_dir.exists(), "cost_runs/<ts>/ must be created")
            files = list(run_dir.glob("stage_*.json"))
            self.assertEqual(len(files), 1, f"expected one stage file, got {files}")

            payload = json.loads(files[0].read_text())
            for key in ("stage", "started_at", "duration_s", "est_tokens",
                        "est_cost_usd", "model", "cost_source"):
                self.assertIn(key, payload, f"missing required key {key!r}")
            self.assertEqual(payload["stage"], "noop")
            self.assertGreater(payload["duration_s"], 0.0,
                               "duration_s must be positive")
            # No model provided → subprocess-cost semantics.
            self.assertEqual(payload["est_cost_usd"], 0.0)
            self.assertEqual(payload["cost_source"], "subprocess")


class LLMCostEstimateTests(unittest.TestCase):
    """For a known sonnet ratecard ($3/M input + $15/M output) the math is
    deterministic: 1000 input + 500 output = 0.003 + 0.0075 = 0.0105 USD."""

    def test_llm_stage_cost_estimate(self) -> None:
        cost_telemetry.reset_run()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            cost_telemetry.start_run("20260101T000001Z")
            with cost_telemetry.record_stage(
                "synthesize", ws, model="sonnet",
                est_tokens={"input": 1000, "output": 500},
            ):
                pass

            files = list((ws / "cost_runs" / "20260101T000001Z").glob("stage_*.json"))
            self.assertEqual(len(files), 1)
            payload = json.loads(files[0].read_text())
            self.assertEqual(payload["model"], "sonnet")
            self.assertEqual(payload["est_tokens"], {"input": 1000, "output": 500})
            self.assertEqual(payload["cost_source"], "rate-card")
            self.assertAlmostEqual(payload["est_cost_usd"], 0.0105, places=6)


class SubprocessStageZeroCostTests(unittest.TestCase):
    """Regression test against PR #102-style silent cost inflation: a
    subprocess stage (no model, no tokens) MUST report est_cost_usd=0 and
    mark source 'subprocess', not None / not a stale rate."""

    def test_subprocess_stage_zero_cost(self) -> None:
        cost, source = cost_telemetry.estimate_cost_usd(
            model=None, est_tokens=None, rate_card={"models": {}},
        )
        self.assertEqual(cost, 0.0)
        self.assertEqual(source, "subprocess")

    def test_llm_without_tokens_is_not_silently_zero(self) -> None:
        """A known LLM stage with no est_tokens must record None, not 0."""
        cost, source = cost_telemetry.estimate_cost_usd(
            model="sonnet", est_tokens=None,
            rate_card={"models": {"sonnet": {
                "input_per_mtok_usd": 3.0, "output_per_mtok_usd": 15.0,
            }}},
        )
        self.assertIsNone(cost)
        self.assertEqual(source, "walltime-only")


class SummarizeEmptyWorkspaceTests(unittest.TestCase):
    def test_summarize_empty_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            summary = cost_telemetry.summarize_workspace(ws)
        self.assertEqual(summary["stage_count"], 0)
        self.assertEqual(summary["total_duration_s"], 0.0)
        self.assertEqual(summary["total_est_cost_usd"], 0.0)
        self.assertEqual(summary["per_stage"], {})
        self.assertEqual(summary["runs"], [])
        self.assertFalse(summary["cost_is_partial"])


class SummarizeMultiStageTests(unittest.TestCase):
    """Three fake stage artifacts → totals + per-stage breakdown are correct."""

    def _write(self, run_dir: Path, stage: str, duration: float,
               cost: float | None, model: str | None,
               source: str) -> None:
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / f"stage_{stage}.json").write_text(json.dumps({
            "stage": stage,
            "started_at": "2026-01-01T00:00:00+00:00",
            "duration_s": duration,
            "est_tokens": None if model is None else {"input": 100, "output": 50},
            "est_cost_usd": cost,
            "model": model,
            "cost_source": source,
        }))

    def test_summarize_multi_stage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            run = ws / "cost_runs" / "20260101T000002Z"
            self._write(run, "scan",    2.5, 0.0,    None,       "subprocess")
            self._write(run, "agent",   4.0, 0.0105, "sonnet",   "rate-card")
            self._write(run, "opusrun", 1.0, None,   "opus",     "walltime-only")

            summary = cost_telemetry.summarize_workspace(ws)

        self.assertEqual(summary["stage_count"], 3)
        self.assertAlmostEqual(summary["total_duration_s"], 7.5, places=6)
        # The walltime-only entry contributes nothing to total cost.
        self.assertAlmostEqual(summary["total_est_cost_usd"], 0.0105, places=6)
        self.assertTrue(summary["cost_is_partial"])
        self.assertEqual(summary["runs"], ["20260101T000002Z"])

        per_stage = summary["per_stage"]
        self.assertIn("scan", per_stage)
        self.assertIn("agent", per_stage)
        self.assertIn("opusrun", per_stage)
        self.assertEqual(per_stage["scan"]["count"], 1)
        self.assertAlmostEqual(per_stage["scan"]["total_est_cost_usd"], 0.0,
                               places=6)
        self.assertAlmostEqual(per_stage["agent"]["total_est_cost_usd"], 0.0105,
                               places=6)
        # Partial stage is flagged; cost is the sum of non-None entries only.
        self.assertTrue(per_stage["opusrun"]["cost_is_partial"])
        self.assertAlmostEqual(per_stage["opusrun"]["total_est_cost_usd"], 0.0,
                               places=6)


class OverrideRateCardViaEnvTests(unittest.TestCase):
    """COST_RATE_CARD_PATH override must change the computed cost. This
    catches the 'stale rate card is silently used' failure mode."""

    def test_override_rate_card_via_env(self) -> None:
        cost_telemetry.reset_run()
        prior = os.environ.pop("COST_RATE_CARD_PATH", None)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                tmp_p = Path(tmp)
                override_card = tmp_p / "custom_rates.json"
                # Deliberately different from the repo default: input $10/M,
                # output $100/M. 1000 input + 500 output → 0.06 USD.
                override_card.write_text(json.dumps({
                    "models": {
                        "sonnet": {
                            "input_per_mtok_usd": 10.0,
                            "output_per_mtok_usd": 100.0,
                        },
                    },
                }))
                ws = tmp_p / "ws"
                ws.mkdir()

                os.environ["COST_RATE_CARD_PATH"] = str(override_card)
                cost_telemetry.start_run("20260101T000003Z")
                with cost_telemetry.record_stage(
                    "synthesize", ws, model="sonnet",
                    est_tokens={"input": 1000, "output": 500},
                ):
                    pass

                files = list((ws / "cost_runs" / "20260101T000003Z").glob("stage_*.json"))
                self.assertEqual(len(files), 1)
                payload = json.loads(files[0].read_text())
                # Custom rates: 1000/1e6 * 10 + 500/1e6 * 100 = 0.06
                self.assertAlmostEqual(payload["est_cost_usd"], 0.06, places=6)
                self.assertEqual(payload["cost_source"], "rate-card")
        finally:
            if prior is None:
                os.environ.pop("COST_RATE_CARD_PATH", None)
            else:
                os.environ["COST_RATE_CARD_PATH"] = prior


class MissingRateCardTests(unittest.TestCase):
    """If COST_RATE_CARD_PATH points to nothing, cost is None (walltime-only),
    not $0. The engagement must still complete."""

    def test_missing_rate_card_falls_back_to_walltime_only(self) -> None:
        cost_telemetry.reset_run()
        prior = os.environ.pop("COST_RATE_CARD_PATH", None)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                tmp_p = Path(tmp)
                os.environ["COST_RATE_CARD_PATH"] = str(tmp_p / "does-not-exist.json")
                ws = tmp_p / "ws"
                ws.mkdir()
                cost_telemetry.start_run("20260101T000004Z")
                with cost_telemetry.record_stage(
                    "synthesize", ws, model="sonnet",
                    est_tokens={"input": 1000, "output": 500},
                ):
                    pass

                files = list((ws / "cost_runs" / "20260101T000004Z").glob("stage_*.json"))
                self.assertEqual(len(files), 1)
                payload = json.loads(files[0].read_text())
                self.assertIsNone(payload["est_cost_usd"])
                self.assertEqual(payload["cost_source"], "walltime-only")
        finally:
            if prior is None:
                os.environ.pop("COST_RATE_CARD_PATH", None)
            else:
                os.environ["COST_RATE_CARD_PATH"] = prior


if __name__ == "__main__":
    unittest.main()
