#!/usr/bin/env python3
"""Tests for the advisory track-record verdict weighting sidecar (P12).

Covers the load-bearing guarantees:
  * cold-start (no model/task_type join) == naive Counter/majority, byte-identical
    to the captured baseline;
  * a calibrated-bad lane is down-weighted vs a calibrated-good lane;
  * a credible weighted disagreement emits ESCALATE (not silent majority);
  * the AUDITOOOR_VERDICT_WEIGHT_STRICT flag is OFF by default (effective ==
    naive), and setting it does not change cold-start output;
  * the emitter retrofit writes model/task_type when inferable and omits them
    (record stays cold-start) otherwise.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TOOLS = REPO / "tools"
WEIGHT_TOOL = TOOLS / "lane-verdict-weight.py"
BUS_TOOL = TOOLS / "lane-verdict-bus.py"
AUTOAPPEND = TOOLS / "hooks" / "lane-verdict-bus-autoappend.sh"
BASELINE = Path("/tmp/qna-build-baselines/P12.txt")


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


weight = _load(WEIGHT_TOOL, "lane_verdict_weight_under_test")
bus = _load(BUS_TOOL, "lane_verdict_bus_under_test")


def _append(ws: Path, lane_id: str, candidate: str, verdict: str, metadata=None):
    md = dict(metadata or {})
    md.setdefault("verdict_hash", f"{lane_id}:{candidate}:{verdict}")
    bus.append_record(
        ws,
        lane_id=lane_id,
        candidate_id=candidate,
        attack_class="reentrancy",
        verdict=verdict,
        metadata=md,
    )


def _seed(rows):
    return {
        "_schema_version": "test",
        "_default_min_samples": 20,
        "_min_precision_pct": 70,
        "rows": rows,
    }


class ColdStartByteIdentityTests(unittest.TestCase):
    def test_cold_start_weighted_equals_naive_counter(self):
        # C1: DROPPED / KEPT / DROPPED, all metadata absent (cold-start).
        with tempfile.TemporaryDirectory(prefix="lvw_") as td:
            ws = Path(td)
            _append(ws, "hunt-a", "C1", "DROPPED")
            _append(ws, "hunt-b", "C1", "KEPT")
            _append(ws, "hunt-c", "C1", "DROPPED")
            out = weight.weigh(ws)
            c1 = out["candidates"]["C1"]
            # Naive == weighted, byte-identical tally.
            self.assertEqual(c1["naive_by_verdict"], {"DROPPED": 2, "KEPT": 1})
            self.assertEqual(
                c1["weighted_by_verdict"], {"DROPPED": 2.0, "KEPT": 1.0}
            )
            self.assertEqual(c1["naive_majority"], "DROPPED")
            self.assertEqual(c1["weighted_majority"], "DROPPED")
            self.assertFalse(c1["escalate"])

    def test_cold_start_matches_bus_aggregate_by_verdict(self):
        with tempfile.TemporaryDirectory(prefix="lvw_") as td:
            ws = Path(td)
            _append(ws, "hunt-a", "C1", "DROPPED")
            _append(ws, "hunt-b", "C1", "KEPT")
            _append(ws, "hunt-c", "C1", "DROPPED")
            agg = bus.aggregate_records(ws)
            out = weight.weigh(ws)
            c1 = out["candidates"]["C1"]
            # The weighted tally reduced to ints must equal the bus by_verdict.
            reduced = {k: int(v) for k, v in c1["weighted_by_verdict"].items()}
            self.assertEqual(reduced, agg["by_verdict"])
            self.assertEqual(c1["naive_by_verdict"], agg["by_verdict"])

    def test_baseline_file_by_verdict_matches(self):
        if not BASELINE.exists():
            self.skipTest("baseline file not present")
        text = BASELINE.read_text(encoding="utf-8")
        # Pull the first JSON object (the aggregate) out of the baseline dump.
        start = text.index("{")
        depth = 0
        end = start
        for i, ch in enumerate(text[start:], start=start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        agg = json.loads(text[start:end])
        baseline_by_verdict = agg["by_verdict"]
        with tempfile.TemporaryDirectory(prefix="lvw_") as td:
            ws = Path(td)
            _append(ws, "hunt-a", "C1", "DROPPED")
            _append(ws, "hunt-b", "C1", "KEPT")
            _append(ws, "hunt-c", "C1", "DROPPED")
            out = weight.weigh(ws)
            c1 = out["candidates"]["C1"]
            reduced = {k: int(v) for k, v in c1["weighted_by_verdict"].items()}
            self.assertEqual(reduced, baseline_by_verdict)
            self.assertEqual(c1["naive_by_verdict"], baseline_by_verdict)


class FlagDefaultOffTests(unittest.TestCase):
    def test_flag_unset_effective_is_naive(self):
        env_had = os.environ.pop(weight.WEIGHT_STRICT_ENV, None)
        try:
            with tempfile.TemporaryDirectory(prefix="lvw_") as td:
                ws = Path(td)
                _append(ws, "hunt-a", "C1", "DROPPED")
                _append(ws, "hunt-b", "C1", "KEPT")
                _append(ws, "hunt-c", "C1", "DROPPED")
                out = weight.weigh(ws)
                c1 = out["candidates"]["C1"]
                self.assertFalse(out["weight_strict_env_set"])
                self.assertEqual(c1["effective_verdict"], c1["naive_majority"])
        finally:
            if env_had is not None:
                os.environ[weight.WEIGHT_STRICT_ENV] = env_had

    def test_flag_set_on_cold_start_is_still_naive(self):
        os.environ[weight.WEIGHT_STRICT_ENV] = "1"
        try:
            with tempfile.TemporaryDirectory(prefix="lvw_") as td:
                ws = Path(td)
                _append(ws, "hunt-a", "C1", "DROPPED")
                _append(ws, "hunt-b", "C1", "KEPT")
                _append(ws, "hunt-c", "C1", "DROPPED")
                out = weight.weigh(ws)
                c1 = out["candidates"]["C1"]
                # Cold-start: even with the flag on, weighted == naive.
                self.assertTrue(out["weight_strict_env_set"])
                self.assertEqual(c1["effective_verdict"], c1["naive_majority"])
                self.assertEqual(c1["weighted_majority"], c1["naive_majority"])
        finally:
            os.environ.pop(weight.WEIGHT_STRICT_ENV, None)


class CalibratedWeightingTests(unittest.TestCase):
    def _seed_path(self, td: Path, rows) -> Path:
        p = td / "seed.json"
        p.write_text(json.dumps(_seed(rows)), encoding="utf-8")
        return p

    def test_calibrated_bad_lane_down_weighted_vs_good(self):
        # Two lanes vote KEPT (bad, low precision), one lane votes DROPPED (good,
        # high precision). Naive majority = KEPT (2 vs 1). Weighted: KEPT lanes
        # at 0.30 each = 0.60, DROPPED lane at 0.95 = 0.95 => weighted = DROPPED.
        with tempfile.TemporaryDirectory(prefix="lvw_") as td:
            ws = Path(td)
            seed_path = self._seed_path(
                ws,
                [
                    {"provider": "kimi", "task_type": "adversarial-kill",
                     "sample_count": 40, "precision_pct": 30},
                    {"provider": "minimax", "task_type": "adversarial-kill",
                     "sample_count": 40, "precision_pct": 95},
                ],
            )
            _append(ws, "kimi-a", "C1", "KEPT",
                    {"model": "kimi-for-coding", "task_type": "adversarial-kill"})
            _append(ws, "kimi-b", "C1", "KEPT",
                    {"model": "kimi-for-coding", "task_type": "adversarial-kill"})
            _append(ws, "mm-a", "C1", "DROPPED",
                    {"model": "MiniMax-M2.7", "task_type": "adversarial-kill"})
            out = weight.weigh(ws, seed_path=seed_path)
            c1 = out["candidates"]["C1"]
            self.assertEqual(c1["naive_majority"], "KEPT")
            self.assertEqual(c1["weighted_majority"], "DROPPED")
            self.assertLess(
                c1["weighted_by_verdict"]["KEPT"],
                c1["weighted_by_verdict"]["DROPPED"],
            )

    def test_credible_disagreement_emits_escalate(self):
        with tempfile.TemporaryDirectory(prefix="lvw_") as td:
            ws = Path(td)
            seed_path = self._seed_path(
                ws,
                [
                    {"provider": "kimi", "task_type": "adversarial-kill",
                     "sample_count": 40, "precision_pct": 30},
                    {"provider": "minimax", "task_type": "adversarial-kill",
                     "sample_count": 40, "precision_pct": 95},
                ],
            )
            _append(ws, "kimi-a", "C1", "KEPT",
                    {"model": "kimi-for-coding", "task_type": "adversarial-kill"})
            _append(ws, "kimi-b", "C1", "KEPT",
                    {"model": "kimi-for-coding", "task_type": "adversarial-kill"})
            _append(ws, "mm-a", "C1", "DROPPED",
                    {"model": "MiniMax-M2.7", "task_type": "adversarial-kill"})
            out = weight.weigh(ws, seed_path=seed_path)
            c1 = out["candidates"]["C1"]
            self.assertTrue(c1["escalate"], c1)
            self.assertIn("C1", out["escalate_candidates"])
            self.assertIn("disagrees with naive majority", c1["escalate_reason"])

    def test_no_escalate_when_weighted_agrees_with_naive(self):
        # Calibrated lanes present but they only reinforce the naive majority.
        with tempfile.TemporaryDirectory(prefix="lvw_") as td:
            ws = Path(td)
            seed_path = self._seed_path(
                ws,
                [
                    {"provider": "minimax", "task_type": "adversarial-kill",
                     "sample_count": 40, "precision_pct": 95},
                ],
            )
            _append(ws, "mm-a", "C1", "DROPPED",
                    {"model": "MiniMax-M2.7", "task_type": "adversarial-kill"})
            _append(ws, "mm-b", "C1", "DROPPED",
                    {"model": "MiniMax-M2.7", "task_type": "adversarial-kill"})
            _append(ws, "plain", "C1", "KEPT")  # cold-start weight 1.0
            out = weight.weigh(ws, seed_path=seed_path)
            c1 = out["candidates"]["C1"]
            self.assertEqual(c1["naive_majority"], "DROPPED")
            self.assertEqual(c1["weighted_majority"], "DROPPED")
            self.assertFalse(c1["escalate"])

    def test_unknown_task_type_degrades_to_cold_start_no_crash(self):
        with tempfile.TemporaryDirectory(prefix="lvw_") as td:
            ws = Path(td)
            seed_path = self._seed_path(ws, [])
            _append(ws, "a", "C1", "DROPPED",
                    {"model": "kimi-for-coding", "task_type": "not-a-real-task-type"})
            _append(ws, "b", "C1", "KEPT",
                    {"model": "kimi-for-coding", "task_type": "not-a-real-task-type"})
            out = weight.weigh(ws, seed_path=seed_path)
            c1 = out["candidates"]["C1"]
            # No calibration join => weights 1.0 => weighted == naive.
            self.assertEqual(c1["weighted_by_verdict"], {"DROPPED": 1.0, "KEPT": 1.0})
            self.assertFalse(c1["escalate"])

    def test_unknown_model_label_degrades_to_cold_start(self):
        with tempfile.TemporaryDirectory(prefix="lvw_") as td:
            ws = Path(td)
            seed_path = self._seed_path(
                ws,
                [{"provider": "kimi", "task_type": "adversarial-kill",
                  "sample_count": 40, "precision_pct": 30}],
            )
            _append(ws, "a", "C1", "DROPPED",
                    {"model": "some-unmapped-model", "task_type": "adversarial-kill"})
            out = weight.weigh(ws, seed_path=seed_path)
            lane = out["candidates"]["C1"]["lanes"][0]
            self.assertIsNone(lane["provider"])
            self.assertEqual(lane["weight"], 1.0)
            self.assertFalse(lane["calibrated"])

    def test_below_min_samples_stays_neutral(self):
        with tempfile.TemporaryDirectory(prefix="lvw_") as td:
            ws = Path(td)
            seed_path = self._seed_path(
                ws,
                [{"provider": "kimi", "task_type": "adversarial-kill",
                  "sample_count": 3, "precision_pct": 30}],
            )
            _append(ws, "a", "C1", "KEPT",
                    {"model": "kimi-for-coding", "task_type": "adversarial-kill"})
            out = weight.weigh(ws, seed_path=seed_path)
            lane = out["candidates"]["C1"]["lanes"][0]
            self.assertEqual(lane["weight"], 1.0)
            self.assertFalse(lane["calibrated"])


class ProviderResolutionTests(unittest.TestCase):
    def test_reverse_model_map_and_bare_provider(self):
        self.assertEqual(weight.resolve_provider("kimi-for-coding"), "kimi")
        self.assertEqual(weight.resolve_provider("MiniMax-M2.7"), "minimax")
        self.assertEqual(weight.resolve_provider("kimi"), "kimi")
        self.assertIsNone(weight.resolve_provider("gpt-4o"))
        self.assertIsNone(weight.resolve_provider(""))
        self.assertIsNone(weight.resolve_provider(None))
        # 'unknown' is the codex sentinel and must not join.
        self.assertIsNone(weight.resolve_provider("unknown"))


class EmitterRetrofitTests(unittest.TestCase):
    def _run_hook(self, payload: dict, ws: Path):
        env = os.environ.copy()
        env["AUDITOOOR_LANE_VERDICT_BUS_TOOL"] = str(BUS_TOOL)
        env["CLAUDE_PROJECT_DIR"] = str(ws)
        # Clear any ambient model/task env so omission is testable.
        for k in ("AUDITOOOR_LANE_MODEL", "ANTHROPIC_MODEL",
                  "AUDITOOOR_LANE_TASK_TYPE"):
            env.pop(k, None)
        return subprocess.run(
            ["bash", str(AUTOAPPEND)],
            input=json.dumps(payload),
            capture_output=True, text=True, env=env, cwd=str(ws), check=False,
        )

    def _rows(self, ws: Path, lane: str):
        p = ws / ".auditooor" / "lane_verdict_bus" / f"{lane}.jsonl"
        if not p.exists():
            return []
        return [json.loads(x) for x in p.read_text().splitlines() if x.strip()]

    def test_model_and_task_type_omitted_when_uninferable(self):
        with tempfile.TemporaryDirectory(prefix="lvw_hook_") as td:
            ws = Path(td) / "workspace"
            ws.mkdir()
            payload = {
                "tool_name": "Task",
                "tool_input": {
                    "prompt": f"workspace: {ws}\nlane_id: L1\ncandidate_id: C1",
                    "workspace_path": str(ws),
                },
                "tool_response": "VERDICT: DROPPED\n",
            }
            proc = self._run_hook(payload, ws)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            rows = self._rows(ws, "L1")
            self.assertEqual(len(rows), 1)
            md = rows[0]["metadata"]
            self.assertNotIn("model", md)
            self.assertNotIn("task_type", md)
            # Existing metadata preserved (no regression).
            self.assertEqual(md["source"], "posttooluse:Task")
            self.assertIn("verdict_hash", md)
            self.assertIn("reply_sha256", md)

    def test_model_and_task_type_emitted_from_tool_input(self):
        with tempfile.TemporaryDirectory(prefix="lvw_hook_") as td:
            ws = Path(td) / "workspace"
            ws.mkdir()
            payload = {
                "tool_name": "Task",
                "tool_input": {
                    "prompt": f"workspace: {ws}\nlane_id: L2\ncandidate_id: C2",
                    "workspace_path": str(ws),
                    "model": "kimi-for-coding",
                    "task_type": "adversarial-kill",
                },
                "tool_response": "VERDICT: KEPT\n",
            }
            proc = self._run_hook(payload, ws)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            rows = self._rows(ws, "L2")
            self.assertEqual(len(rows), 1)
            md = rows[0]["metadata"]
            self.assertEqual(md["model"], "kimi-for-coding")
            self.assertEqual(md["task_type"], "adversarial-kill")

    def test_model_and_task_type_from_prompt_regex(self):
        with tempfile.TemporaryDirectory(prefix="lvw_hook_") as td:
            ws = Path(td) / "workspace"
            ws.mkdir()
            payload = {
                "tool_name": "Agent",
                "tool_input": {
                    "prompt": (
                        f"workspace: {ws}\nlane_id: L3\ncandidate_id: C3\n"
                        "model: MiniMax-M2.7\ntask_type: source-extraction\n"
                    ),
                    "workspace_path": str(ws),
                },
                "tool_response": "VERDICT: DROPPED\n",
            }
            proc = self._run_hook(payload, ws)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            rows = self._rows(ws, "L3")
            self.assertEqual(len(rows), 1)
            md = rows[0]["metadata"]
            self.assertEqual(md["model"], "MiniMax-M2.7")
            self.assertEqual(md["task_type"], "source-extraction")


if __name__ == "__main__":
    unittest.main(verbosity=2)
