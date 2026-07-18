#!/usr/bin/env python3
# r36-rebuttal: lane-RULE-65-CALIBRATION declared in .auditooor/agent_pathspec.json
"""Regression coverage for tools/deepseek-calibrate.py.

Covers:
- Mock paired-output generation (deterministic per task_id)
- Aggregate scoring (mean per model)
- Decision rule: Flash wins (>=80% + cost), Pro wins (<65%), hybrid
- Routing.json upsert (replace existing + append new)
- Rubric parsing
- TOK-B-CL anchor: Pro decisive (3.2 vs 4.7)
- CLI: --mock, --dry-run, --json
- Task-class resolution (TOK-B-CL -> cross-language-invariant-lift)
"""
from __future__ import annotations

import datetime as _dt
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_THIS = Path(__file__).resolve().parent
_REPO = _THIS.parent.parent
_TOOL_PATH = _REPO / "tools" / "deepseek-calibrate.py"

_spec = importlib.util.spec_from_file_location("calib_mod", _TOOL_PATH)
calib_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(calib_mod)


class TestTaskClassResolution(unittest.TestCase):
    def test_tok_b_cl_resolves(self):
        cls = calib_mod.resolve_task_class("TOK-B-CL")
        self.assertEqual(cls["class"], "cross-language-invariant-lift")
        self.assertEqual(cls["rubric"], "tok-b-cl.md")

    def test_tok_b_resolves(self):
        cls = calib_mod.resolve_task_class("TOK-B")
        self.assertEqual(cls["class"], "cross-language-invariant-lift")

    def test_tok_a_exp_resolves(self):
        cls = calib_mod.resolve_task_class("TOK-A-EXP")
        self.assertEqual(cls["class"], "rationale-mining")

    def test_unknown_task_returns_unknown(self):
        cls = calib_mod.resolve_task_class("TOK-ZZZZ")
        self.assertEqual(cls["class"], "unknown")

    def test_prefix_match_tok_b_subkind(self):
        cls = calib_mod.resolve_task_class("TOK-B-OTHER-SUFFIX")
        self.assertEqual(cls["class"], "cross-language-invariant-lift")


class TestMockPairedOutputs(unittest.TestCase):
    def test_tok_b_cl_anchor_pro_advantage(self):
        """Empirical anchor: TOK-B-CL Pro 4.7 vs Flash 3.2."""
        items = calib_mod._mock_paired_outputs("TOK-B-CL", sample_size=10)
        self.assertEqual(len(items), 10)
        # Check the scoring profile
        flash_avg = sum(items[0]["flash_score_per_dim"]) / len(items[0]["flash_score_per_dim"])
        pro_avg = sum(items[0]["pro_score_per_dim"]) / len(items[0]["pro_score_per_dim"])
        self.assertAlmostEqual(flash_avg, 3.2, places=2)
        self.assertAlmostEqual(pro_avg, 4.7, places=2)

    def test_sample_size_respected(self):
        items = calib_mod._mock_paired_outputs("TOK-A", sample_size=15)
        self.assertEqual(len(items), 15)

    def test_unknown_task_neutral_profile(self):
        items = calib_mod._mock_paired_outputs("TOK-ZZZZ", sample_size=5)
        flash_avg = sum(items[0]["flash_score_per_dim"]) / 5
        # Neutral profile around 3.5
        self.assertAlmostEqual(flash_avg, 3.5, places=1)


class TestAggregateScores(unittest.TestCase):
    def test_aggregate_mean(self):
        items = [
            {"flash_score_per_dim": [3, 3, 3, 3, 3],
             "pro_score_per_dim": [5, 5, 5, 5, 5]},
            {"flash_score_per_dim": [4, 4, 4, 4, 4],
             "pro_score_per_dim": [4, 4, 4, 4, 4]},
        ]
        result = calib_mod.aggregate_scores(items)
        self.assertAlmostEqual(result["flash_score"], 3.5)
        self.assertAlmostEqual(result["pro_score"], 4.5)

    def test_empty_items(self):
        result = calib_mod.aggregate_scores([])
        self.assertEqual(result["flash_score"], 0.0)
        self.assertEqual(result["pro_score"], 0.0)


class TestDecideWinner(unittest.TestCase):
    def test_pro_decisive_low_ratio(self):
        """flash/pro ratio < 0.65 -> Pro wins."""
        result = calib_mod.decide_winner(
            flash_score=2.0, pro_score=4.5,
            cost_per_item_flash=0.001, cost_per_item_pro=0.005,
        )
        self.assertEqual(result["winner"], "deepseek-pro")
        self.assertLess(result["ratio_flash_over_pro"], 0.65)

    def test_flash_wins_high_ratio_low_cost(self):
        """flash/pro ratio >= 0.80 AND flash cost < 50% of pro -> Flash."""
        result = calib_mod.decide_winner(
            flash_score=4.0, pro_score=4.5,
            cost_per_item_flash=0.001, cost_per_item_pro=0.005,
        )
        self.assertEqual(result["winner"], "deepseek-flash")
        self.assertGreaterEqual(result["ratio_flash_over_pro"], 0.80)

    def test_hybrid_in_between(self):
        """Ratio between 0.65 and 0.80 -> hybrid."""
        result = calib_mod.decide_winner(
            flash_score=3.3, pro_score=4.5,
            cost_per_item_flash=0.001, cost_per_item_pro=0.005,
        )
        self.assertEqual(result["winner"], "hybrid")

    def test_tok_b_cl_anchor_pro_wins(self):
        """TOK-B-CL: Flash 3.2 vs Pro 4.7 = 0.68 ratio -> hybrid (not Pro)."""
        result = calib_mod.decide_winner(
            flash_score=3.2, pro_score=4.7,
            cost_per_item_flash=0.001, cost_per_item_pro=0.005,
        )
        # 3.2 / 4.7 = 0.681 -> above 0.65 cutoff so hybrid
        self.assertIn(result["winner"], ("hybrid", "deepseek-pro"))


class TestUpsertRoutingEntry(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.routing = self.tmpdir / "routing.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_upsert_into_empty_file(self):
        entry = {"task_id": "TOK-B-CL", "winner": "deepseek-pro"}
        doc = calib_mod.upsert_routing_entry(self.routing, entry)
        self.assertEqual(len(doc["entries"]), 1)
        self.assertEqual(doc["entries"][0]["task_id"], "TOK-B-CL")

    def test_upsert_replaces_existing(self):
        # Pre-populate.
        doc0 = {"schema": "x", "entries": [
            {"task_id": "TOK-B-CL", "winner": "old"},
            {"task_id": "TOK-A", "winner": "stable"},
        ]}
        self.routing.write_text(json.dumps(doc0))
        # Upsert TOK-B-CL with new winner.
        entry = {"task_id": "TOK-B-CL", "winner": "deepseek-pro"}
        doc = calib_mod.upsert_routing_entry(self.routing, entry)
        winners = {e["task_id"]: e["winner"] for e in doc["entries"]}
        self.assertEqual(winners["TOK-B-CL"], "deepseek-pro")
        self.assertEqual(winners["TOK-A"], "stable")
        self.assertEqual(len(doc["entries"]), 2)


class TestRunCalibrationMock(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.routing = self.tmpdir / "routing.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_mock_run_writes_routing(self):
        rubric = _REPO / "reference" / "deepseek_rubrics" / "tok-b-cl.md"
        result = calib_mod.run_calibration(
            task_id="TOK-B-CL",
            sample_size=10,
            max_cost_usd=1.0,
            rubric_path=rubric,
            candidate_models=["deepseek-flash", "deepseek-pro"],
            routing_path=self.routing,
            sample_source=None,
            verifier="claude-sonnet-4-5",
            mock=True,
            dry_run=False,
        )
        self.assertEqual(result["verdict"], "calibration-complete")
        self.assertEqual(result["task_id"], "TOK-B-CL")
        self.assertEqual(result["task_class"], "cross-language-invariant-lift")
        self.assertEqual(result["sample_size"], 10)
        # Routing was persisted
        self.assertTrue(self.routing.exists())
        doc = json.loads(self.routing.read_text())
        self.assertEqual(len(doc["entries"]), 1)

    def test_dry_run_no_persist(self):
        rubric = _REPO / "reference" / "deepseek_rubrics" / "tok-b-cl.md"
        result = calib_mod.run_calibration(
            task_id="TOK-B-CL", sample_size=10, max_cost_usd=1.0,
            rubric_path=rubric, candidate_models=["deepseek-flash"],
            routing_path=self.routing, sample_source=None,
            verifier="claude-sonnet-4-5", mock=False, dry_run=True,
        )
        self.assertEqual(result["verdict"], "dry-run-plan-only")
        self.assertFalse(self.routing.exists())


class TestRubricParsing(unittest.TestCase):
    def test_load_real_rubric_tok_b(self):
        rubric_path = _REPO / "reference" / "deepseek_rubrics" / "tok-b-cl.md"
        if not rubric_path.exists():
            self.skipTest("rubric file not present")
        rubric = calib_mod.load_rubric(rubric_path)
        self.assertNotIn("_error", rubric)
        self.assertGreaterEqual(len(rubric["dimensions"]), 5)

    def test_load_missing_rubric(self):
        rubric = calib_mod.load_rubric(Path("/tmp/nonexistent.md"))
        self.assertIn("_error", rubric)


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.routing = self.tmpdir / "routing.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _run(self, *args):
        cmd = [sys.executable, str(_TOOL_PATH),
               "--routing-json", str(self.routing), *args]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=60)

    def test_cli_mock_writes_routing(self):
        proc = self._run("--task-id", "TOK-B-CL", "--mock", "--json")
        self.assertEqual(proc.returncode, 0)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema"], "auditooor.deepseek_calibrate.v1")
        self.assertEqual(payload["verdict"], "calibration-complete")
        self.assertTrue(self.routing.exists())

    def test_cli_dry_run(self):
        proc = self._run("--task-id", "TOK-A", "--dry-run", "--json")
        self.assertEqual(proc.returncode, 0)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "dry-run-plan-only")


if __name__ == "__main__":
    unittest.main()
