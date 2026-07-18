#!/usr/bin/env python3
# R36 pathspec discipline: this test belongs to lane-DEEPSEEK-FANOUT-HARNESS
# registered in .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py.
"""Unit tests for tools/llm-fanout-dispatcher.py.

All tests run in --mock mode (no network). Each test exercises a single
slice of the fanout state machine: concurrency cap, retry policy, budget
cap, monitor JSONL, output-dir layout, dry-run, L34 v2 refusal.
"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from typing import Any, Dict, List


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DISPATCHER = REPO_ROOT / "tools" / "llm-fanout-dispatcher.py"
FIXTURES = REPO_ROOT / "tools" / "tests" / "fixtures" / "deepseek_fanout"


def _load_dispatcher_module() -> Any:
    """Load tools/llm-fanout-dispatcher.py as a module for direct calls."""
    spec = importlib.util.spec_from_file_location(
        "deepseek_fanout_dispatcher", str(DISPATCHER)
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _write_batch(tmpdir: pathlib.Path, tasks: List[Dict[str, Any]]) -> pathlib.Path:
    """Helper: write a JSONL batch from a list of task dicts."""
    p = tmpdir / "batch.jsonl"
    with p.open("w", encoding="utf-8") as fh:
        for t in tasks:
            fh.write(json.dumps(t) + "\n")
    return p


def _make_task(i: int, task_type: str = "tok_a_corpus_mine",
               prompt: str = "test prompt") -> Dict[str, Any]:
    return {
        "task_id": f"{task_type}_{i:04d}",
        "task_type": task_type,
        "prompt": prompt + f" [#{i}]",
        "max_input_tokens": 1000,
        "max_output_tokens": 500,
        "verification_tier_target": "tier-3-synthetic-taxonomy-anchored",
        "meta": {"idx": i},
    }


def _run_dispatcher(args: List[str]) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(DISPATCHER)] + args
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60)


class TestDeepSeekFanout(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmpdir = pathlib.Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # ------------------------------------------------------------------
    # Case 1: mock-mode 10-task batch all succeed, cost computed
    # ------------------------------------------------------------------
    def test_01_mock_10_tasks_all_succeed_cost_calc(self) -> None:
        batch = _write_batch(self.tmpdir, [_make_task(i) for i in range(10)])
        out_dir = self.tmpdir / "out"
        monitor = self.tmpdir / "monitor.jsonl"
        res = _run_dispatcher([
            "--task-batch", str(batch),
            "--provider", "deepseek-flash",
            "--concurrency", "5",
            "--output-dir", str(out_dir),
            "--monitor-jsonl", str(monitor),
            "--budget-cap-usd", "1.0",
            "--mock", "--json",
        ])
        self.assertEqual(res.returncode, 0, msg=res.stderr)
        summary = json.loads(res.stdout)
        self.assertEqual(summary["total_tasks"], 10)
        self.assertEqual(summary["ok"], 10)
        self.assertEqual(summary["failed"], 0)
        self.assertGreater(summary["cost_usd_total"], 0.0)
        self.assertEqual(summary["concurrency_cap"], 5)
        # Verify per-task files exist
        produced = list(out_dir.glob("*.json"))
        self.assertEqual(len(produced), 10)
        # Verify monitor JSONL exists
        self.assertTrue(monitor.exists())
        self.assertGreater(monitor.stat().st_size, 0)

    # ------------------------------------------------------------------
    # Case 2: concurrency cap 50 enforced (default; no --aggressive)
    # ------------------------------------------------------------------
    def test_02_concurrency_default_cap_50(self) -> None:
        batch = _write_batch(self.tmpdir, [_make_task(i) for i in range(5)])
        out_dir = self.tmpdir / "out"
        # Pass concurrency higher than default; should be clamped to 50.
        res = _run_dispatcher([
            "--task-batch", str(batch),
            "--concurrency", "200",
            "--output-dir", str(out_dir),
            "--mock", "--json",
        ])
        self.assertEqual(res.returncode, 0, msg=res.stderr)
        summary = json.loads(res.stdout)
        # Clamped to 50.
        self.assertEqual(summary["concurrency_cap"], 50)
        self.assertIn("default cap", res.stderr)

    # ------------------------------------------------------------------
    # Case 3: --aggressive allows concurrency up to 500
    # ------------------------------------------------------------------
    def test_03_aggressive_allows_500(self) -> None:
        batch = _write_batch(self.tmpdir, [_make_task(i) for i in range(3)])
        out_dir = self.tmpdir / "out"
        res = _run_dispatcher([
            "--task-batch", str(batch),
            "--concurrency", "500",
            "--aggressive",
            "--output-dir", str(out_dir),
            "--mock", "--json",
        ])
        self.assertEqual(res.returncode, 0, msg=res.stderr)
        summary = json.loads(res.stdout)
        self.assertEqual(summary["concurrency_cap"], 500)

    # ------------------------------------------------------------------
    # Case 4: --aggressive with concurrency over 500 clamps to 500
    # ------------------------------------------------------------------
    def test_04_aggressive_clamps_at_500(self) -> None:
        batch = _write_batch(self.tmpdir, [_make_task(i) for i in range(2)])
        out_dir = self.tmpdir / "out"
        res = _run_dispatcher([
            "--task-batch", str(batch),
            "--concurrency", "10000",
            "--aggressive",
            "--output-dir", str(out_dir),
            "--mock", "--json",
        ])
        self.assertEqual(res.returncode, 0, msg=res.stderr)
        summary = json.loads(res.stdout)
        self.assertEqual(summary["concurrency_cap"], 500)
        self.assertIn("aggressive max", res.stderr)

    # ------------------------------------------------------------------
    # Case 5: per-batch budget cap halts gracefully
    # ------------------------------------------------------------------
    def test_05_budget_cap_halt(self) -> None:
        # 20 tasks; set budget so low that cap fires partway through.
        batch = _write_batch(self.tmpdir, [_make_task(i) for i in range(20)])
        out_dir = self.tmpdir / "out"
        monitor = self.tmpdir / "monitor.jsonl"
        res = _run_dispatcher([
            "--task-batch", str(batch),
            "--concurrency", "1",  # serial so the cap fires deterministically
            "--output-dir", str(out_dir),
            "--monitor-jsonl", str(monitor),
            "--budget-cap-usd", "0.00005",  # extremely small
            "--mock", "--json",
        ])
        # Should NOT exit non-zero (budget exhaustion is graceful).
        self.assertEqual(res.returncode, 0, msg=res.stderr)
        summary = json.loads(res.stdout)
        # Check halt_reason in monitor or in summary
        monitor_lines = monitor.read_text().strip().split("\n")
        halt_events = [
            json.loads(line) for line in monitor_lines
            if json.loads(line).get("event") == "batch_halt"
        ]
        self.assertGreater(
            len(halt_events), 0,
            msg=f"expected at least one batch_halt event; summary={summary}",
        )
        self.assertEqual(halt_events[0]["details"]["reason"],
                         "BUDGET_CAP_EXCEEDED")

    # ------------------------------------------------------------------
    # Case 6: monitor JSONL emits one event per state-change
    # ------------------------------------------------------------------
    def test_06_monitor_jsonl_per_state_change(self) -> None:
        batch = _write_batch(self.tmpdir, [_make_task(i) for i in range(5)])
        out_dir = self.tmpdir / "out"
        monitor = self.tmpdir / "monitor.jsonl"
        res = _run_dispatcher([
            "--task-batch", str(batch),
            "--concurrency", "2",
            "--output-dir", str(out_dir),
            "--monitor-jsonl", str(monitor),
            "--mock", "--json",
        ])
        self.assertEqual(res.returncode, 0, msg=res.stderr)
        lines = monitor.read_text().strip().split("\n")
        # Expect at least 2 events per task (started + ok) = 10 events.
        events = [json.loads(line) for line in lines]
        started = sum(1 for e in events if e["event"] == "task_started")
        ok = sum(1 for e in events if e["event"] == "task_ok")
        self.assertEqual(started, 5)
        self.assertEqual(ok, 5)
        # Cost is cumulative + monotonic non-decreasing
        cumulative = [e["cost_usd_cumulative"] for e in events]
        for prev, curr in zip(cumulative, cumulative[1:]):
            self.assertGreaterEqual(curr, prev,
                                    msg="cumulative cost regressed in monitor")

    # ------------------------------------------------------------------
    # Case 7: per-task result file shape carries verification_tier
    # ------------------------------------------------------------------
    def test_07_per_task_result_carries_verification_tier(self) -> None:
        batch = _write_batch(self.tmpdir, [_make_task(0)])
        out_dir = self.tmpdir / "out"
        res = _run_dispatcher([
            "--task-batch", str(batch),
            "--output-dir", str(out_dir),
            "--mock", "--json",
        ])
        self.assertEqual(res.returncode, 0, msg=res.stderr)
        result_files = list(out_dir.glob("*.json"))
        self.assertEqual(len(result_files), 1)
        record = json.loads(result_files[0].read_text())
        # R37 tier present + non-empty
        self.assertIn("verification_tier", record)
        self.assertTrue(record["verification_tier"])
        # Standard fields present
        for k in ("task_id", "status", "provider", "input_tokens",
                  "output_tokens", "cost_usd", "duration_s", "result",
                  "retries", "started_at_utc", "ended_at_utc"):
            self.assertIn(k, record, msg=f"missing field: {k}")
        self.assertEqual(record["status"], "ok")
        self.assertEqual(record["provider"], "deepseek-flash")

    def test_07b_per_task_result_carries_mimo_context_metadata(self) -> None:
        task = _make_task(0, task_type="per_file_workspace_hunt_v2")
        task.update({
            "source_question_id": "q-theft",
            "attack_class": "theft",
            "hacker_q_reweight": {"signal_score": 7, "signal_class": "HIGH"},
            "mimo_context_feed": {
                "schema": "auditooor.mimo_prompt_context_feed.v1",
                "mcp_calls": [{"callable": "vault_attack_class_evidence_v3"}],
            },
            "file_anchor": {"file_path": "src/Vault.sol", "is_uncovered": True},
        })
        batch = _write_batch(self.tmpdir, [task])
        out_dir = self.tmpdir / "out"
        res = _run_dispatcher([
            "--task-batch", str(batch),
            "--output-dir", str(out_dir),
            "--mock", "--json",
        ])
        self.assertEqual(res.returncode, 0, msg=res.stderr)
        record = json.loads(next(out_dir.glob("*.json")).read_text())
        self.assertEqual(record["source_question_id"], "q-theft")
        self.assertEqual(record["attack_class"], "theft")
        self.assertEqual(record["hacker_q_reweight"]["signal_score"], 7)
        self.assertEqual(
            record["mimo_context_feed"]["schema"],
            "auditooor.mimo_prompt_context_feed.v1",
        )
        self.assertEqual(record["file_anchor"]["file_path"], "src/Vault.sol")

    # ------------------------------------------------------------------
    # Case 8: dry-run prints summary + cost estimate, no API call
    # ------------------------------------------------------------------
    def test_08_dry_run_summary_only(self) -> None:
        batch = _write_batch(self.tmpdir, [_make_task(i) for i in range(7)])
        out_dir = self.tmpdir / "out"
        res = _run_dispatcher([
            "--task-batch", str(batch),
            "--output-dir", str(out_dir),
            "--dry-run", "--json",
        ])
        self.assertEqual(res.returncode, 0, msg=res.stderr)
        summary = json.loads(res.stdout)
        self.assertTrue(summary["dry_run"])
        self.assertEqual(summary["total_tasks"], 7)
        self.assertIn("estimated_cost_usd_low", summary)
        self.assertIn("estimated_cost_usd_high", summary)
        self.assertGreaterEqual(
            summary["estimated_cost_usd_high"],
            summary["estimated_cost_usd_low"],
        )
        # No per-task result files should be emitted in dry-run.
        produced = list(out_dir.glob("*.json"))
        self.assertEqual(len(produced), 0)

    # ------------------------------------------------------------------
    # Case 9: empty batch handled gracefully
    # ------------------------------------------------------------------
    def test_09_empty_batch(self) -> None:
        empty = self.tmpdir / "empty.jsonl"
        empty.write_text("")
        out_dir = self.tmpdir / "out"
        res = _run_dispatcher([
            "--task-batch", str(empty),
            "--output-dir", str(out_dir),
            "--mock", "--json",
        ])
        self.assertEqual(res.returncode, 0, msg=res.stderr)
        summary = json.loads(res.stdout)
        self.assertEqual(summary["total_tasks"], 0)
        self.assertEqual(summary.get("summary"), "empty-batch")

    # ------------------------------------------------------------------
    # Case 10: L34 v2 refuses draft-file bucket as output-dir
    # ------------------------------------------------------------------
    def test_10_l34_refuses_draft_file_bucket(self) -> None:
        batch = _write_batch(self.tmpdir, [_make_task(0)])
        # Construct an L34 draft-file bucket path
        draft_dir = self.tmpdir / "submissions" / "paste_ready" / \
                    "hb-some-finding-HIGH" / "hb-some-finding-HIGH.md"
        # The dispatcher uses output_dir as a DIRECTORY; the L34 regex
        # checks for the canonical draft-file shape in the path. We supply
        # a path that ends in submissions/<status>/<slug>/<slug>.md.
        res = _run_dispatcher([
            "--task-batch", str(batch),
            "--output-dir", str(draft_dir),
            "--mock", "--json",
        ])
        # Should refuse with exit 2.
        self.assertEqual(res.returncode, 2, msg=res.stderr)
        summary = json.loads(res.stdout)
        self.assertEqual(summary.get("summary"), "l34-refused")

    # ------------------------------------------------------------------
    # Case 11: missing task batch -> exit 2 with FileNotFoundError
    # ------------------------------------------------------------------
    def test_11_missing_task_batch(self) -> None:
        out_dir = self.tmpdir / "out"
        res = _run_dispatcher([
            "--task-batch", "/nonexistent/batch.jsonl",
            "--output-dir", str(out_dir),
            "--mock", "--json",
        ])
        self.assertEqual(res.returncode, 2)
        self.assertIn("task batch not found", res.stderr)

    # ------------------------------------------------------------------
    # Case 12: per-task verification_tier_target overrides default
    # ------------------------------------------------------------------
    def test_12_per_task_tier_override(self) -> None:
        task = _make_task(0)
        task["verification_tier_target"] = "tier-2-verified-public-archive"
        batch = _write_batch(self.tmpdir, [task])
        out_dir = self.tmpdir / "out"
        res = _run_dispatcher([
            "--task-batch", str(batch),
            "--output-dir", str(out_dir),
            "--verification-tier", "tier-3-synthetic-taxonomy-anchored",
            "--mock", "--json",
        ])
        self.assertEqual(res.returncode, 0, msg=res.stderr)
        result_files = list(out_dir.glob("*.json"))
        record = json.loads(result_files[0].read_text())
        self.assertEqual(record["verification_tier"],
                         "tier-2-verified-public-archive")

    # ------------------------------------------------------------------
    # Case 13: in-process cost computation matches default pricing
    # ------------------------------------------------------------------
    def test_13_cost_computation_matches_pricing(self) -> None:
        mod = _load_dispatcher_module()
        # 1000 input tokens + 500 output tokens of deepseek-flash
        cost = mod._compute_cost_usd("deepseek-flash", 1000, 500)
        # 1.0 * 0.00014 + 0.5 * 0.00028 = 0.00014 + 0.00014 = 0.00028
        self.assertAlmostEqual(cost, 0.00028, places=8)
        # Pro pricing
        cost_pro = mod._compute_cost_usd("deepseek-pro", 1000, 500)
        # 1.0 * 0.00060 + 0.5 * 0.00120 = 0.00060 + 0.00060 = 0.00120
        self.assertAlmostEqual(cost_pro, 0.00120, places=8)

    # ------------------------------------------------------------------
    # Case 14: deterministic mock response shape
    # ------------------------------------------------------------------
    def test_14_mock_response_deterministic(self) -> None:
        mod = _load_dispatcher_module()
        task = _make_task(42, prompt="some content")
        r1, in1, out1 = mod._mock_response(task, "deepseek-flash")
        r2, in2, out2 = mod._mock_response(task, "deepseek-flash")
        # Determinism: same task -> same response, same tokens
        self.assertEqual(r1, r2)
        self.assertEqual(in1, in2)
        self.assertEqual(out1, out2)
        # Response contains task_id
        self.assertIn(task["task_id"], r1)

    # ------------------------------------------------------------------
    # Case 15: TOK-A fixture parses + dispatches in mock mode
    # ------------------------------------------------------------------
    def test_15_tok_a_fixture_end_to_end(self) -> None:
        fixture = FIXTURES / "tok_a_corpus_mine.jsonl"
        self.assertTrue(fixture.exists(), msg=f"fixture missing: {fixture}")
        out_dir = self.tmpdir / "tok_a_out"
        res = _run_dispatcher([
            "--task-batch", str(fixture),
            "--output-dir", str(out_dir),
            "--mock", "--json",
        ])
        self.assertEqual(res.returncode, 0, msg=res.stderr)
        summary = json.loads(res.stdout)
        self.assertEqual(summary["total_tasks"], 10)
        self.assertEqual(summary["ok"], 10)

    # ------------------------------------------------------------------
    # Case 16: all 5 fixtures dispatch successfully
    # ------------------------------------------------------------------
    def test_16_all_five_fixtures_dispatch(self) -> None:
        fixtures = [
            "tok_a_corpus_mine.jsonl",
            "tok_b_invariant_lift.jsonl",
            "tok_c_hypothesis_gen.jsonl",
            "tok_d_persona_drafts.jsonl",
            "tok_f_freshness_delta.jsonl",
        ]
        for f in fixtures:
            fixture = FIXTURES / f
            out_dir = self.tmpdir / f.replace(".jsonl", "_out")
            res = _run_dispatcher([
                "--task-batch", str(fixture),
                "--output-dir", str(out_dir),
                "--mock", "--json",
            ])
            self.assertEqual(res.returncode, 0,
                             msg=f"fixture {f} failed: {res.stderr}")
            summary = json.loads(res.stdout)
            self.assertEqual(summary["total_tasks"], 10,
                             msg=f"fixture {f} task count mismatch")

    # ------------------------------------------------------------------
    # Case 17: dry-run cost estimate scales linearly with task count
    # ------------------------------------------------------------------
    def test_17_dry_run_cost_estimate_linearity(self) -> None:
        batch5 = _write_batch(
            self.tmpdir / "five", []
        ) if False else None  # placeholder
        # Generate 5-task vs 50-task batches
        b1 = self.tmpdir / "b1.jsonl"
        b2 = self.tmpdir / "b2.jsonl"
        with b1.open("w") as fh:
            for i in range(5):
                fh.write(json.dumps(_make_task(i)) + "\n")
        with b2.open("w") as fh:
            for i in range(50):
                fh.write(json.dumps(_make_task(i)) + "\n")
        r1 = _run_dispatcher([
            "--task-batch", str(b1), "--dry-run", "--json",
        ])
        r2 = _run_dispatcher([
            "--task-batch", str(b2), "--dry-run", "--json",
        ])
        self.assertEqual(r1.returncode, 0, msg=r1.stderr)
        self.assertEqual(r2.returncode, 0, msg=r2.stderr)
        s1 = json.loads(r1.stdout)
        s2 = json.loads(r2.stdout)
        # 50/5 = 10x; cost should be ~10x.
        ratio = s2["estimated_cost_usd_high"] / max(s1["estimated_cost_usd_high"], 1e-9)
        self.assertAlmostEqual(ratio, 10.0, places=1)

    # ------------------------------------------------------------------
    # Case 18: existing output file is skipped and preserved by default
    # ------------------------------------------------------------------
    def test_18_existing_output_not_overwritten_by_default(self) -> None:
        batch = _write_batch(self.tmpdir, [_make_task(i) for i in range(2)])
        out_dir = self.tmpdir / "out"
        out_dir.mkdir()
        existing = out_dir / "tok_a_corpus_mine_0000.json"
        existing.write_text(
            json.dumps({
                "task_id": "tok_a_corpus_mine_0000",
                "status": "canonical",
                "sentinel": "do-not-overwrite",
            }) + "\n",
            encoding="utf-8",
        )
        res = _run_dispatcher([
            "--task-batch", str(batch),
            "--output-dir", str(out_dir),
            "--mock", "--json",
        ])
        self.assertEqual(res.returncode, 0, msg=res.stderr)
        summary = json.loads(res.stdout)
        self.assertEqual(summary["total_input_tasks"], 2)
        self.assertEqual(summary["total_tasks"], 1)
        self.assertEqual(summary["skipped_existing"], 1)
        self.assertEqual(summary["ok"], 1)

        preserved = json.loads(existing.read_text(encoding="utf-8"))
        self.assertEqual(preserved["status"], "canonical")
        self.assertEqual(preserved["sentinel"], "do-not-overwrite")
        self.assertTrue((out_dir / "tok_a_corpus_mine_0001.json").exists())


if __name__ == "__main__":
    unittest.main()
