# r36-rebuttal: registered lane learning-closeout-wiring in .auditooor/agent_pathspec.json
"""Tests for the learning-closeout wiring (FIX 1 + FIX 2).

FIX 1: the learning-closeout Makefile recipe invokes the 3 formerly-orphan
       feedback/learning tools (outcome-feedback-loop, triage-feedback-collector,
       triage-verdict-feedback), each gated/advisory/persisting.
FIX 2: the per-workspace learning ledgers are aggregated into a shared corpus
       (tools/learning-ledger-aggregate.py) and that derived path is registered
       in obsidian-vault-sync SECTION_SOURCES so recall can surface them.
"""
from __future__ import annotations

import importlib.util
import json
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
MAKEFILE = REPO_ROOT / "Makefile"
AGG_TOOL = REPO_ROOT / "tools" / "learning-ledger-aggregate.py"
VAULT_SYNC = REPO_ROOT / "tools" / "obsidian-vault-sync.py"
AGG_DERIVED = "audit/corpus_tags/derived/agent_learning_ledger_aggregated.jsonl"


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _learning_closeout_recipe() -> str:
    """Return the text of the learning-closeout recipe block."""
    text = MAKEFILE.read_text(encoding="utf-8")
    m = re.search(r"\nlearning-closeout:.*?(?=\n[A-Za-z0-9_.-]+:|\n# =====)", text, re.DOTALL)
    assert m, "learning-closeout target not found in Makefile"
    return m.group(0)


class TestLearningCloseoutInvokesFeedbackTools(unittest.TestCase):
    """FIX 1: each of the 3 tools is invoked by the learning-closeout recipe."""

    def setUp(self) -> None:
        self.recipe = _learning_closeout_recipe()

    def test_outcome_feedback_loop_invoked(self) -> None:
        self.assertIn("tools/outcome-feedback-loop.py", self.recipe)

    def test_triage_feedback_collector_invoked(self) -> None:
        self.assertIn("tools/triage-feedback-collector.py", self.recipe)
        # Must use the persisting --sync-from-md mode, not a read-only list.
        self.assertIn("--sync-from-md", self.recipe)

    def test_triage_verdict_feedback_invoked(self) -> None:
        self.assertIn("tools/triage-verdict-feedback.py", self.recipe)

    def test_each_tool_skips_cleanly_when_input_absent(self) -> None:
        # Each tool is guarded by a conditional and emits SKIP/WARN rather than
        # hard-failing the closeout.
        self.assertIn("SKIP outcome-feedback-loop", self.recipe)
        self.assertIn("SKIP triage-feedback-collector", self.recipe)
        self.assertIn("SKIP triage-verdict-feedback", self.recipe)

    def test_outcome_feedback_loop_runs_live_not_dry_run(self) -> None:
        # Closeout must PERSIST, so the recipe must NOT pass --dry-run to the
        # outcome feedback loop.
        line = [l for l in self.recipe.splitlines() if "outcome-feedback-loop.py" in l]
        self.assertTrue(line)
        for l in line:
            self.assertNotIn("--dry-run", l)


class TestLearningCloseoutAggregationStep(unittest.TestCase):
    """FIX 2: aggregation step present in the recipe + path registered in vault sync."""

    def test_aggregation_step_in_recipe(self) -> None:
        recipe = _learning_closeout_recipe()
        self.assertIn("tools/learning-ledger-aggregate.py", recipe)

    def test_aggregated_path_registered_in_section_sources(self) -> None:
        sync_mod = _load_module(VAULT_SYNC, "obsidian_vault_sync_for_test")
        mining = sync_mod.SECTION_SOURCES.get("mining", [])
        self.assertIn(AGG_DERIVED, mining,
                      "aggregated learning-ledger corpus must be registered in "
                      "SECTION_SOURCES['mining'] so recall surfaces it")


class TestAggregatorBehavior(unittest.TestCase):
    """FIX 2: the aggregator dedupes, is idempotent, and skips cleanly."""

    def setUp(self) -> None:
        self.mod = _load_module(AGG_TOOL, "learning_ledger_aggregate_for_test")

    def _write_ledger(self, ws: Path, rows: list[dict]) -> Path:
        d = ws / ".auditooor" / "agent_artifacts"
        d.mkdir(parents=True, exist_ok=True)
        p = d / "learning_ledger.jsonl"
        p.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        return p

    def test_skips_cleanly_when_no_ledgers(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "audits"
            root.mkdir()
            out = Path(td) / "agg.jsonl"
            res = self.mod.aggregate(root, out, include_repo_local=False)
            self.assertEqual(res["ledger_count"], 0)
            self.assertEqual(res["rows_added"], 0)
            self.assertFalse(out.exists())

    def test_aggregates_across_workspaces(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "audits"
            ws_a = root / "alpha"
            ws_b = root / "beta"
            self._write_ledger(ws_a, [
                {"artifact_id": "a1", "terminal_kind": "k", "primary_for": "x", "workspace": str(ws_a)},
            ])
            self._write_ledger(ws_b, [
                {"artifact_id": "b1", "terminal_kind": "k", "primary_for": "x", "workspace": str(ws_b)},
            ])
            out = Path(td) / "agg.jsonl"
            res = self.mod.aggregate(root, out, include_repo_local=False)
            self.assertEqual(res["ledger_count"], 2)
            self.assertEqual(res["rows_added"], 2)
            self.assertTrue(out.exists())
            self.assertEqual(len(out.read_text().strip().splitlines()), 2)

    def test_idempotent_rerun_adds_zero(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "audits"
            ws = root / "alpha"
            self._write_ledger(ws, [
                {"artifact_id": "a1", "terminal_kind": "k", "primary_for": "x", "workspace": str(ws)},
            ])
            out = Path(td) / "agg.jsonl"
            first = self.mod.aggregate(root, out, include_repo_local=False)
            self.assertEqual(first["rows_added"], 1)
            second = self.mod.aggregate(root, out, include_repo_local=False)
            self.assertEqual(second["rows_added"], 0)
            self.assertEqual(second["rows_total"], 1)

    def test_single_workspace_does_not_clobber_others(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "audits"
            ws_a = root / "alpha"
            ws_b = root / "beta"
            self._write_ledger(ws_a, [
                {"artifact_id": "a1", "terminal_kind": "k", "primary_for": "x", "workspace": str(ws_a)},
            ])
            self._write_ledger(ws_b, [
                {"artifact_id": "b1", "terminal_kind": "k", "primary_for": "x", "workspace": str(ws_b)},
            ])
            out = Path(td) / "agg.jsonl"
            self.mod.aggregate(root, out, include_repo_local=False)  # full roll-up: 2 rows
            # Now a single-workspace closeout for alpha must keep beta's row.
            res = self.mod.aggregate(root, out, workspace=ws_a, include_repo_local=False)
            self.assertEqual(res["rows_added"], 0)
            self.assertEqual(res["rows_total"], 2)
            lines = out.read_text().strip().splitlines()
            self.assertEqual(len(lines), 2)


if __name__ == "__main__":
    unittest.main()
