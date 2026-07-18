from __future__ import annotations

import importlib.util
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "batch-checkpoint-status.py"


def load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("batch_checkpoint_status", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MOD = load_module()


class BatchCheckpointStatusTest(unittest.TestCase):
    def test_below_threshold_keeps_push_and_broad_docs_deferred(self) -> None:
        original = MOD.summarize_dirty_files
        MOD.summarize_dirty_files = lambda repo_root: {"total": 0, "by_role": {}, "by_status": {}}
        with tempfile.TemporaryDirectory() as tmp:
            try:
                report = MOD.build_status(
                    repo_root=Path(tmp),
                    local_commit_count=6,
                    commits_behind_upstream=2,
                    loops_since_checkpoint=3,
                )
            finally:
                MOD.summarize_dirty_files = original

        self.assertFalse(report["state"]["checkpoint_due"])
        self.assertFalse(report["recommendation"]["push_now"])
        self.assertFalse(report["recommendation"]["refresh_broad_github_docs_now"])
        self.assertTrue(report["recommendation"]["keep_broad_github_docs_untouched"])
        self.assertTrue(report["recommendation"]["continue_local_batch"])
        self.assertEqual(report["state"]["commits_behind_upstream"], 2)
        self.assertTrue(report["state"]["coordination_reason_required_for_early_push"])
        self.assertIn("obsidian-vault/", report["policy"]["live_state_sources"])

    def test_commit_threshold_allows_checkpoint_packaging(self) -> None:
        original = MOD.summarize_dirty_files
        MOD.summarize_dirty_files = lambda repo_root: {"total": 0, "by_role": {}, "by_status": {}}
        try:
            report = MOD.build_status(
                repo_root=ROOT,
                local_commit_count=100,
                commits_behind_upstream=0,
                loops_since_checkpoint=0,
            )
        finally:
            MOD.summarize_dirty_files = original

        self.assertTrue(report["state"]["checkpoint_due"])
        self.assertTrue(report["state"]["can_checkpoint"])
        self.assertTrue(report["recommendation"]["push_now"])
        self.assertTrue(report["recommendation"]["refresh_broad_github_docs_now"])
        self.assertFalse(report["recommendation"]["keep_broad_github_docs_untouched"])
        self.assertFalse(report["state"]["coordination_reason_required_for_early_push"])
        self.assertIn("local commit threshold met", report["state"]["reasons"][0])

    def test_dirty_worktree_blocks_checkpoint_even_when_threshold_is_met(self) -> None:
        original = MOD.summarize_dirty_files
        MOD.summarize_dirty_files = lambda repo_root: {
            "total": 2,
            "by_role": {"source_code": 2},
            "by_status": {"tracked_modified": 1, "untracked": 1},
        }
        try:
            report = MOD.build_status(
                repo_root=ROOT,
                local_commit_count=100,
                commits_behind_upstream=0,
                loops_since_checkpoint=20,
            )
        finally:
            MOD.summarize_dirty_files = original

        self.assertTrue(report["state"]["checkpoint_due"])
        self.assertTrue(report["state"]["dirty_blocks_checkpoint"])
        self.assertFalse(report["state"]["can_checkpoint"])
        self.assertFalse(report["recommendation"]["push_now"])
        self.assertTrue(report["recommendation"]["keep_broad_github_docs_untouched"])
        self.assertIn("workspace has 2 dirty file(s)", report["state"]["reasons"])
        self.assertIn("Checkpoint only from a clean worktree", report["policy"]["dirty_checkpoint_rule"])

    def test_loop_threshold_allows_checkpoint_even_with_smaller_commit_batch(self) -> None:
        original = MOD.summarize_dirty_files
        MOD.summarize_dirty_files = lambda repo_root: {"total": 0, "by_role": {}, "by_status": {}}
        try:
            report = MOD.build_status(
                repo_root=ROOT,
                local_commit_count=17,
                commits_behind_upstream=0,
                loops_since_checkpoint=20,
            )
        finally:
            MOD.summarize_dirty_files = original

        self.assertTrue(report["state"]["checkpoint_due"])
        self.assertTrue(report["recommendation"]["push_now"])
        self.assertIn("loop threshold met", report["state"]["reasons"][0])

    def test_dirty_summary_is_compact_and_categorized(self) -> None:
        original = MOD.summarize_dirty_files
        MOD.summarize_dirty_files = lambda repo_root: {
            "total": 3,
            "by_role": {"agent_output": 1, "source_code": 2},
            "by_status": {"tracked_modified": 2, "untracked": 1},
            "samples": [
                {
                    "path": "detectors/wave17/example.py",
                    "role": "source_code",
                    "status": "tracked_modified",
                }
            ],
        }
        try:
            report = MOD.build_status(
                repo_root=ROOT,
                local_commit_count=7,
                commits_behind_upstream=1,
                loops_since_checkpoint=4,
            )
        finally:
            MOD.summarize_dirty_files = original

        self.assertEqual(report["state"]["dirty_files"]["total"], 3)
        self.assertEqual(report["state"]["dirty_files"]["by_role"]["source_code"], 2)
        self.assertEqual(report["state"]["dirty_files"]["by_status"]["untracked"], 1)
        self.assertEqual(
            report["state"]["dirty_files"]["samples"][0]["path"],
            "detectors/wave17/example.py",
        )
        self.assertIn("branch is behind upstream: 1 commit(s)", report["state"]["reasons"])
        self.assertIn("workspace has 3 dirty file(s)", report["state"]["reasons"])

    def test_markdown_renders_policy_boundary(self) -> None:
        original = MOD.summarize_dirty_files
        MOD.summarize_dirty_files = lambda repo_root: {
            "total": 2,
            "by_role": {"generated_report": 1, "source_code": 1},
            "by_status": {"tracked_modified": 1, "untracked": 1},
            "samples": [
                {
                    "path": "reports/generated.json",
                    "role": "generated_report",
                    "status": "tracked_modified",
                },
                {
                    "path": "tools/tests/test_row.py",
                    "role": "source_code",
                    "status": "untracked",
                },
            ],
        }
        try:
            report = MOD.build_status(
                repo_root=ROOT,
                local_commit_count=5,
                commits_behind_upstream=3,
                loops_since_checkpoint=1,
            )
        finally:
            MOD.summarize_dirty_files = original

        rendered = MOD.render_markdown(report)

        self.assertIn("# Batch Checkpoint Status", rendered)
        self.assertIn("- Branch divergence: ahead 5, behind 3", rendered)
        self.assertIn("- Dirty files: 2", rendered)
        self.assertIn("- Dirty files block checkpoint: yes", rendered)
        self.assertIn("- Push now: no", rendered)
        self.assertIn("- Coordination reason required for early push: yes", rendered)
        self.assertIn("- Dirty roles: generated_report:1, source_code:1", rendered)
        self.assertIn("- Dirty statuses: tracked_modified:1, untracked:1", rendered)
        self.assertIn("- Dirty samples:", rendered)
        self.assertIn("`reports/generated.json` (generated_report, tracked_modified)", rendered)
        self.assertIn("- Broad GitHub docs refresh now: no", rendered)
        self.assertIn("Broad GitHub Surfaces Deferred Until Checkpoint", rendered)
        self.assertIn("Dirty Checkpoint Rule", rendered)
        self.assertIn("`README.md`", rendered)


if __name__ == "__main__":
    unittest.main()
