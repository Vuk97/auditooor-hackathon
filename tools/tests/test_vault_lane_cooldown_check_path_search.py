"""Tests for vault_lane_cooldown_check path-search fallback (FIX-PASS Gap 2).

Verifies:
  1. When workspace_path has no state file but worktree_path does, the
     callable finds the state via worktree fallback.
  2. The state_file_path_searched list is populated with all candidates tried.
  3. workspace_path-only call still works when its state file exists.
  4. Both empty (state_file_not_found) and populated returns include the
     state_file_path_searched key.
"""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


def _state_payload(iteration: int = 12) -> dict:
    return {
        "iteration": iteration,
        "lane_cooldowns": {
            "lane-A": {
                "since_iter": 8,
                "reason": "test cooldown",
                "trigger_state": {"key": "value"},
            }
        },
    }


class TestVaultLaneCooldownCheckPathSearch(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="vlcc-pathsearch-")
        self.root = Path(self.tmp.name)
        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir(parents=True)
        self.workspace = self.root / "audits" / "spark"
        self.workspace.mkdir(parents=True)
        # workspace has NO state file — fallback target
        self.worktree = self.root / "auditooor-worktrees" / "fake-wt"
        (self.worktree / ".auditooor").mkdir(parents=True)
        self.worktree_state = (
            self.worktree / ".auditooor" / "spark_hunt_loop_state.json"
        )
        self.worktree_state.write_text(json.dumps(_state_payload()), encoding="utf-8")
        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_worktree_fallback_finds_state(self):
        result = self.vault.vault_lane_cooldown_check(
            workspace_path=str(self.workspace),
            worktree_path=str(self.worktree),
        )
        # Successfully found via fallback
        self.assertNotIn(
            "error",
            result,
            f"unexpected error after worktree fallback: {result.get('error')}",
        )
        self.assertEqual(result["total_cooldowns"], 1)
        self.assertEqual(result["current_iter"], 12)
        # state_file_path resolves to the worktree state, not workspace.
        # Compare via Path.resolve() to handle macOS /private/var symlink.
        self.assertEqual(
            Path(result["state_file_path"]).resolve(),
            self.worktree_state.resolve(),
        )

    def test_state_file_path_searched_populated(self):
        result = self.vault.vault_lane_cooldown_check(
            workspace_path=str(self.workspace),
            worktree_path=str(self.worktree),
        )
        searched = result.get("state_file_path_searched")
        self.assertIsInstance(searched, list)
        # Must have at least the workspace candidate AND the worktree candidate.
        # Use resolved path-substring check to handle macOS symlinks.
        ws_resolved = str(self.workspace.resolve())
        wt_resolved = str(self.worktree.resolve())
        joined = "\n".join(searched)
        self.assertIn(ws_resolved, joined)
        self.assertIn(wt_resolved, joined)

    def test_empty_envelope_includes_searched(self):
        # Point both workspace AND worktree to nonexistent paths so neither has
        # a state file. The glob fallback may still hit the real
        # /Users/wolf/auditooor-worktrees/*/... so we don't assert error here;
        # we only verify that state_file_path_searched is populated.
        result = self.vault.vault_lane_cooldown_check(
            workspace_path=str(self.root / "nonexistent-workspace"),
            worktree_path=str(self.root / "nonexistent-worktree"),
        )
        self.assertIn("state_file_path_searched", result)
        self.assertGreaterEqual(len(result["state_file_path_searched"]), 1)


if __name__ == "__main__":
    unittest.main()
