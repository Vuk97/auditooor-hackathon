from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class ObsidianVaultEmitGoalsTests(unittest.TestCase):
    def test_emit_goals_writes_current_perpetual_goal_note(self) -> None:
        mod = _load("obsidian_vault_emit_goals", ROOT / "tools" / "obsidian-vault-emit.py")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            vault = root / "obsidian-vault"
            (root / "docs").mkdir()
            (root / "reports").mkdir()
            (root / "reports" / "goal_loop_status_2026-05-05.json").write_text(
                json.dumps(
                    {
                        "goal_policy": {
                            "status": "active_continuous_loop",
                            "terminal_completion_allowed": False,
                            "loop_back_phase": "recall_memory",
                        },
                        "next_operational_rule": "Use memory first, verify locally, write back memory, and loop.",
                    }
                ),
                encoding="utf-8",
            )
            (root / "docs" / "GOAL_LOOP_STATUS_2026-05-05.md").write_text(
                "# Goal Loop Status\n\nTerminal completion allowed: `False`\n",
                encoding="utf-8",
            )

            old_root = mod.REPO_ROOT
            try:
                mod.REPO_ROOT = root
                count = mod.emit_goals(vault, dry_run=False)
            finally:
                mod.REPO_ROOT = old_root

            note = vault / "goals" / "current.md"
            text = note.read_text(encoding="utf-8")

        self.assertEqual(count, 1)
        self.assertIn('status: "active_continuous_loop"', text)
        self.assertIn('terminal_condition: "never"', text)
        self.assertIn('loop: "perpetual"', text)
        self.assertIn("Use memory first, verify locally", text)


if __name__ == "__main__":
    unittest.main()
