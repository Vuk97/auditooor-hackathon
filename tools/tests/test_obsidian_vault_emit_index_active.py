from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class ObsidianVaultEmitIndexActiveTests(unittest.TestCase):
    def test_highest_merged_pr_reads_merge_and_squash_commit_messages(self) -> None:
        mod = _load("obsidian_vault_emit_pr_counter", ROOT / "tools" / "obsidian-vault-emit.py")

        def fake_run(*_args, **_kwargs):
            return subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=(
                    "Merge pull request #642 from Vuk97/fix\n"
                    "Harden MCP audit workflow portability\n"
                    "Merged PR #643: MCP/audit workflow portability fixes\n"
                ),
                stderr="",
            )

        with mock.patch.object(mod.subprocess, "run", side_effect=fake_run):
            self.assertEqual(mod._highest_merged_pr_number(), 643)

    def test_index_active_uses_git_pr_count_and_truncates_on_line_boundary(self) -> None:
        mod = _load("obsidian_vault_emit_index_active", ROOT / "tools" / "obsidian-vault-emit.py")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            vault = root / "obsidian-vault"
            docs = root / "docs"
            docs.mkdir()
            (docs / "zzz_state.md").write_text(
                "Older docs mention PR #638, finding #65287, and external PR #15796.\n",
                encoding="utf-8",
            )
            (docs / "AUDITOOOR_CONTROL_PLANE_PLAN.md").write_text(
                "\n".join(
                    [
                        "| Phase | Status | Reach |",
                        "|---|---|---|",
                        "| 1 | done | " + ("x" * 2000) + " |",
                        "## Next",
                    ]
                ),
                encoding="utf-8",
            )
            old_root = mod.REPO_ROOT
            old_inventory = mod.INVENTORY_DIR
            try:
                mod.REPO_ROOT = root
                mod.INVENTORY_DIR = root / "missing-inventory"
                with mock.patch.object(mod, "_highest_merged_pr_number", return_value=642):
                    count = mod.emit_index_active(vault, dry_run=False)
            finally:
                mod.REPO_ROOT = old_root
                mod.INVENTORY_DIR = old_inventory

            text = (vault / "INDEX_active.md").read_text(encoding="utf-8")

        self.assertEqual(count, 1)
        self.assertIn("| Highest merged PR | #642 |", text)
        self.assertNotIn("#65287", text)
        self.assertNotIn("#15796", text)
        self.assertIn("_(truncated)_", text)
        self.assertNotIn("`docs", text)


if __name__ == "__main__":
    unittest.main()
