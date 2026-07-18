"""Tests for VaultQuery.vault_toolsite_context callable.

synthetic_fixture: true

Verifies:
  1. Callable runs without error with an empty task query.
  2. Task phrase filtering returns relevant workflows.
  3. Envelope carries schema + context_pack_id + context_pack_hash.
  4. Callable appears in TOOL_SCHEMAS.
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_toolsite", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _make_minimal_vault(vault_dir: Path) -> None:
    # synthetic_fixture: true
    vault_dir.mkdir(parents=True, exist_ok=True)
    (vault_dir / "INDEX.md").write_text("# INDEX\n\n- entry\n", encoding="utf-8")
    (vault_dir / "INDEX_active.md").write_text("# active\n- item\n", encoding="utf-8")
    (vault_dir / "NEXT_LOOP.md").write_text("# NEXT_LOOP\n\n## Section\n- item\n", encoding="utf-8")
    goals = vault_dir / "goals"
    goals.mkdir(exist_ok=True)
    (goals / "current.md").write_text("---\nobjective: synth\n---\n# goal\n", encoding="utf-8")


vault_mcp_server = _load_module()


class TestVaultToolsiteContext(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="toolsite-ctx-test-")
        self.root = Path(self.tmp.name)
        self.vault = self.root / "obsidian-vault"
        _make_minimal_vault(self.vault)
        self.query = vault_mcp_server.VaultQuery(self.vault, self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_runs_without_task(self):
        # synthetic_fixture: true
        result = self.query.vault_toolsite_context()
        # Should degrade gracefully (tooling-index script lives in repo, not tmp)
        self.assertIn("schema", result)
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)

    def test_schema_is_correct(self):
        # synthetic_fixture: true
        result = self.query.vault_toolsite_context(task="start audit")
        self.assertEqual(result.get("schema"), vault_mcp_server.TOOLSITE_CONTEXT_SCHEMA)

    def test_task_phrase_returns_workflows_or_degrades(self):
        # synthetic_fixture: true
        # The real repo has the tooling-index script; in tmp it may degrade.
        result = self.query.vault_toolsite_context(task="exploit queue", limit=5)
        self.assertIn("workflows_returned", result)
        self.assertIsInstance(result.get("workflows"), list)

    def test_callable_in_tool_schemas(self):
        # synthetic_fixture: true
        names = [t["name"] for t in vault_mcp_server.TOOL_SCHEMAS]
        self.assertIn("vault_toolsite_context", names)

    def test_real_repo_returns_exploit_queue_workflow(self):
        # synthetic_fixture: true - uses real repo's tooling index
        real_vault = REPO_ROOT / "obsidian-vault"
        if not real_vault.is_dir():
            real_vault = Path.home() / "Documents" / "Codex" / "auditooor" / "obsidian-vault"
        if not real_vault.is_dir():
            self.skipTest("no real vault dir available")
        real_query = vault_mcp_server.VaultQuery(real_vault, REPO_ROOT)
        result = real_query.vault_toolsite_context(task="exploit queue", limit=5)
        wf_ids = [w.get("id") for w in result.get("workflows", [])]
        self.assertIn("exploit-conversion-queue", wf_ids,
                      f"exploit-conversion-queue not found in {wf_ids}")


if __name__ == "__main__":
    unittest.main()
