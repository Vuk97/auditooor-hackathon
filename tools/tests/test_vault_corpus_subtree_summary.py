"""Tests for VaultQuery.vault_corpus_subtree_summary callable (W3.8 coverage push).

synthetic_fixture: true

Verifies:
  1. Happy path on synthetic empty corpus returns degraded envelope.
  2. Empty subtree filter accepted.
  3. top_n kwarg accepted.
  4. Returned dict contains schema + context_pack_id.
  5. CLI dispatch exits 0 and returns valid JSON.
  6. Callable appears in TOOL_SCHEMAS list.

Notes: All in-process and CLI calls pass a synthetic empty `tags_dir` so the
production corpus tree (audit/corpus_tags/tags/ with 41k+ records) is NOT
walked. This keeps each test hermetic and well under any sensible timeout.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server", MODULE_PATH)
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


class TestVaultCorpusSubtreeSummary(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="w38-corpus_subtree_summary-")
        self.root = Path(self.tmp.name)
        self.vault = self.root / "obsidian-vault"
        _make_minimal_vault(self.vault)
        self.query = vault_mcp_server.VaultQuery(self.vault, self.root)
        # synthetic_fixture: true - empty tags_dir so we never walk the
        # production corpus from the worktree.
        self.synth_tags = self.root / "synth_corpus_tags" / "tags"
        self.synth_tags.mkdir(parents=True, exist_ok=True)
        self.synth_exemptions = self.root / "synth_corpus_tags" / "acceptance_exemptions.yaml"
        self.synth_exemptions.write_text("# synthetic empty exemptions\n", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def _kwargs(self, **extra):
        base = {
            "tags_dir": str(self.synth_tags),
            "exemptions_path": str(self.synth_exemptions),
        }
        base.update(extra)
        return base

    def test_happy_path_returns_dict(self):
        # synthetic_fixture: true
        result = self.query.vault_corpus_subtree_summary(**self._kwargs())
        self.assertIsInstance(result, dict)
        expected = ['schema', 'context_pack_id', 'context_pack_hash']
        present = [k for k in expected if k in result]
        self.assertTrue(present, f"none of expected={expected} in keys={list(result.keys())[:10]}")

    def test_subtree_filter_kwarg_accepted(self):
        # synthetic_fixture: true
        result = self.query.vault_corpus_subtree_summary(**self._kwargs(subtree="nonexistent_subtree"))
        self.assertIsInstance(result, dict)

    def test_top_n_kwarg_accepted(self):
        # synthetic_fixture: true
        result = self.query.vault_corpus_subtree_summary(**self._kwargs(top_n=10))
        self.assertIsInstance(result, dict)
        self.assertEqual(result.get("top_n"), 10)

    def test_schema_envelope_present(self):
        # synthetic_fixture: true
        result = self.query.vault_corpus_subtree_summary(**self._kwargs())
        self.assertEqual(result.get("schema"), vault_mcp_server.CORPUS_SUBTREE_SUMMARY_SCHEMA)
        self.assertIn("context_pack_id", result)

    def test_cli_dispatch_exits_zero(self):
        # synthetic_fixture: true
        args_json = json.dumps(self._kwargs())
        proc = subprocess.run(
            [sys.executable, str(MODULE_PATH), "--repo-root", str(self.root),
             "--vault-dir", str(self.vault), "--call", "vault_corpus_subtree_summary",
             "--args", args_json],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[:300])
        parsed = json.loads(proc.stdout)
        self.assertIsInstance(parsed, dict)

    def test_callable_in_tool_schemas(self):
        # synthetic_fixture: true
        names = [t["name"] for t in vault_mcp_server.TOOL_SCHEMAS]
        self.assertIn("vault_corpus_subtree_summary", names)


if __name__ == "__main__":
    unittest.main()
