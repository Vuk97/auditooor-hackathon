"""Tests for VaultQuery.vault_resume_context callable (W3.8 coverage push).

synthetic_fixture: true

Verifies:
  1. Happy path with minimal vault returns context_pack envelope.
  2. workspace_path kwarg accepted without crash.
  3. paths=[] (empty list) does not crash.
  4. Schema constant matches CONTEXT_PACK_SCHEMA.
  5. CLI dispatch exits 0 and returns valid JSON.
  6. callable appears in TOOL_SCHEMAS list.
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


class TestVaultResumeContext(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="w38-resume-")
        self.root = Path(self.tmp.name)
        self.vault = self.root / "obsidian-vault"
        _make_minimal_vault(self.vault)
        self.query = vault_mcp_server.VaultQuery(self.vault, self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_happy_path_envelope(self):
        # synthetic_fixture: true
        result = self.query.vault_resume_context()
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)
        self.assertEqual(result.get("schema"), vault_mcp_server.CONTEXT_PACK_SCHEMA)
        self.assertEqual(result.get("kind"), "resume")

    def test_workspace_path_kwarg_ok(self):
        # synthetic_fixture: true
        ws = self.root / "ws"
        ws.mkdir()
        result = self.query.vault_resume_context(workspace_path=str(ws))
        self.assertIn("context_pack_id", result)

    def test_empty_paths_list_ok(self):
        # synthetic_fixture: true
        result = self.query.vault_resume_context(paths=[])
        self.assertEqual(result.get("kind"), "resume")

    def test_schema_constant_matches(self):
        # synthetic_fixture: true
        result = self.query.vault_resume_context()
        self.assertEqual(result["schema"], "auditooor.vault_context_pack.v1")

    def test_cli_dispatch_ok(self):
        # synthetic_fixture: true
        proc = subprocess.run(
            [sys.executable, str(MODULE_PATH), "--repo-root", str(self.root),
             "--vault-dir", str(self.vault), "--call", "vault_resume_context",
             "--args", "{}"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[:300])
        parsed = json.loads(proc.stdout)
        self.assertIn("context_pack_id", parsed)

    def test_in_tool_schemas(self):
        # synthetic_fixture: true
        names = [t["name"] for t in vault_mcp_server.TOOL_SCHEMAS]
        self.assertIn("vault_resume_context", names)


if __name__ == "__main__":
    unittest.main()
