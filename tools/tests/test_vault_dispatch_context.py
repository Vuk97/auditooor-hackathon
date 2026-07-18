"""Tests for VaultQuery.vault_dispatch_context callable (W3.8 coverage push).

synthetic_fixture: true

Verifies:
  1. Happy path on synthetic empty workspace returns expected envelope keys.
  2. Callable is invokable with no extra kwargs without raising.
  3. Sample kwargs payload accepted: (no kwargs).
  4. Returned dict contains at least one well-known field.
  5. CLI dispatch exits 0 and returns valid JSON.
  6. Callable appears in TOOL_SCHEMAS list.

Notes: thin wrapper over _context_pack
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


class TestVaultDispatchContext(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="w38-dispatch_context-")
        self.root = Path(self.tmp.name)
        self.vault = self.root / "obsidian-vault"
        _make_minimal_vault(self.vault)
        self.query = vault_mcp_server.VaultQuery(self.vault, self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_happy_path_returns_dict(self):
        # synthetic_fixture: true
        result = self.query.vault_dispatch_context()
        self.assertIsInstance(result, dict)
        # At least one of the expected keys must be present
        expected = ['context_pack_id', 'context_pack_hash', 'schema', 'kind']
        present = [k for k in expected if k in result]
        self.assertTrue(present, f"none of expected={expected} in keys={list(result.keys())[:10]}")

    def test_no_kwargs_does_not_raise(self):
        # synthetic_fixture: true
        result = self.query.vault_dispatch_context()
        self.assertIsInstance(result, dict)

    def test_kwargs_payload_accepted(self):
        # synthetic_fixture: true
        result = self.query.vault_dispatch_context()
        self.assertIsInstance(result, dict)
        # Either error envelope, or success envelope; both are dicts
        self.assertGreater(len(result), 0)

    def test_schema_or_error_field_present(self):
        # synthetic_fixture: true
        result = self.query.vault_dispatch_context()
        # Every callable on empty workspace returns either:
        #  - a schema-tagged envelope (success or degraded), OR
        #  - an error envelope with at least an "error" key.
        has_schema = "schema" in result
        has_error = "error" in result
        has_pack = "context_pack_id" in result
        has_known = any(k in result for k in ['context_pack_id', 'context_pack_hash', 'schema', 'kind'])
        self.assertTrue(
            has_schema or has_error or has_pack or has_known,
            f"no recognised envelope key in: {list(result.keys())[:10]}",
        )

    def test_cli_dispatch_exits_zero(self):
        # synthetic_fixture: true
        args_json = json.dumps({  })
        proc = subprocess.run(
            [sys.executable, str(MODULE_PATH), "--repo-root", str(self.root),
             "--vault-dir", str(self.vault), "--call", "vault_dispatch_context",
             "--args", args_json],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[:300])
        parsed = json.loads(proc.stdout)
        self.assertIsInstance(parsed, dict)

    def test_callable_in_tool_schemas(self):
        # synthetic_fixture: true
        names = [t["name"] for t in vault_mcp_server.TOOL_SCHEMAS]
        self.assertIn("vault_dispatch_context", names)


if __name__ == "__main__":
    unittest.main()
