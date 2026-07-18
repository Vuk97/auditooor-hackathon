"""Tests for VaultQuery.vault_poc_falsification_context callable (Lane 9, Wave-6).

synthetic_fixture: true

Verifies:
  1. Degraded when neither result_path nor result_json is provided.
  2. Degraded when result_path points to a missing file.
  3. Happy-path with inline result_json returns verdict + key fields.
  4. Happy-path with file-backed result_path works.
  5. commands_run and negative_controls are bounded to safe list lengths.
  6. Envelope carries schema + context_pack_id + context_pack_hash.
  7. CLI dispatch exits 0; callable appears in TOOL_SCHEMAS.
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
    spec = importlib.util.spec_from_file_location("vault_mcp_server_falsification", MODULE_PATH)
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

_FIXTURE_RESULT = {
    "candidate_id": "EQ-001",
    "verdict": "proved",
    "commands_run": ["forge test --match-test test_exploit_path -v"],
    "transcript_paths": [],
    "negative_controls": ["no-attacker-path returns 0"],
    "production_path_checks": ["FinalizeBlock path exercised"],
    "restart_checks": [],
    "multi_validator_checks": [],
    "synthetic_state_status": "none",
    "open_blockers": [],
}

_FIXTURE_DISPROVED = {
    "candidate_id": "EQ-002",
    "verdict": "disproved",
    "commands_run": ["go test ./... -run TestReentrancy"],
    "negative_controls": [],
    "production_path_checks": [],
    "synthetic_state_status": "none",
    "open_blockers": ["guard blocks attacker path at ante decorator"],
}


class TestVaultPocFalsificationContext(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="falsification-ctx-test-")
        self.root = Path(self.tmp.name)
        self.vault = self.root / "obsidian-vault"
        _make_minimal_vault(self.vault)
        self.query = vault_mcp_server.VaultQuery(self.vault, self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_degraded_no_input(self):
        # synthetic_fixture: true
        result = self.query.vault_poc_falsification_context()
        self.assertTrue(result.get("degraded"))
        self.assertEqual(result.get("reason"), "no_result_input")
        self.assertIn("hint", result)

    def test_degraded_missing_file(self):
        # synthetic_fixture: true
        result = self.query.vault_poc_falsification_context(
            result_path="/nonexistent/path/result.json"
        )
        self.assertTrue(result.get("degraded"))
        self.assertEqual(result.get("reason"), "result_path_not_found")

    def test_happy_path_proved(self):
        # synthetic_fixture: true
        result = self.query.vault_poc_falsification_context(result_json=_FIXTURE_RESULT)
        self.assertFalse(result.get("degraded"))
        self.assertEqual(result["verdict"], "proved")
        self.assertEqual(result["candidate_id"], "EQ-001")
        self.assertEqual(result["synthetic_state_status"], "none")
        self.assertIn("forge test", result["commands_run"][0])
        self.assertIn("no-attacker-path returns 0", result["negative_controls"])
        self.assertEqual(result["open_blockers"], [])

    def test_happy_path_disproved(self):
        # synthetic_fixture: true
        result = self.query.vault_poc_falsification_context(result_json=_FIXTURE_DISPROVED)
        self.assertFalse(result.get("degraded"))
        self.assertEqual(result["verdict"], "disproved")
        self.assertEqual(len(result["open_blockers"]), 1)

    def test_happy_path_file(self):
        # synthetic_fixture: true
        result_file = self.root / "falsification_result.json"
        result_file.write_text(json.dumps(_FIXTURE_RESULT, indent=2), encoding="utf-8")
        result = self.query.vault_poc_falsification_context(result_path=str(result_file))
        self.assertFalse(result.get("degraded"))
        self.assertEqual(result["verdict"], "proved")

    def test_commands_bounded(self):
        # synthetic_fixture: true
        data = dict(_FIXTURE_RESULT)
        data["commands_run"] = [f"cmd-{i}" for i in range(20)]
        result = self.query.vault_poc_falsification_context(result_json=data)
        self.assertFalse(result.get("degraded"))
        self.assertLessEqual(len(result["commands_run"]), 10)

    def test_schema_envelope(self):
        # synthetic_fixture: true
        result = self.query.vault_poc_falsification_context(result_json=_FIXTURE_RESULT)
        self.assertEqual(
            result.get("schema"),
            vault_mcp_server.POC_FALSIFICATION_CONTEXT_SCHEMA,
        )
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)

    def test_cli_dispatch_exits_zero(self):
        # synthetic_fixture: true
        proc = subprocess.run(
            [
                sys.executable, str(MODULE_PATH),
                "--repo-root", str(self.root),
                "--vault-dir", str(self.vault),
                "--call", "vault_poc_falsification_context",
                "--args", json.dumps({"result_json": _FIXTURE_RESULT}),
            ],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[:300])
        parsed = json.loads(proc.stdout)
        self.assertFalse(parsed.get("degraded"))
        self.assertEqual(parsed["verdict"], "proved")

    def test_callable_in_tool_schemas(self):
        # synthetic_fixture: true
        names = [t["name"] for t in vault_mcp_server.TOOL_SCHEMAS]
        self.assertIn("vault_poc_falsification_context", names)


if __name__ == "__main__":
    unittest.main()
