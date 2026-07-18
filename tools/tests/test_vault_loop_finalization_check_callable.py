"""Tests for VaultQuery.vault_loop_finalization_check callable.

synthetic_fixture: true

Verifies:
  1. Degraded when manifest_path is absent.
  2. Degrades (or errors gracefully) when manifest_path points to a missing file.
  3. Degraded envelope carries schema + context_pack_id + context_pack_hash.
  4. Callable appears in TOOL_SCHEMAS.
  5. CLI dispatch exits 0 on degraded path.
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
    spec = importlib.util.spec_from_file_location("vault_mcp_server_lfc", MODULE_PATH)
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


class TestVaultLoopFinalizationCheckCallable(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="lfc-ctx-test-")
        self.root = Path(self.tmp.name)
        self.vault = self.root / "obsidian-vault"
        _make_minimal_vault(self.vault)
        self.query = vault_mcp_server.VaultQuery(self.vault, self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_degraded_no_manifest_path(self):
        # synthetic_fixture: true
        result = self.query.vault_loop_finalization_check()
        self.assertTrue(result.get("degraded"))
        self.assertEqual(result.get("reason"), "missing_manifest_path")
        self.assertIn("schema", result)
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)

    def test_degraded_missing_manifest_file(self):
        # synthetic_fixture: true
        result = self.query.vault_loop_finalization_check(
            manifest_path="/nonexistent/path/loop_manifest.json"
        )
        # Either degraded flag or error in reason - both are acceptable graceful degradation
        self.assertIn("schema", result)
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)
        # The result must have either degraded=True or passed field
        has_degraded = result.get("degraded") is True
        has_passed = "passed" in result
        self.assertTrue(has_degraded or has_passed,
                        f"Expected degraded or passed field in result: {result}")

    def test_envelope_fields_present_on_degraded(self):
        # synthetic_fixture: true
        result = self.query.vault_loop_finalization_check()
        self.assertEqual(result.get("schema"), vault_mcp_server.LOOP_FINALIZATION_CHECK_WRAPPER_SCHEMA)
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)
        self.assertIn("generated_at_utc", result)

    def test_callable_in_tool_schemas(self):
        # synthetic_fixture: true
        names = [t["name"] for t in vault_mcp_server.TOOL_SCHEMAS]
        self.assertIn("vault_loop_finalization_check", names)

    def test_cli_dispatch_exits_zero_degraded(self):
        # synthetic_fixture: true - degraded path still exits 0
        proc = subprocess.run(
            [
                sys.executable, str(MODULE_PATH),
                "--repo-root", str(self.root),
                "--vault-dir", str(self.vault),
                "--call", "vault_loop_finalization_check",
                "--args", "{}",
            ],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[:300])
        parsed = json.loads(proc.stdout)
        self.assertTrue(parsed.get("degraded"))
        self.assertEqual(parsed.get("reason"), "missing_manifest_path")

    def test_allow_no_artifact_flag_accepted(self):
        # synthetic_fixture: true - flag is passed through without error
        result = self.query.vault_loop_finalization_check(allow_no_artifact=True)
        # Still degrades because no manifest_path, but accepts the flag
        self.assertTrue(result.get("degraded"))
        self.assertIn("context_pack_id", result)

    def test_manifest_path_passed_for_hacker_question_obligation_gate(self):
        # synthetic_fixture: true
        ws = self.root / "ws"
        draft = ws / "submissions" / "staging" / "hq.md"
        log = ws / "agent_outputs" / "loop_finalization_check_2026-05-14.md"
        obligations = ws / ".auditooor" / "hacker_question_obligations.jsonl"
        manifest_path = ws / ".auditooor" / "finalization" / "current_manifest.json"
        draft.parent.mkdir(parents=True)
        log.parent.mkdir(parents=True)
        obligations.parent.mkdir(parents=True)
        manifest_path.parent.mkdir(parents=True)
        draft.write_text(
            "# Finding\n\nSeverity: Critical\n\nsrc/Vault.sol withdraw is reachable.\n",
            encoding="utf-8",
        )
        log.write_text("ok\n", encoding="utf-8")
        obligations.write_text(
            json.dumps(
                {
                    "schema": "auditooor.hacker_question_obligation.v1",
                    "obligation_id": "hqmcp0000001",
                    "workspace": str(ws),
                    "file": "src/Vault.sol",
                    "function_signature": "function withdraw(uint256 amount) external",
                    "function_name": "withdraw",
                    "attack_class": "reentrancy",
                    "question": "Can withdraw re-enter before accounting is finalized?",
                    "state": "open",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        manifest_path.write_text(
            json.dumps(
                {
                    "changed_artifacts": ["submissions/staging/hq.md"],
                    "workspace_path": str(ws),
                    "handoff_or_ledger_updated": {"paths": ["docs/handoff.md"]},
                    "agent_outputs_collected": {"paths": ["agent_outputs/out.md"]},
                    "tests_or_logs_linked": {
                        "commands": ["echo ok"],
                        "logs": ["agent_outputs/loop_finalization_check_2026-05-14.md"],
                    },
                    "mcp_memory_updated_when_relevant": {"relevant": False},
                }
            )
            + "\n",
            encoding="utf-8",
        )

        result = self.query.vault_loop_finalization_check(manifest_path=str(manifest_path))

        self.assertEqual(result.get("status"), "policy_fail", result)
        self.assertFalse(result.get("passed"))
        gate = result["checks"]["hacker_question_obligations"]
        self.assertEqual(gate["mode"], "blocking_open_obligations")


if __name__ == "__main__":
    unittest.main()
