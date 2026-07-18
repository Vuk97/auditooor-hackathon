"""Focused tests for Phase II capability wrappers in vault-mcp-server."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = load_module()


def make_minimal_vault(vault_dir: Path) -> None:
    vault_dir.mkdir(parents=True, exist_ok=True)
    (vault_dir / "INDEX.md").write_text("# INDEX\n", encoding="utf-8")
    (vault_dir / "INDEX_active.md").write_text("# active\n", encoding="utf-8")
    (vault_dir / "NEXT_LOOP.md").write_text("# NEXT_LOOP\n", encoding="utf-8")


class PhaseIICapabilityCallableTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="phase-ii-mcp-")
        self.root = Path(self.tmp.name)
        self.vault_dir = self.root / "obsidian-vault"
        make_minimal_vault(self.vault_dir)
        self.query = vault_mcp_server.VaultQuery(self.vault_dir, REPO_ROOT)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_defender_narrative_simulator_wraps_inline_text(self) -> None:
        result = self.query.vault_defender_narrative_simulator(
            text="Severity: High. No PoC yet; admin can pause; duplicate prior report.",
            max_narratives=2,
        )

        self.assertEqual(result["schema"], vault_mcp_server.DEFENDER_NARRATIVE_SIMULATOR_CONTEXT_SCHEMA)
        self.assertEqual(result["tool_schema"], "auditooor.defender_narrative_simulator.v1")
        self.assertFalse(result["degraded"])
        self.assertFalse(result["provider_call_made"])
        self.assertEqual(result["submission_posture"], "NOT_SUBMIT_READY")
        self.assertGreaterEqual(len(result["defender_narratives"]), 1)
        self.assertIn("context_pack_hash", result)

    def test_fork_divergence_attack_surface_wraps_inline_manifest(self) -> None:
        manifest = {
            "rows": [
                {
                    "module": "github.com/example/bridge",
                    "fork_repo": "github.com/example/fork",
                    "pin_sha": "abc123",
                    "candidate_security_commits": [
                        {
                            "sha": "def456",
                            "subject": "fix signature replay in bridge proof verifier",
                        }
                    ],
                    "changed_surface": "bridge proof verifier",
                    "reachable_in_scope_code_path": "reachable",
                }
            ]
        }

        result = self.query.vault_fork_divergence_attack_surface(inputs=[manifest], top=1)

        self.assertEqual(result["schema"], vault_mcp_server.FORK_DIVERGENCE_ATTACK_SURFACE_CONTEXT_SCHEMA)
        self.assertEqual(result["tool_schema"], "auditooor.fork_divergence_attack_surface_ranker.v1")
        self.assertFalse(result["degraded"])
        self.assertEqual(result["summary"]["rows"], 1)
        self.assertEqual(result["rows"][0]["priority_band"], "urgent")
        self.assertGreater(result["rows"][0]["priority_score"], 80)

    def test_post_filing_outcome_replay_patterns_wraps_outcome_file(self) -> None:
        outcomes = self.root / "outcomes.jsonl"
        outcomes.write_text(
            json.dumps(
                {
                    "workspace": "synth",
                    "report_id": "S-1",
                    "title": "withdraw rejected",
                    "outcome": "rejected",
                    "rejection_reason": "Missing proof artifact / no runnable PoC.",
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        result = self.query.vault_post_filing_outcome_replay_patterns(outcomes_path=str(outcomes))

        self.assertEqual(result["schema"], vault_mcp_server.POST_FILING_OUTCOME_REPLAY_PATTERN_CONTEXT_SCHEMA)
        self.assertEqual(result["tool_schema"], "auditooor.post_filing_outcome_replay_pattern_distiller.v1")
        self.assertFalse(result["degraded"])
        self.assertGreaterEqual(result["input_summary"]["patterns_emitted"], 1)
        self.assertTrue(result["patterns"])
        self.assertEqual(result["submission_posture"], "NOT_SUBMIT_READY")

    def test_adversarial_hypothesis_differential_wraps_solidity_source(self) -> None:
        source = self.root / "Vault.sol"
        source.write_text(
            textwrap.dedent(
                """\
                pragma solidity ^0.8.20;
                contract Vault {
                    mapping(address => uint256) public balanceOf;
                    function withdraw(uint256 amount) external {
                        require(balanceOf[msg.sender] >= amount, "balance");
                        (bool ok, ) = msg.sender.call{value: amount}("");
                        require(ok);
                        balanceOf[msg.sender] -= amount;
                    }
                }
                """
            ),
            encoding="utf-8",
        )

        result = self.query.vault_adversarial_hypothesis_differential(
            source_path=str(source),
            max_functions=5,
            max_hypotheses_per_function=2,
        )

        self.assertEqual(result["schema"], vault_mcp_server.ADVERSARIAL_HYPOTHESIS_DIFFERENTIAL_CONTEXT_SCHEMA)
        self.assertEqual(result["tool_schema"], "auditooor.adversarial_hypothesis_differential_hunter.v1")
        self.assertFalse(result["degraded"])
        self.assertEqual(result["summary"]["function_count"], 1)
        self.assertTrue(result["hypotheses"])
        self.assertIn("context_pack_id", result)

    def test_tool_schemas_and_cli_dispatch(self) -> None:
        names = {tool["name"] for tool in vault_mcp_server.TOOL_SCHEMAS}
        self.assertIn("vault_defender_narrative_simulator", names)
        self.assertIn("vault_fork_divergence_attack_surface", names)
        self.assertIn("vault_post_filing_outcome_replay_patterns", names)
        self.assertIn("vault_adversarial_hypothesis_differential", names)

        proc = subprocess.run(
            [
                sys.executable,
                str(MODULE_PATH),
                "--repo-root",
                str(REPO_ROOT),
                "--vault-dir",
                str(self.vault_dir),
                "--call",
                "vault_defender_narrative_simulator",
                "--args",
                json.dumps({"text": "Severity: High. No PoC yet.", "max_narratives": 1}),
            ],
            check=False,
            text=True,
            capture_output=True,
        )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema"], vault_mcp_server.DEFENDER_NARRATIVE_SIMULATOR_CONTEXT_SCHEMA)
        self.assertIn("context_pack_id", payload)


if __name__ == "__main__":
    unittest.main()
