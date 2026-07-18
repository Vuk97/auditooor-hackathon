from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"
EXPECTED_SCHEMA = "auditooor.vault_chained_attack_plan_context.v1"


def _load_vault_mcp():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_chained_attack_plan", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _plan(idx: int, workspace: Path) -> dict:
    source_file = workspace / "src" / f"Vault{idx}.sol"
    return {
        "chain_id": f"CHAIN-{idx:03d}",
        "status": "candidate_not_submit_ready",
        "score": 100 - idx,
        "title": f"candidate chain {idx}",
        "composition_rationale": "shared source refs need proof before any submission posture can change",
        "primitives": [
            {
                "primitive_id": f"angle:{idx}",
                "source_kind": "exploit_angle",
                "source_refs": [str(source_file) + ":42", f"workspace:src/Vault{idx}.sol:42"],
            }
        ],
        "chain_steps": [
            {
                "step_id": f"step-{idx}",
                "source_kind": "detector_cluster",
                "advisory_only": True,
                "source_refs": [str(source_file) + ":42"],
            }
        ],
        "shared_evidence": [f"shared_files:{source_file}:42"],
        "source_refs": [str(source_file) + ":42", f"workspace:src/Vault{idx}.sol:42"],
        "proof_steps": ["confirm file:line exploitability"],
        "blockers": ["pre-submit gate has not passed"],
    }


class VaultChainedAttackPlanContextTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="vault-chained-plan-context-")
        self.base = Path(self.tmp.name)
        self.vault_dir = self.base / "vault"
        self.repo = self.base / "repo"
        self.ws = self.base / "workspace"
        self.vault_dir.mkdir()
        self.repo.mkdir()
        self.ws.mkdir()
        self.vault_mcp = _load_vault_mcp()
        self.vault = self.vault_mcp.VaultQuery(self.vault_dir, repo_root=self.repo)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_reads_bounded_advisory_plans_and_scrubs_local_paths(self) -> None:
        _write_json(
            self.ws / "swarm" / "chained_attack_plans.json",
            {
                "schema_version": "auditooor.chained_attack_plans.v1",
                "workspace": "<workspace>",
                "advisory_only": True,
                "submission_posture": "candidate_not_submit_ready",
                "summary": {"plan_count": 5, "max_plans": 5},
                "plans": [_plan(idx, self.ws) for idx in range(1, 6)],
                "source_refs": [str(self.ws / "swarm" / "chained_attack_plans.json")],
            },
        )

        self.assertTrue(
            hasattr(self.vault, "vault_chained_attack_plan_context"),
            "VaultQuery must expose vault_chained_attack_plan_context",
        )
        result = self.vault.vault_chained_attack_plan_context(
            workspace_path=str(self.ws),
            max_plans=2,
        )

        self.assertEqual(result["schema"], EXPECTED_SCHEMA)
        self.assertEqual(result["kind"], "chained_attack_plan_context")
        self.assertFalse(result["degraded"], result.get("degraded_reason"))
        self.assertTrue(result["advisory_only"])
        self.assertEqual(result["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(len(result["plans"]), 2)
        self.assertLessEqual(len(result["plans"]), result["limits"]["max_plans"])
        self.assertEqual(result["summary"]["plan_count"], 2)
        self.assertGreaterEqual(result["summary"]["total_plans_available"], 5)
        self.assertTrue(result["context_pack_id"].startswith(EXPECTED_SCHEMA))
        self.assertTrue(result["privacy_guards"]["workspace_relative_refs_only"])
        self.assertTrue(result["privacy_guards"]["absolute_local_paths_blocked"])

        payload = json.dumps(result, sort_keys=True)
        self.assertNotIn(str(self.base), payload)
        self.assertNotIn("/private/", payload)
        self.assertNotIn("/Users/", payload)
        self.assertNotEqual(result["submission_posture"], "SUBMIT_READY")

    def test_missing_workspace_or_plan_file_returns_valid_empty_envelope(self) -> None:
        self.assertTrue(
            hasattr(self.vault, "vault_chained_attack_plan_context"),
            "VaultQuery must expose vault_chained_attack_plan_context",
        )

        missing_workspace = self.vault.vault_chained_attack_plan_context(
            workspace_path=str(self.base / "missing-workspace"),
        )
        self.assertEqual(missing_workspace["schema"], EXPECTED_SCHEMA)
        self.assertTrue(missing_workspace["degraded"])
        self.assertTrue(missing_workspace["advisory_only"])
        self.assertEqual(missing_workspace["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(missing_workspace["plans"], [])
        self.assertNotIn(str(self.base), json.dumps(missing_workspace, sort_keys=True))

        missing_file = self.vault.vault_chained_attack_plan_context(workspace_path=str(self.ws))
        self.assertEqual(missing_file["schema"], EXPECTED_SCHEMA)
        self.assertTrue(missing_file["advisory_only"])
        self.assertEqual(missing_file["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(missing_file["plans"], [])
        self.assertIn(missing_file["degraded"], (True, False))
        self.assertNotIn(str(self.base), json.dumps(missing_file, sort_keys=True))

    def test_tools_list_and_call_register_chained_attack_plan_context(self) -> None:
        listed = self.vault_mcp.handle_request(
            self.vault,
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        by_name = {tool["name"]: tool for tool in listed["result"]["tools"]}
        self.assertIn("vault_chained_attack_plan_context", by_name)
        props = by_name["vault_chained_attack_plan_context"]["inputSchema"]["properties"]
        self.assertIn("workspace_path", props)
        self.assertIn("max_plans", props)

        response = self.vault_mcp.handle_request(
            self.vault,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "vault_chained_attack_plan_context",
                    "arguments": {"workspace_path": str(self.ws), "max_plans": 1},
                },
            },
        )
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(payload["schema"], EXPECTED_SCHEMA)
        self.assertTrue(payload["advisory_only"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")


if __name__ == "__main__":
    unittest.main()
