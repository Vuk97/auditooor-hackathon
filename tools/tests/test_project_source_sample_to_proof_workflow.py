from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _import_tool(filename: str, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, str(ROOT / "tools" / filename))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _impact_units(candidate: str, family: str = "asset_custody") -> dict[str, object]:
    return {
        "units": [
            {
                "candidate_id": candidate,
                "impact_contract_id": f"impact-contract-{candidate}",
                "route_family": family,
                "tier": "Critical",
                "requirement": "candidate_bound_project_source_citation",
                "blocker_class": "candidate_bound_project_source_citation_missing",
            },
            {
                "candidate_id": candidate,
                "impact_contract_id": f"impact-contract-{candidate}",
                "route_family": family,
                "tier": "Critical",
                "requirement": "project_specific_harness_execution",
                "blocker_class": "project_specific_harness_execution_missing",
                "local_artifact_status": {"missing_requirements": ["target_project_binding"]},
            },
            {
                "candidate_id": candidate,
                "impact_contract_id": f"impact-contract-{candidate}",
                "route_family": family,
                "tier": "Critical",
                "requirement": "proved_exploit_impact_execution_manifest",
                "blocker_class": "proved_exploit_impact_execution_manifest_missing",
                "next_command": f"make poc-execution-record CANDIDATE_ID={candidate}",
            },
        ]
    }


class ProjectSourceSampleToProofWorkflowTests(unittest.TestCase):
    def test_declared_source_root_line_hits_plus_all_proof_inputs_becomes_execution_proof_ready(self) -> None:
        declaration_mod = _import_tool("project-source-root-declaration.py", "project_source_root_declaration_e2e")
        readiness_mod = _import_tool("project-source-root-readiness.py", "project_source_root_readiness_e2e")
        discovery_mod = _import_tool("impact-binding-source-harness-discovery.py", "impact_binding_discovery_e2e")
        source_import_mod = _import_tool("impact-binding-source-import-readiness.py", "impact_source_import_e2e")
        proof_mod = _import_tool("execution-manifest-proof-readiness.py", "execution_proof_readiness_e2e")

        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-critical-asset-custody-42"
            source_root = ws / "target_project" / "src"
            source_root.mkdir(parents=True)
            (source_root / "Vault.sol").write_text(
                "\n".join(
                    [
                        "contract Vault {",
                        "  function withdraw(uint256 amount) external {",
                        "    // asset custody transfer path",
                        "  }",
                        "}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            manifest = ws / ".auditooor" / "project_source_roots.json"
            readiness_path = ws / ".auditooor" / "project_source_root_readiness.json"
            discovery_path = ws / ".auditooor" / "impact_binding_source_harness_discovery.json"
            source_import_path = ws / ".auditooor" / "impact_binding_source_import_readiness.json"
            _write_json(input_path, _impact_units(candidate))
            _write_json(ws / ".auditooor" / "semantic_graph.json", {"contracts": []})

            declaration_payload = declaration_mod.build_payload(
                manifest,
                ["target=target_project/src"],
                merge_existing=False,
            )
            _write_json(manifest, declaration_payload)
            readiness_payload = readiness_mod.build_payload(ws, manifest_path=manifest)
            _write_json(readiness_path, readiness_payload)
            discovery_payload = discovery_mod.build_payload(
                ws,
                input_path=input_path,
                project_source_readiness_path=readiness_path,
            )
            _write_json(discovery_path, discovery_payload)
            source_import_payload = source_import_mod.build_payload(
                ws,
                discovery_path=discovery_path,
                readiness_path=readiness_path,
            )
            _write_json(source_import_path, source_import_payload)

            ready_discovery_rows = []
            for row in discovery_payload["reductions"]:
                ready_discovery_rows.append(
                    {
                        **row,
                        "discovery_status": "project_source_and_harness_ready",
                        "candidate_bound_project_source_citation": "target_project/src/Vault.sol:2",
                        "project_harness_binding": f"poc-tests/{candidate}/run_harness.sh",
                    }
                )
            _write_json(discovery_path, {**discovery_payload, "reductions": ready_discovery_rows})
            _write_json(
                ws / "poc_execution" / candidate / "execution_manifest.json",
                {
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": [
                        {
                            "command": "forge test --match-test testExploitImpact",
                            "status": "pass",
                            "exit_code": 0,
                        }
                    ],
                },
            )

            proof_payload = proof_mod.build_payload(ws, input_path=input_path, bundle_dir=ws / ".auditooor" / "proof_units")

        self.assertEqual(readiness_payload["ready_root_count"], 1)
        self.assertEqual(discovery_payload["candidate_source_hint_unit_count"], 2)
        self.assertEqual(source_import_payload["line_hit_unit_count"], 2)
        self.assertEqual(proof_payload["proof_ready_count"], 1)
        row = proof_payload["rows"][0]
        self.assertEqual(row["readiness_status"], "execution_proof_ready")
        self.assertEqual(row["source_import_status"]["status"], "source_import_line_hits_ready")
        self.assertEqual(row["source_harness_status"]["status"], "source_harness_binding_ready")
        self.assertEqual(row["manifest_status"]["status"], "proved_exploit_impact_manifest_present")
        self.assertEqual(row["missing_inputs"], [])
        self.assertFalse(proof_payload["promotion_allowed"])

    def test_line_hits_without_exact_binding_or_exploit_manifest_do_not_become_proof_ready(self) -> None:
        declaration_mod = _import_tool("project-source-root-declaration.py", "project_source_root_declaration_e2e_neg")
        readiness_mod = _import_tool("project-source-root-readiness.py", "project_source_root_readiness_e2e_neg")
        discovery_mod = _import_tool("impact-binding-source-harness-discovery.py", "impact_binding_discovery_e2e_neg")
        source_import_mod = _import_tool("impact-binding-source-import-readiness.py", "impact_source_import_e2e_neg")
        proof_mod = _import_tool("execution-manifest-proof-readiness.py", "execution_proof_readiness_e2e_neg")

        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-critical-asset-custody-43"
            source_root = ws / "target_project" / "src"
            source_root.mkdir(parents=True)
            (source_root / "Vault.sol").write_text(
                "contract Vault { function withdraw(uint256 amount) external {} }\n",
                encoding="utf-8",
            )
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            manifest = ws / ".auditooor" / "project_source_roots.json"
            readiness_path = ws / ".auditooor" / "project_source_root_readiness.json"
            discovery_path = ws / ".auditooor" / "impact_binding_source_harness_discovery.json"
            source_import_path = ws / ".auditooor" / "impact_binding_source_import_readiness.json"
            _write_json(input_path, _impact_units(candidate))
            _write_json(ws / ".auditooor" / "semantic_graph.json", {"contracts": []})

            _write_json(
                manifest,
                declaration_mod.build_payload(manifest, ["target=target_project/src"], merge_existing=False),
            )
            readiness_payload = readiness_mod.build_payload(ws, manifest_path=manifest)
            _write_json(readiness_path, readiness_payload)
            discovery_payload = discovery_mod.build_payload(
                ws,
                input_path=input_path,
                project_source_readiness_path=readiness_path,
            )
            _write_json(discovery_path, discovery_payload)
            source_import_payload = source_import_mod.build_payload(
                ws,
                discovery_path=discovery_path,
                readiness_path=readiness_path,
            )
            _write_json(source_import_path, source_import_payload)
            _write_json(
                ws / "poc_execution" / candidate / "execution_manifest.json",
                {
                    "final_result": "proved",
                    "impact_assertion": "not_demonstrated",
                    "commands_attempted": ["forge test"],
                },
            )

            proof_payload = proof_mod.build_payload(ws, input_path=input_path)

        self.assertEqual(readiness_payload["ready_root_count"], 1)
        self.assertEqual(source_import_payload["line_hit_unit_count"], 2)
        self.assertEqual(proof_payload["proof_ready_count"], 0)
        row = proof_payload["rows"][0]
        self.assertEqual(row["source_import_status"]["status"], "source_import_line_hits_ready")
        self.assertEqual(row["source_harness_status"]["status"], "source_or_harness_hints_require_manual_binding")
        self.assertEqual(row["manifest_status"]["status"], "terminal_execution_manifest_not_proved")
        self.assertIn("candidate_bound_project_source_citation", row["missing_inputs"])
        self.assertIn("project_harness_binding", row["missing_inputs"])
        self.assertIn("impact_assertion_exploit_impact", row["missing_inputs"])


if __name__ == "__main__":
    unittest.main()
