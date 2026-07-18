import importlib.util
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]


def load_tool(name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(name, REPO / relative_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


synth = load_tool("live_check_spec_synthesizer_under_test", "tools/live-check-spec-synthesizer.py")
runner = load_tool("live_check_runner_under_test", "tools/live-check-runner.py")


class LiveTopologyHeuristicProvenanceTests(unittest.TestCase):
    def test_generated_relation_checks_record_heuristic_provenance(self) -> None:
        checks = synth.generate_relation_checks(
            angles=[
                {
                    "id": "A-AUTH",
                    "contracts": ["VaultAdapter", "RiskManager"],
                    "title": "risk manager wiring controls adapter",
                }
            ],
            topology={
                "VaultAdapter": {
                    "status": "resolved",
                    "resolved_address": "0x1111111111111111111111111111111111111111",
                    "candidate_addresses": [],
                },
                "RiskManager": {
                    "status": "ambiguous",
                    "candidate_addresses": [
                        "0x2222222222222222222222222222222222222222",
                        "0x3333333333333333333333333333333333333333",
                    ],
                },
            },
            default_network="mainnet",
            contract_getters={"VaultAdapter": {"riskManager"}, "RiskManager": set()},
            contract_text={"VaultAdapter": "contract VaultAdapter { RiskManager public riskManager; }"},
            seed_checks=[],
        )

        self.assertEqual(len(checks), 1)
        provenance = checks[0].get("heuristic_provenance")
        self.assertIsInstance(provenance, dict)
        self.assertEqual(provenance["confidence"], "heuristic")
        self.assertEqual(provenance["source_contract"], "VaultAdapter")
        self.assertEqual(provenance["target_contract"], "RiskManager")
        self.assertEqual(provenance["getter"], "riskManager")
        self.assertIn("manager", provenance["signals"]["meaningful_token_overlap"])
        self.assertIn("risk", provenance["signals"]["meaningful_token_overlap"])
        self.assertTrue(provenance["signals"]["source_mentions_target_type"])
        self.assertTrue(provenance["signals"]["source_topology"]["has_resolved_address"])
        self.assertEqual(provenance["signals"]["target_topology"]["candidate_count"], 2)
        self.assertIn("not semantic graph proof", " ".join(provenance["limitations"]))

        summary = synth.summarize(checks)
        self.assertEqual(summary["generated_relation"], 1)
        self.assertEqual(summary["generated_with_heuristic_provenance"], 1)

    def test_generated_relation_provenance_cites_semantic_graph_edges(self) -> None:
        checks = synth.generate_relation_checks(
            angles=[
                {
                    "id": "A-AUTH",
                    "contracts": ["VaultAdapter", "RiskManager"],
                    "title": "risk manager wiring controls adapter",
                }
            ],
            topology={
                "VaultAdapter": {
                    "status": "resolved",
                    "resolved_address": "0x1111111111111111111111111111111111111111",
                    "candidate_addresses": [],
                },
                "RiskManager": {
                    "status": "resolved",
                    "resolved_address": "0x2222222222222222222222222222222222222222",
                    "candidate_addresses": [],
                },
            },
            default_network="mainnet",
            contract_getters={"VaultAdapter": {"riskManager"}, "RiskManager": set()},
            contract_text={"VaultAdapter": "contract VaultAdapter { RiskManager public riskManager; }"},
            seed_checks=[],
            semantic_graph={
                "schema_version": "auditooor.semantic_graph.v1",
                "relation_edges": [
                    {
                        "kind": "registry-write",
                        "source_contract": "VaultAdapter",
                        "source_function": "configureRiskManager",
                        "target": "riskManager",
                        "method": "setRiskManager",
                        "file": "src/VaultAdapter.sol",
                        "line": 42,
                        "confidence": "source-shape",
                    }
                ],
            },
        )

        provenance = checks[0]["heuristic_provenance"]
        semantic_edges = provenance["signals"]["semantic_graph_relation_edges"]
        self.assertEqual(provenance["confidence"], "source-shape")
        self.assertEqual(len(semantic_edges), 1)
        self.assertEqual(semantic_edges[0]["source_function"], "configureRiskManager")
        self.assertIn("compiler dataflow proof", " ".join(provenance["limitations"]))

    def test_runner_preserves_heuristic_provenance_for_blocked_rows(self) -> None:
        provenance = {
            "kind": "generated-relation-heuristic",
            "confidence": "heuristic",
            "source_contract": "VaultAdapter",
            "target_contract": "VaultFactory",
            "getter": "vaultFactory",
            "signals": {
                "source_mentions_target_type": True,
                "meaningful_token_overlap": ["factory", "vault"],
                "semantic_graph_relation_edges": [
                    {
                        "kind": "registry-write",
                        "source_function": "setFactory",
                        "target": "vaultFactory",
                    }
                ],
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            result = runner.run_single_check(
                ws,
                {
                    "id": "gen-a-auth-vaultadapter-vaultfactory",
                    "title": "VaultAdapter.vaultFactory should resolve to VaultFactory",
                    "contract": "VaultAdapter",
                    "address_ref": "VaultAdapter",
                    "network": "mainnet",
                    "call": "vaultFactory()(address)",
                    "expect_ref": "VaultFactory",
                    "evidence_class": "topology-relation",
                    "related_angle_ids": ["A-AUTH"],
                    "spec_source": "generated-relation",
                    "generated": True,
                    "heuristic_provenance": provenance,
                },
                topology={},
                workspace_env={},
                force_dry_run=True,
                allow_public_rpc=False,
            )

        self.assertEqual(result["status"], "blocked_unresolved_address")
        self.assertEqual(result["heuristic_provenance"], provenance)

        artifact = {
            "workspace": str(ws),
            "spec": "spec.json",
            "generated_at": "2026-04-28T00:00:00Z",
            "summary": runner.summarize([result]),
            "results": [result],
            "manual_imports": {},
            "proof_pairs": [],
            "proof_pair_summary": {},
            "proof_contradictions": [],
        }
        markdown = runner.render_markdown(ws, artifact)
        self.assertIn("Heuristic provenance", markdown)
        self.assertIn("VaultAdapter.vaultFactory -> VaultFactory", markdown)
        self.assertIn("Getter/target token overlap", markdown)
        self.assertIn("Semantic graph relation edges", markdown)


if __name__ == "__main__":
    unittest.main()
