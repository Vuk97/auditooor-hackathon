from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "impact-binding-source-harness-discovery.py"


def _import():
    spec = importlib.util.spec_from_file_location("impact_binding_source_harness_discovery_test", str(TOOL))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


class ImpactBindingSourceHarnessDiscoveryTests(unittest.TestCase):
    def test_terminalizes_source_and_harness_when_no_project_source_roots_exist(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-critical-access-control-01"
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            semantic_graph = ws / ".auditooor" / "semantic_graph.json"
            _write_json(
                input_path,
                {
                    "units": [
                        {
                            "candidate_id": candidate,
                            "impact_contract_id": f"impact-contract-{candidate}",
                            "route_family": "access_control",
                            "tier": "Critical",
                            "requirement": "candidate_bound_project_source_citation",
                            "blocker_class": "terminal_no_candidate_bound_project_source",
                        },
                        {
                            "candidate_id": candidate,
                            "impact_contract_id": f"impact-contract-{candidate}",
                            "route_family": "access_control",
                            "tier": "Critical",
                            "requirement": "project_specific_harness_execution",
                            "blocker_class": "blocked_project_harness_missing_inputs",
                            "local_artifact_status": {"missing_requirements": ["target_project_binding"]},
                        },
                    ]
                },
            )
            _write_json(
                semantic_graph,
                {
                    "contracts": [
                        {"file": "detectors/fixtures/Foo.sol", "name": "Foo", "functions": []},
                        {"file": "reference/harness-fixture-kits/demo/src/Mock.sol", "name": "Mock", "functions": []},
                    ]
                },
            )

            payload = mod.build_payload(ws, input_path=input_path, semantic_graph_path=semantic_graph, bundle_dir=ws / ".auditooor" / "bundles")

        self.assertEqual(payload["project_source_root_count"], 0)
        self.assertEqual(payload["reduced_unit_count"], 2)
        self.assertEqual(payload["terminal_reduced_unit_count"], 2)
        self.assertEqual(payload["summary"]["discovery_status_counts"]["terminal_no_project_source_roots"], 1)
        self.assertEqual(payload["summary"]["discovery_status_counts"]["terminal_harness_blocked_no_project_source_roots"], 1)
        self.assertFalse(payload["promotion_allowed"])

    def test_finds_candidate_source_hints_without_promoting_source_or_harness(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-high-oracle-settlement-01"
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            semantic_graph = ws / ".auditooor" / "semantic_graph.json"
            _write_json(
                input_path,
                {
                    "units": [
                        {
                            "candidate_id": candidate,
                            "route_family": "oracle_settlement",
                            "tier": "High",
                            "requirement": "candidate_bound_project_source_citation",
                            "blocker_class": "terminal_semantic_hints_not_project_source",
                        },
                        {
                            "candidate_id": candidate,
                            "route_family": "oracle_settlement",
                            "tier": "High",
                            "requirement": "project_specific_harness_execution",
                            "blocker_class": "blocked_project_harness_missing_inputs",
                            "local_artifact_status": {"missing_requirements": ["bounded_input_fixture_json"]},
                        },
                    ]
                },
            )
            _write_json(
                semantic_graph,
                {
                    "contracts": [
                        {
                            "file": "src/OracleSettlement.sol",
                            "name": "OracleSettlement",
                            "functions": [{"name": "settle"}, {"name": "updatePrice"}],
                        }
                    ]
                },
            )

            payload = mod.build_payload(ws, input_path=input_path, semantic_graph_path=semantic_graph, bundle_dir=ws / ".auditooor" / "bundles")
            self.assertTrue((ws / ".auditooor" / "bundles" / "oracle_settlement.json").exists())

        statuses = {row["requirement"]: row["discovery_status"] for row in payload["reductions"]}
        self.assertEqual(statuses["candidate_bound_project_source_citation"], "candidate_project_source_hints_require_manual_citation")
        self.assertEqual(statuses["project_specific_harness_execution"], "harness_binding_hints_require_project_setup")
        self.assertEqual(payload["candidate_source_hint_unit_count"], 2)
        self.assertEqual(payload["closure_candidate_count"], 0)

    def test_consumes_validated_project_source_readiness_roots(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-high-oracle-settlement-01"
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            semantic_graph = ws / ".auditooor" / "semantic_graph.json"
            readiness = ws / ".auditooor" / "project_source_root_readiness.json"
            _write_json(
                input_path,
                {
                    "units": [
                        {
                            "candidate_id": candidate,
                            "route_family": "oracle_settlement",
                            "tier": "High",
                            "requirement": "candidate_bound_project_source_citation",
                            "blocker_class": "missing_source_review_row",
                        },
                    ]
                },
            )
            _write_json(semantic_graph, {"contracts": []})
            _write_json(
                readiness,
                {
                    "roots": [
                        {
                            "label": "target",
                            "usable": True,
                            "sample_files": [
                                {
                                    "file": "target_project/src/OracleSettlement.sol",
                                    "abs_path": str(ws / "target_project" / "src" / "OracleSettlement.sol"),
                                    "suffix": ".sol",
                                }
                            ],
                        },
                        {
                            "label": "fixture",
                            "usable": True,
                            "sample_files": [
                                {
                                    "file": "detectors/fixtures/OracleSettlement.sol",
                                    "abs_path": str(ws / "detectors" / "fixtures" / "OracleSettlement.sol"),
                                    "suffix": ".sol",
                                }
                            ],
                        },
                    ]
                },
            )

            payload = mod.build_payload(
                ws,
                input_path=input_path,
                semantic_graph_path=semantic_graph,
                project_source_readiness_path=readiness,
                bundle_dir=ws / ".auditooor" / "bundles",
            )

        self.assertEqual(payload["project_source_root_count"], 1)
        self.assertEqual(payload["candidate_source_hint_unit_count"], 1)
        self.assertEqual(
            payload["reductions"][0]["discovery_status"],
            "candidate_project_source_hints_require_manual_citation",
        )

    def test_declared_real_root_end_to_end_creates_review_candidates_not_proof(self) -> None:
        mod = _import()
        readiness_spec = importlib.util.spec_from_file_location(
            "project_source_root_readiness_e2e",
            str(ROOT / "tools" / "project-source-root-readiness.py"),
        )
        assert readiness_spec is not None and readiness_spec.loader is not None
        readiness_mod = importlib.util.module_from_spec(readiness_spec)
        readiness_spec.loader.exec_module(readiness_mod)

        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            target_root = ws / "target_project" / "src"
            target_root.mkdir(parents=True)
            (target_root / "OracleSettlement.sol").write_text(
                "contract OracleSettlement { function settle(uint256 price) external {} }\n",
                encoding="utf-8",
            )
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            semantic_graph = ws / ".auditooor" / "semantic_graph.json"
            manifest = ws / ".auditooor" / "project_source_roots.json"
            readiness = ws / ".auditooor" / "project_source_root_readiness.json"
            _write_json(
                manifest,
                {
                    "schema": "auditooor.project_source_roots.v1",
                    "roots": [
                        {
                            "label": "target",
                            "path": "target_project/src",
                            "kind": "target_project_source",
                        },
                        {
                            "label": "generated",
                            "path": "detectors/fixtures",
                            "kind": "target_project_source",
                        },
                    ],
                },
            )
            _write_json(
                input_path,
                {
                    "units": [
                        {
                            "candidate_id": "imo-high-oracle-settlement-01",
                            "route_family": "oracle_settlement",
                            "tier": "High",
                            "requirement": "candidate_bound_project_source_citation",
                            "blocker_class": "missing_source_review_row",
                        },
                        {
                            "candidate_id": "imo-high-oracle-settlement-01",
                            "route_family": "oracle_settlement",
                            "tier": "High",
                            "requirement": "project_specific_harness_execution",
                            "blocker_class": "blocked_project_harness_missing_inputs",
                        },
                    ]
                },
            )
            _write_json(semantic_graph, {"contracts": []})
            readiness_payload = readiness_mod.build_payload(ws, manifest_path=manifest)
            _write_json(readiness, readiness_payload)

            payload = mod.build_payload(
                ws,
                input_path=input_path,
                semantic_graph_path=semantic_graph,
                project_source_readiness_path=readiness,
                bundle_dir=ws / ".auditooor" / "bundles",
            )

        self.assertEqual(readiness_payload["ready_root_count"], 1)
        self.assertEqual(readiness_payload["rejected_root_count"], 1)
        self.assertEqual(payload["project_source_root_count"], 1)
        self.assertEqual(payload["candidate_source_hint_unit_count"], 2)
        self.assertEqual(payload["closure_candidate_count"], 0)
        self.assertFalse(payload["promotion_allowed"])
        statuses = {row["requirement"]: row["discovery_status"] for row in payload["reductions"]}
        self.assertEqual(
            statuses["candidate_bound_project_source_citation"],
            "candidate_project_source_hints_require_manual_citation",
        )
        self.assertEqual(
            statuses["project_specific_harness_execution"],
            "harness_binding_hints_require_project_setup",
        )

    def test_excludes_generated_and_reference_paths_from_project_sources(self) -> None:
        mod = _import()
        self.assertFalse(mod.is_project_source_path("benchmark_fixtures/impact_miss_offset/non_base_demo/src/DemoVault.sol"))
        self.assertFalse(mod.is_project_source_path("detectors/_fixtures/Foo.sol"))
        self.assertFalse(mod.is_project_source_path("patterns/fixtures/auto/finding_10411__BaseVault.sol.vuln.sol"))
        self.assertFalse(mod.is_project_source_path("projects/morpho/submissions/staging/__ref_Vault.sol"))
        self.assertFalse(mod.is_project_source_path("test_poc/kelp_style_lz_oft_adapter.sol"))
        self.assertFalse(mod.is_project_source_path("reference/harness-fixture-kits/demo/src/Mock.sol"))
        self.assertTrue(mod.is_project_source_path("src/Vault.sol"))
        self.assertTrue(mod.is_project_source_path("external/base-node/crates/node/src/lib.rs"))

    # --- Bug fix coverage: .go / .ts / .nr were missing from SOURCE_SUFFIXES ---

    def test_go_source_file_accepted_by_is_project_source_path(self) -> None:
        """A Go source file in a non-excluded path must pass is_project_source_path."""
        mod = _import()
        self.assertTrue(mod.is_project_source_path("x/keeper/keeper.go"))

    def test_ts_source_file_accepted_by_is_project_source_path(self) -> None:
        """A TypeScript source file in a non-excluded path must pass is_project_source_path."""
        mod = _import()
        self.assertTrue(mod.is_project_source_path("contracts/Token.ts"))

    def test_nr_source_file_accepted_by_is_project_source_path(self) -> None:
        """A Noir source file in a non-excluded path must pass is_project_source_path."""
        mod = _import()
        self.assertTrue(mod.is_project_source_path("circuits/vault.nr"))

    def test_go_workspace_discovery_not_terminal(self) -> None:
        """A Go workspace with a semantic_graph entry must NOT produce terminal_no_project_source_roots.

        Before the fix SOURCE_SUFFIXES lacked .go so project_source_root_count was 0 and
        every source unit received discovery_status = terminal_no_project_source_roots.
        After the fix the root is discovered and the status becomes
        candidate_project_source_hints_require_manual_citation.
        """
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-critical-access-control-go-01"
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            semantic_graph = ws / ".auditooor" / "semantic_graph.json"
            _write_json(
                input_path,
                {
                    "units": [
                        {
                            "candidate_id": candidate,
                            "impact_contract_id": f"impact-contract-{candidate}",
                            "route_family": "access_control",
                            "tier": "Critical",
                            "requirement": "candidate_bound_project_source_citation",
                            "blocker_class": "terminal_no_candidate_bound_project_source",
                        }
                    ]
                },
            )
            _write_json(
                semantic_graph,
                {
                    "contracts": [
                        {"file": "x/keeper/keeper.go", "name": "Keeper", "functions": [{"name": "SetOwner"}]}
                    ]
                },
            )
            payload = mod.build_payload(ws, input_path=input_path, semantic_graph_path=semantic_graph)

        # After the fix: the Go file must be discovered
        self.assertEqual(payload["project_source_root_count"], 1, "Go file must be counted as a project source root")
        self.assertEqual(len(payload["reductions"]), 1)
        # discovery_status must NOT be the terminal no-roots status
        status = payload["reductions"][0]["discovery_status"]
        self.assertNotEqual(
            status,
            "terminal_no_project_source_roots",
            f"Got terminal status {status!r} - .go was still missing from SOURCE_SUFFIXES",
        )

    def test_ts_workspace_discovery_not_terminal(self) -> None:
        """A TypeScript workspace with a semantic_graph entry must NOT produce terminal_no_project_source_roots."""
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-high-asset-custody-ts-01"
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            semantic_graph = ws / ".auditooor" / "semantic_graph.json"
            _write_json(
                input_path,
                {
                    "units": [
                        {
                            "candidate_id": candidate,
                            "impact_contract_id": f"impact-contract-{candidate}",
                            "route_family": "asset_custody",
                            "tier": "High",
                            "requirement": "candidate_bound_project_source_citation",
                            "blocker_class": "terminal_no_candidate_bound_project_source",
                        }
                    ]
                },
            )
            _write_json(
                semantic_graph,
                {
                    "contracts": [
                        {"file": "contracts/Token.ts", "name": "Token", "functions": [{"name": "transfer"}]}
                    ]
                },
            )
            payload = mod.build_payload(ws, input_path=input_path, semantic_graph_path=semantic_graph)

        self.assertEqual(payload["project_source_root_count"], 1, "TypeScript file must be counted as a project source root")
        status = payload["reductions"][0]["discovery_status"]
        self.assertNotEqual(
            status,
            "terminal_no_project_source_roots",
            f"Got terminal status {status!r} - .ts was still missing from SOURCE_SUFFIXES",
        )

    def test_nr_workspace_discovery_not_terminal(self) -> None:
        """A Noir workspace with a semantic_graph entry must NOT produce terminal_no_project_source_roots."""
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-high-proof-verification-nr-01"
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            semantic_graph = ws / ".auditooor" / "semantic_graph.json"
            _write_json(
                input_path,
                {
                    "units": [
                        {
                            "candidate_id": candidate,
                            "impact_contract_id": f"impact-contract-{candidate}",
                            "route_family": "proof_verification",
                            "tier": "High",
                            "requirement": "candidate_bound_project_source_citation",
                            "blocker_class": "terminal_no_candidate_bound_project_source",
                        }
                    ]
                },
            )
            _write_json(
                semantic_graph,
                {
                    "contracts": [
                        {"file": "circuits/vault.nr", "name": "Vault", "functions": [{"name": "verify"}]}
                    ]
                },
            )
            payload = mod.build_payload(ws, input_path=input_path, semantic_graph_path=semantic_graph)

        self.assertEqual(payload["project_source_root_count"], 1, "Noir file must be counted as a project source root")
        status = payload["reductions"][0]["discovery_status"]
        self.assertNotEqual(
            status,
            "terminal_no_project_source_roots",
            f"Got terminal status {status!r} - .nr was still missing from SOURCE_SUFFIXES",
        )

if __name__ == "__main__":
    unittest.main()
