"""Gap E — mining-prioritizer per_asset_allocation test.

Verifies:
  - `swarm/mining_priorities.json` contains `per_asset_allocation` sourced
    from INTAKE_BASELINE.json's asset_coverage_plan when available.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "mining-prioritizer.py"


def _load_tool():
    """Load mining-prioritizer as a module for direct function tests.

    mining-prioritizer.py imports sibling helpers (submission_ledger,
    submission_paths, outcome_reweight) as bare names; we put tools/ on
    sys.path so those imports resolve during the exec_module call.
    """
    tools_dir = str(REPO / "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    spec = importlib.util.spec_from_file_location("mining_prioritizer", TOOL)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _write_intake(ws: Path) -> None:
    (ws / "INTAKE_BASELINE.json").write_text(json.dumps({
        "schema": "auditooor.intake-baseline.v1",
        "assets_in_scope": ["Smart Contract", "Blockchain/DLT"],
        "asset_coverage_plan": {
            "Smart Contract": {
                "roots": ["src/contracts"],
                "strategy": "line-by-line",
                "estimated_hours": 30,
                "agent_hour_quota_pct": 60,
                "plan_status": "ready",
            },
            "Blockchain/DLT": {
                "roots": ["external/base"],
                "strategy": "rust review",
                "estimated_hours": 20,
                "agent_hour_quota_pct": 40,
                "plan_status": "ready",
            },
        },
    }, indent=2))


def _write_ccia(ws: Path) -> None:
    (ws / "ccia_report.json").write_text(json.dumps({
        "ccia": {},
        "attack_angles": [
            {
                "id": "A-REENT",
                "severity": "HIGH",
                "title": "Reentrancy in Vault.withdraw",
                "contracts": ["Vault"],
            },
            {
                "id": "A-AUTH",
                "severity": "MEDIUM",
                "title": "Unauthenticated admin setter",
                "contracts": ["Admin"],
            },
        ],
    }, indent=2))


def _write_semantic_graph(ws: Path) -> None:
    aud = ws / ".auditooor"
    aud.mkdir()
    (aud / "semantic_graph.json").write_text(json.dumps({
        "schema_version": "auditooor.semantic_graph.v1",
        "source_file_count": 1,
        "contract_count": 2,
        "entrypoint_count": 1,
        "relation_edge_count": 1,
        "evidence_edge_count": 3,
        "multi_hop_path_count": 1,
        "entrypoints": [
            {
                "contract": "Bridge",
                "function": "finalize",
                "role": "permissionless",
                "state_writes": ["finalized"],
                "external_calls": [],
            }
        ],
        "relation_edges": [
            {
                "kind": "high-level-call",
                "source_contract": "Bridge",
                "source_function": "finalize",
                "target": "Portal",
                "method": "withdraw",
                "receiver": "portal",
                "target_type": "Portal",
                "receiver_source": "state",
                "resolution": "type-name-source-shape",
                "detector_hint": "resolved_typed_receiver",
                "file": "src/Bridge.sol",
                "line": 12,
            }
        ],
        "multi_hop_paths": [
            {
                "path_id": "SG-MH-001",
                "impact_family": "bridge_finalization",
                "source_component": "Bridge.finalize",
                "mapped_stages": ["caller", "validation", "proof_dispute_bridge_finalization"],
                "missing_stages": ["parser", "cache_provider", "state_root"],
            }
        ],
    }, indent=2))


def _write_semantic_detector_worklist(ws: Path) -> None:
    aud = ws / ".auditooor"
    aud.mkdir(exist_ok=True)
    (aud / "semantic_detector_worklist.json").write_text(json.dumps({
        "schema": "auditooor.semantic_detector_worklist.v1",
        "coverage_claim": "none_source_shape_only",
        "advisory_only": True,
        "promotion_allowed": False,
        "task_count": 2,
        "relation_edge_task_count": 1,
        "multi_hop_task_count": 1,
        "candidate_detector_family_counts": {
            "factory_proxy_relation": 1,
            "bridge_finalization": 1,
        },
        "detector_query_bridge_counts": {
            "factory_proxy_or_clone_relation": 1,
            "bridge_or_proof_finalization_path": 1,
        },
        "tasks": [
            {
                "task_id": "SDW-REL-001",
                "source_kind": "semantic_relation_edge",
                "source_id": "Factory.deploy:clone:42",
                "detector_task_kind": "semantic_relation_detector_rewrite",
                "candidate_detector_family": "factory_proxy_relation",
                "detector_task_status": "advisory_untriaged",
                "terminal_state": "open_advisory",
                "submission_posture": "NOT_SUBMIT_READY",
                "submit_status": "NOT_SUBMIT_READY",
                "severity": "none",
                "severity_claim": "none",
                "selected_impact": "",
                "impact_contract_id": "",
                "impact_contract_required": True,
                "advisory_only": True,
                "promotion_allowed": False,
                "source_component": "Factory.deploy",
                "target_component": "Implementation",
                "file": "src/Factory.sol",
                "line": 42,
                "recommended_action": "Evaluate detector predicate.",
                "detector_query_bridge": {
                    "backend": "semantic_graph_query",
                    "advisory_only": True,
                    "coverage_claim": "none_source_shape_only",
                    "query_status": "candidate_spec",
                    "source_collection": "relation_edges",
                    "query_shape": "factory_proxy_or_clone_relation",
                    "fixture_tags": ["factory", "proxy", "clone"],
                },
            },
            {
                "task_id": "SDW-MH-001",
                "source_kind": "semantic_multi_hop_path",
                "source_id": "SG-MH-001",
                "detector_task_kind": "semantic_multihop_detector_rewrite",
                "candidate_detector_family": "bridge_finalization",
                "detector_task_status": "advisory_untriaged",
                "terminal_state": "open_advisory",
                "submission_posture": "NOT_SUBMIT_READY",
                "submit_status": "NOT_SUBMIT_READY",
                "severity": "none",
                "severity_claim": "none",
                "selected_impact": "",
                "impact_contract_id": "",
                "impact_contract_required": True,
                "advisory_only": True,
                "promotion_allowed": False,
                "impact_family": "bridge_finalization",
                "recommended_action": "Route to detector or invariant review.",
                "detector_query_bridge": {
                    "backend": "semantic_graph_query",
                    "advisory_only": True,
                    "coverage_claim": "none_source_shape_only",
                    "query_status": "candidate_spec",
                    "source_collection": "multi_hop_paths",
                    "query_shape": "bridge_or_proof_finalization_path",
                    "required_stages": ["caller", "validation", "proof_dispute_bridge_finalization"],
                    "fixture_tags": ["bridge", "proof", "finalization"],
                },
            },
        ],
    }, indent=2))


def _write_semantic_graph_query_results(ws: Path, *, source_mode: str = "semantic_detector_worklist") -> None:
    aud = ws / ".auditooor"
    aud.mkdir(exist_ok=True)
    task_id = (
        "high-001-network-stop-semantic-query-001"
        if source_mode == "impact_family_worklist"
        else "SDW-REL-001"
    )
    (aud / "semantic_graph_query_results.json").write_text(json.dumps({
        "schema": "auditooor.semantic_graph_query_results.v1",
        "workspace": str(ws),
        "source_mode": source_mode,
        "source_artifact": str(aud / ("impact_family_worklists.json" if source_mode == "impact_family_worklist" else "semantic_detector_worklist.json")),
        "query_count": 1,
        "error_count": 0,
        "matched_row_count": 1,
        "impact_worklist_row_count": 1 if source_mode == "impact_family_worklist" else 0,
        "coverage_claim": "none_source_shape_only",
        "advisory_only": True,
        "promotion_allowed": False,
        "severity": "none",
        "selected_impact": "",
        "submission_posture": "NOT_SUBMIT_READY",
        "submit_status": "NOT_SUBMIT_READY",
        "impact_contract_required": True,
        "results": [
            {
                "task_id": task_id,
                "route_id": task_id,
                "route_kind": "semantic_graph_query",
                "impact_id": "high-001-network-stop" if source_mode == "impact_family_worklist" else "",
                "impact_family": "node_or_network_liveness" if source_mode == "impact_family_worklist" else "",
                "candidate_detector_family": "factory_proxy_relation",
                "query_shape": "impact_worklist_component_relations" if source_mode == "impact_family_worklist" else "factory_proxy_or_clone_relation",
                "source_collection": "relation_edges",
                "query_status": "executed",
                "match_count": 1,
                "truncated": False,
                "coverage_claim": "none_source_shape_only",
                "advisory_only": True,
                "promotion_allowed": False,
                "severity": "none",
                "selected_impact": "",
                "submission_posture": "NOT_SUBMIT_READY",
                "submit_status": "NOT_SUBMIT_READY",
                "impact_contract_required": True,
                "matches": [{"file": "src/Factory.sol", "line": 42}],
            }
        ],
    }, indent=2))


def _write_semantic_detector_adjudication(ws: Path) -> None:
    aud = ws / ".auditooor"
    aud.mkdir(exist_ok=True)
    (aud / "semantic_detector_adjudication.json").write_text(json.dumps({
        "schema": "auditooor.semantic_detector_adjudication.v1",
        "workspace": str(ws),
        "source_mode": "semantic_detector_worklist",
        "coverage_claim": "none_source_shape_only",
        "advisory_only": True,
        "promotion_allowed": False,
        "severity": "none",
        "severity_claim": "none",
        "selected_impact": "",
        "submission_posture": "NOT_SUBMIT_READY",
        "submit_status": "NOT_SUBMIT_READY",
        "impact_contract_required": True,
        "processed_query_count": 2,
        "input_query_count": 2,
        "input_matched_row_count": 2,
        "detector_rewrite_brief_count": 1,
        "fixture_requirement_count": 2,
        "non_detectorizable_count": 1,
        "adjudication_summary": {
            "non_detectorizable_reason_counts": {
                "multi_hop_path_requires_fixture_or_invariant_before_detector_rewrite": 1,
            },
            "orphaned_query_result_count": 0,
            "non_executed_query_result_count": 0,
        },
        "readiness": {
            "ready_for_detector_rewrite_count": 1,
            "fixture_first_count": 2,
            "source_review_only_count": 1,
            "ready_for_submission": False,
            "ready_for_poc": False,
            "ready_for_severity": False,
        },
        "next_commands": [
            "make semantic-detector-adjudication WS=<workspace> # detector",
            "make source-proof-task-queue WS=<workspace> # source-only",
        ],
        "detector_rewrite_briefs": [
            {
                "brief_id": "SDA-DET-001",
                "task_id": "SDW-REL-001",
                "adjudication": "detector_rewrite_brief",
                "candidate_detector_family": "factory_proxy_relation",
                "query_shape": "factory_proxy_or_clone_relation",
                "source_collection": "relation_edges",
                "match_count": 1,
                "submission_posture": "NOT_SUBMIT_READY",
                "severity": "none",
                "selected_impact": "",
                "impact_contract_required": True,
                "advisory_only": True,
                "promotion_allowed": False,
            }
        ],
        "fixture_requirements": [
            {
                "fixture_id": "SDA-FIX-001",
                "task_id": "SDW-REL-001",
                "adjudication": "fixture_requirement",
                "query_shape": "factory_proxy_or_clone_relation",
                "submission_posture": "NOT_SUBMIT_READY",
                "severity": "none",
                "impact_contract_required": True,
                "advisory_only": True,
                "promotion_allowed": False,
            },
            {
                "fixture_id": "SDA-FIX-002",
                "task_id": "SDW-MH-001",
                "adjudication": "fixture_requirement",
                "query_shape": "bridge_or_proof_finalization_path",
                "submission_posture": "NOT_SUBMIT_READY",
                "severity": "none",
                "impact_contract_required": True,
                "advisory_only": True,
                "promotion_allowed": False,
            },
        ],
        "non_detectorizable_rows": [
            {
                "row_id": "SDA-ND-002",
                "task_id": "SDW-MH-001",
                "adjudication": "non_detectorizable",
                "reason": "multi_hop_path_requires_fixture_or_invariant_before_detector_rewrite",
                "query_shape": "bridge_or_proof_finalization_path",
                "submission_posture": "NOT_SUBMIT_READY",
                "severity": "none",
                "impact_contract_required": True,
                "advisory_only": True,
                "promotion_allowed": False,
            }
        ],
    }, indent=2))


def _write_impact_family_worklists(ws: Path) -> None:
    aud = ws / ".auditooor"
    aud.mkdir(exist_ok=True)
    (aud / "impact_family_worklists.json").write_text(json.dumps({
        "schema": "auditooor.pr560.impact_family_worklists.v1",
        "status": "open_impact_family_work",
        "blocker_category_counts": {"open_high_impact_candidate_absence": 1},
        "strict_blocking_categories": [],
        "open_work_categories": ["open_high_impact_candidate_absence"],
        "worklists": [
            {
                "impact_id": "high-001-network-stop",
                "worklist_id": "impact-worklist-high-001-network-stop",
                "impact_family": "node_or_network_liveness",
                "severity": "High",
                "impact": "Network nodes stop processing new blocks",
                "status": "open_impact_family_work",
                "submission_posture": "NOT_SUBMIT_READY",
                "submit_ready": False,
                "proof_class": "executed_with_manifest",
                "required_artifacts": ["impact_contract", "poc_execution_manifest"],
                "relevant_source_roots": ["crates/node"],
                "component_count": 1,
                "components": [
                    {
                        "component_id": "NodeIngress.processBlock",
                        "component_kind": "entrypoint",
                        "file": "crates/node/src/ingress.rs",
                        "line": 44,
                    }
                ],
                "oos_traps": ["exclude flood-only DoS"],
                "source_review_handoff": {
                    "schema": "auditooor.pr560.impact_source_review_handoff.v1",
                    "route_count": 1,
                    "route_kind_counts": {"semantic_graph_query": 1},
                    "semantic_graph_query_result_status": "present",
                    "query_result_accounting": {
                        "candidate_query_count": 1,
                        "executed_query_count": 1,
                        "matched_query_count": 1,
                        "zero_match_query_count": 0,
                        "matched_row_count": 1,
                    },
                    "submission_posture": "NOT_SUBMIT_READY",
                    "submit_ready": False,
                    "promotion_allowed": False,
                },
                "next_command": "make source-mine WS=<workspace> IMPACT_ID=high-001-network-stop",
            }
        ],
    }, indent=2))


class MiningPrioritizerAssetQuotaTest(unittest.TestCase):
    def test_per_asset_allocation_in_out_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_intake(ws)
            _write_ccia(ws)
            out_file = ws / "swarm" / "mining_priorities.json"

            result = subprocess.run(
                ["python3", str(TOOL), str(ws),
                 "--top", "5", "--out", str(out_file),
                 "--no-outcome-reweight"],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=30,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(out_file.is_file())
            payload = json.loads(out_file.read_text())
            self.assertIsInstance(payload, dict)
            self.assertIn("per_asset_allocation", payload)
            self.assertIn("angles", payload)
            alloc = payload["per_asset_allocation"]
            self.assertIn("Smart Contract", alloc)
            self.assertIn("Blockchain/DLT", alloc)
            self.assertEqual(alloc["Smart Contract"]["agent_hour_quota_pct"], 60)
            self.assertEqual(alloc["Blockchain/DLT"]["agent_hour_quota_pct"], 40)
            # target_agent_hours falls back to estimated_hours when present.
            self.assertEqual(alloc["Smart Contract"]["target_agent_hours"], 30)
            self.assertEqual(alloc["Blockchain/DLT"]["target_agent_hours"], 20)

    def test_compute_per_asset_allocation_direct(self):
        tool = _load_tool()
        plan = {
            "Smart Contract": {
                "estimated_hours": 30,
                "agent_hour_quota_pct": 60,
                "roots": ["src/"],
                "plan_status": "ready",
            },
            "Blockchain/DLT": {
                "estimated_hours": 0,
                "agent_hour_quota_pct": 50,
                "roots": ["external/"],
                "plan_status": "ready",
            },
        }
        alloc = tool.compute_per_asset_allocation(plan, total_agent_hours=100)
        self.assertEqual(alloc["Smart Contract"]["target_agent_hours"], 30)
        # Falls back to 50% of 100 = 50 when estimated_hours is 0.
        self.assertEqual(alloc["Blockchain/DLT"]["target_agent_hours"], 50)

    def test_semantic_path_inventory_wraps_priorities_when_graph_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_ccia(ws)
            _write_semantic_graph(ws)
            out_file = ws / "swarm" / "mining_priorities.json"

            result = subprocess.run(
                ["python3", str(TOOL), str(ws),
                 "--top", "5", "--out", str(out_file),
                 "--no-outcome-reweight"],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=30,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(out_file.read_text())
            self.assertIsInstance(payload, dict)
            self.assertIn("angles", payload)
            inventory = payload["semantic_path_inventory"]
            self.assertEqual(inventory["coverage_claim"], "none_source_shape_only")
            self.assertEqual(inventory["summary"]["multi_hop_path_count"], 1)
            self.assertEqual(
                inventory["multi_hop_path_worklist"][0]["impact_family"],
                "bridge_finalization",
            )
            self.assertEqual(
                inventory["relation_edge_worklist"][0]["kind"],
                "high-level-call",
            )
            self.assertEqual(
                inventory["relation_edge_worklist"][0]["target_type"],
                "Portal",
            )
            self.assertEqual(
                inventory["relation_edge_worklist"][0]["receiver_source"],
                "state",
            )

    def test_semantic_detector_worklist_is_carried_as_advisory_sidecar(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_ccia(ws)
            _write_semantic_detector_worklist(ws)
            _write_semantic_graph_query_results(ws)
            out_file = ws / "swarm" / "mining_priorities.json"

            result = subprocess.run(
                ["python3", str(TOOL), str(ws),
                 "--top", "5", "--out", str(out_file),
                 "--no-outcome-reweight"],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=30,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(out_file.read_text())
            self.assertIsInstance(payload, dict)
            self.assertIn("angles", payload)
            sidecar = payload["semantic_detector_worklist"]
            self.assertEqual(sidecar["schema"], "auditooor.semantic_detector_worklist.v1")
            self.assertEqual(sidecar["coverage_claim"], "none_source_shape_only")
            self.assertTrue(sidecar["advisory_only"])
            self.assertFalse(sidecar["promotion_allowed"])
            self.assertEqual(sidecar["task_count"], 2)
            self.assertEqual(sidecar["candidate_detector_family_counts"]["factory_proxy_relation"], 1)
            self.assertEqual(sidecar["detector_query_bridge_counts"]["factory_proxy_or_clone_relation"], 1)
            self.assertEqual(sidecar["query_result_accounting"]["executed_query_count"], 1)
            self.assertEqual(sidecar["query_result_accounting"]["matched_query_count"], 1)
            self.assertEqual(sidecar["query_result_accounting"]["matched_row_count"], 1)
            row = sidecar["task_sample"][0]
            self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
            self.assertEqual(row["submit_status"], "NOT_SUBMIT_READY")
            self.assertEqual(row["severity"], "none")
            self.assertEqual(row["severity_claim"], "none")
            self.assertEqual(row["selected_impact"], "")
            self.assertEqual(row["impact_contract_id"], "")
            self.assertTrue(row["impact_contract_required"])
            self.assertTrue(row["advisory_only"])
            self.assertFalse(row["promotion_allowed"])
            self.assertEqual(
                row["detector_query_bridge"]["backend"],
                "semantic_graph_query",
            )
            self.assertEqual(
                row["detector_query_bridge"]["query_shape"],
                "factory_proxy_or_clone_relation",
            )
            self.assertEqual(
                row["detector_query_bridge"]["coverage_claim"],
                "none_source_shape_only",
            )
            self.assertEqual(row["query_result_status"], "executed")
            self.assertEqual(row["query_match_count"], 1)
            self.assertIn("semantic_graph_query_results", payload)
            results = payload["semantic_graph_query_results"]
            self.assertEqual(results["source_mode"], "semantic_detector_worklist")
            self.assertEqual(results["query_count"], 1)
            self.assertEqual(results["matched_row_count"], 1)
            self.assertEqual(results["query_status_counts"], {"executed": 1})
            self.assertEqual(results["result_sample"][0]["submission_posture"], "NOT_SUBMIT_READY")
            self.assertFalse(results["result_sample"][0]["promotion_allowed"])

    def test_semantic_detector_worklist_direct_loader_handles_bad_json(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir()
            (aud / "semantic_detector_worklist.json").write_text("{not json")

            sidecar = tool.load_semantic_detector_worklist(ws)
            self.assertEqual(sidecar["status"], "unreadable")
            self.assertEqual(sidecar["coverage_claim"], "none_source_shape_only")
            self.assertTrue(sidecar["advisory_only"])
            self.assertFalse(sidecar["promotion_allowed"])

    def test_semantic_detector_worklist_direct_loader_absent_is_empty(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            sidecar = tool.load_semantic_detector_worklist(Path(tmp))
            self.assertEqual(sidecar, {})

    def test_semantic_detector_adjudication_is_carried_as_advisory_sidecar(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_ccia(ws)
            _write_semantic_detector_adjudication(ws)
            out_file = ws / "swarm" / "mining_priorities.json"

            result = subprocess.run(
                ["python3", str(TOOL), str(ws),
                 "--top", "5", "--out", str(out_file),
                 "--no-outcome-reweight"],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=30,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(out_file.read_text())
            sidecar = payload["semantic_detector_adjudication"]
            self.assertEqual(sidecar["schema"], "auditooor.semantic_detector_adjudication.v1")
            self.assertEqual(sidecar["coverage_claim"], "none_source_shape_only")
            self.assertTrue(sidecar["advisory_only"])
            self.assertFalse(sidecar["promotion_allowed"])
            self.assertEqual(sidecar["submission_posture"], "NOT_SUBMIT_READY")
            self.assertEqual(sidecar["severity"], "none")
            self.assertEqual(sidecar["selected_impact"], "")
            self.assertTrue(sidecar["impact_contract_required"])
            self.assertEqual(sidecar["detector_rewrite_brief_count"], 1)
            self.assertEqual(sidecar["fixture_requirement_count"], 2)
            self.assertEqual(sidecar["non_detectorizable_count"], 1)
            self.assertEqual(sidecar["readiness"]["ready_for_detector_rewrite_count"], 1)
            self.assertFalse(sidecar["readiness"]["ready_for_submission"])
            self.assertEqual(
                sidecar["non_detectorizable_reason_counts"]["multi_hop_path_requires_fixture_or_invariant_before_detector_rewrite"],
                1,
            )
            self.assertIn("make semantic-detector-adjudication", sidecar["next_command_sample"][0])
            brief = sidecar["detector_rewrite_brief_sample"][0]
            self.assertEqual(brief["adjudication"], "detector_rewrite_brief")
            self.assertEqual(brief["submission_posture"], "NOT_SUBMIT_READY")
            self.assertFalse(brief["promotion_allowed"])
            fixture = sidecar["fixture_requirement_sample"][0]
            self.assertEqual(fixture["adjudication"], "fixture_requirement")
            nd_row = sidecar["non_detectorizable_sample"][0]
            self.assertEqual(nd_row["adjudication"], "non_detectorizable")

    def test_semantic_detector_adjudication_direct_loader_handles_bad_json(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir()
            (aud / "semantic_detector_adjudication.json").write_text("{not json")

            sidecar = tool.load_semantic_detector_adjudication(ws)
            self.assertEqual(sidecar["status"], "unreadable")
            self.assertEqual(sidecar["coverage_claim"], "none_source_shape_only")
            self.assertTrue(sidecar["advisory_only"])
            self.assertFalse(sidecar["promotion_allowed"])

    def test_semantic_detector_adjudication_direct_loader_absent_is_empty(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            sidecar = tool.load_semantic_detector_adjudication(Path(tmp))
            self.assertEqual(sidecar, {})

    def test_semantic_graph_query_results_direct_loader_handles_bad_json(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir()
            (aud / "semantic_graph_query_results.json").write_text("{not json")

            sidecar = tool.load_semantic_graph_query_results(ws)
            self.assertEqual(sidecar["status"], "unreadable")
            self.assertEqual(sidecar["coverage_claim"], "none_source_shape_only")
            self.assertTrue(sidecar["advisory_only"])
            self.assertFalse(sidecar["promotion_allowed"])

    def test_semantic_graph_query_results_direct_loader_absent_is_empty(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            sidecar = tool.load_semantic_graph_query_results(Path(tmp))
            self.assertEqual(sidecar, {})

    def test_impact_family_worklists_are_carried_as_fail_closed_sidecar(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_ccia(ws)
            _write_impact_family_worklists(ws)
            _write_semantic_graph_query_results(ws, source_mode="impact_family_worklist")
            out_file = ws / "swarm" / "mining_priorities.json"

            result = subprocess.run(
                ["python3", str(TOOL), str(ws),
                 "--top", "5", "--out", str(out_file),
                 "--no-outcome-reweight"],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=30,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(out_file.read_text())
            sidecar = payload["impact_family_worklists"]
            self.assertEqual(sidecar["status"], "present")
            self.assertTrue(sidecar["advisory_only"])
            self.assertFalse(sidecar["promotion_allowed"])
            row = sidecar["worklists"][0]
            self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
            self.assertFalse(row["submit_ready"])
            self.assertEqual(row["impact_family"], "node_or_network_liveness")
            self.assertEqual(row["components"][0]["component_id"], "NodeIngress.processBlock")
            handoff = row["source_review_handoff"]
            self.assertEqual(handoff["route_kind_counts"], {"semantic_graph_query": 1})
            self.assertEqual(handoff["semantic_graph_query_result_status"], "present")
            self.assertEqual(handoff["query_result_accounting"]["executed_query_count"], 1)
            self.assertEqual(handoff["submission_posture"], "NOT_SUBMIT_READY")
            self.assertFalse(handoff["submit_ready"])
            results = payload["semantic_graph_query_results"]
            self.assertEqual(results["source_mode"], "impact_family_worklist")
            self.assertEqual(results["impact_worklist_row_count"], 1)
            self.assertEqual(results["source_collection_counts"], {"relation_edges": 1})

    def test_flat_list_when_no_asset_plan(self):
        """Back-compat: when INTAKE_BASELINE.json lacks asset_coverage_plan,
        no semantic graph exists, and no semantic detector worklist exists, the
        JSON file stays a flat list for existing readers."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_ccia(ws)  # no INTAKE_BASELINE.json
            out_file = ws / "swarm" / "mining_priorities.json"

            result = subprocess.run(
                ["python3", str(TOOL), str(ws),
                 "--top", "5", "--out", str(out_file),
                 "--no-outcome-reweight"],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=30,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(out_file.read_text())
            self.assertIsInstance(payload, list)


if __name__ == "__main__":
    unittest.main()
