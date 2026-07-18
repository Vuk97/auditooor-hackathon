#!/usr/bin/env python3
"""Hermetic tests for PR #560 automation-closure inventories."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "automation-closure.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("automation_closure", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["automation_closure"] = module
    spec.loader.exec_module(module)
    return module


tool = load_tool()


SEVERITY = """\
# Severity

## Critical

- Network not being able to confirm new transactions
- Direct theft of user funds

**Finalization windows**

- Single proof: 7 days
- Dual proof: 1 day

## Medium

- Increasing network processing node resource consumption by at least 30%
"""


class AutomationClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self._old_progress_docs_dir = os.environ.get("AUDITOOOR_PR560_PROGRESS_DOCS_DIR")
        self._progress_docs_tmp = tempfile.TemporaryDirectory(prefix="automation_closure_progress_docs_")
        self.progress_docs_dir = Path(self._progress_docs_tmp.name)
        os.environ["AUDITOOOR_PR560_PROGRESS_DOCS_DIR"] = str(self.progress_docs_dir)

    def tearDown(self) -> None:
        if self._old_progress_docs_dir is None:
            os.environ.pop("AUDITOOOR_PR560_PROGRESS_DOCS_DIR", None)
        else:
            os.environ["AUDITOOOR_PR560_PROGRESS_DOCS_DIR"] = self._old_progress_docs_dir
        self._progress_docs_tmp.cleanup()

    def make_ws(self) -> Path:
        ws = Path(tempfile.mkdtemp(prefix="automation_closure_ws_"))
        (ws / "SEVERITY.md").write_text(SEVERITY, encoding="utf-8")
        cand_dir = ws / "critical_hunt" / "candidates"
        cand_dir.mkdir(parents=True)
        (cand_dir / "c1.json").write_text(
            json.dumps(
                {
                    "candidate_id": "C1",
                    "severity": "Critical",
                    "listed_impact_selected": "Direct theft of user funds",
                    "listed_impact_proven": True,
                    "artifact_refs": ["src/Vault.sol"],
                }
            ),
            encoding="utf-8",
        )
        return ws

    def make_second_ws(self) -> Path:
        ws = Path(tempfile.mkdtemp(prefix="automation_closure_second_ws_"))
        (ws / "SEVERITY_BLOCKCHAIN_DLT.md").write_text(
            "# High\n\n"
            "- Network nodes can be forced to stop processing new blocks through one crafted peer message\n",
            encoding="utf-8",
        )
        (ws / "SCOPE.md").write_text(
            "# Scope\n\n"
            "- `crates/node/`\n"
            "- Excluded: social engineering and validator key compromise\n",
            encoding="utf-8",
        )
        (ws / "crates" / "node").mkdir(parents=True)
        (ws / ".auditooor").mkdir()
        for name in ("semantic_graph.json", "rust_source_graph.json", "invariant_ledger.json"):
            (ws / ".auditooor" / name).write_text("{}", encoding="utf-8")
        (ws / "live_topology_checks.json").write_text("{}", encoding="utf-8")
        (ws / "deployment_topology.json").write_text("{}", encoding="utf-8")
        (ws / "scanners" / "rust").mkdir(parents=True)
        (ws / "scanners" / "rust" / "SCAN_RUST_SUMMARY.json").write_text("{}", encoding="utf-8")
        (ws / "scanners" / "SCAN_REPORT.md").write_text("# Scan Report\n", encoding="utf-8")
        (ws / ".auditooor" / "coverage_introspection.json").write_text("{}", encoding="utf-8")
        (ws / "detector_findings.json").write_text("{}", encoding="utf-8")
        cand_dir = ws / "critical_hunt" / "candidates"
        cand_dir.mkdir(parents=True)
        (cand_dir / "node-stop.json").write_text(
            json.dumps(
                {
                    "candidate_id": "NODE-STOP",
                    "listed_impact_selected": "Network nodes can be forced to stop processing new blocks through one crafted peer message",
                    "listed_impact_proven": True,
                }
            ),
            encoding="utf-8",
        )
        return ws

    def make_smart_contract_ws(self) -> Path:
        ws = Path(tempfile.mkdtemp(prefix="automation_closure_smart_ws_"))
        (ws / "SEVERITY_SMART_CONTRACTS.md").write_text(
            "# Critical\n\n- Direct theft from in-scope bridge contracts\n",
            encoding="utf-8",
        )
        (ws / "SCOPE.md").write_text("# Scope\n\n- `src/`\n", encoding="utf-8")
        (ws / "src").mkdir()
        (ws / "src" / "Bridge.sol").write_text("contract Bridge {}\n", encoding="utf-8")
        (ws / ".auditooor").mkdir()
        for name in ("semantic_graph.json", "rust_source_graph.json", "invariant_ledger.json"):
            (ws / ".auditooor" / name).write_text("{}", encoding="utf-8")
        (ws / "live_topology_checks.json").write_text("{}", encoding="utf-8")
        (ws / "deployment_topology.json").write_text("{}", encoding="utf-8")
        (ws / "scanners").mkdir()
        (ws / "scanners" / "SCAN_REPORT.md").write_text("# Scan Report\n", encoding="utf-8")
        cand_dir = ws / "critical_hunt" / "candidates"
        cand_dir.mkdir(parents=True)
        (cand_dir / "bridge-theft.json").write_text(
            json.dumps(
                {
                    "candidate_id": "BRIDGE-THEFT",
                    "listed_impact_selected": "Direct theft from in-scope bridge contracts",
                    "listed_impact_proven": True,
                }
            ),
            encoding="utf-8",
        )
        return ws

    def make_smart_contract_ws_without_optional_topology(self) -> Path:
        ws = Path(tempfile.mkdtemp(prefix="automation_closure_smart_source_only_ws_"))
        (ws / "SEVERITY_SMART_CONTRACTS.md").write_text(
            "# Critical\n\n- Direct theft from in-scope bridge contracts\n",
            encoding="utf-8",
        )
        (ws / "SCOPE.md").write_text("# Scope\n\n- `src/`\n", encoding="utf-8")
        (ws / "src").mkdir()
        (ws / "src" / "Bridge.sol").write_text("contract Bridge {}\n", encoding="utf-8")
        (ws / ".auditooor").mkdir()
        for name in ("semantic_graph.json", "invariant_ledger.json"):
            (ws / ".auditooor" / name).write_text("{}", encoding="utf-8")
        (ws / "scan_report.md").write_text("# Scan Report\n", encoding="utf-8")
        cand_dir = ws / "critical_hunt" / "candidates"
        cand_dir.mkdir(parents=True)
        (cand_dir / "bridge-theft.json").write_text(
            json.dumps(
                {
                    "candidate_id": "BRIDGE-THEFT",
                    "listed_impact_selected": "Direct theft from in-scope bridge contracts",
                    "listed_impact_proven": True,
                }
            ),
            encoding="utf-8",
        )
        return ws

    def write_generated_invariants(self, ws: Path, *, missing: int = 1) -> Path:
        aud = ws / ".auditooor"
        aud.mkdir(exist_ok=True)
        path = aud / "generated_invariants.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": "auditooor.generated_invariants.v1",
                    "workspace": str(ws),
                    "generated_at": "2026-04-30T00:00:00+00:00",
                    "advisory": True,
                    "source_files": ["SEVERITY.md"],
                    "generated_count": 3,
                    "accepted_before_count": 2,
                    "missing_before_count": missing,
                    "added_to_ledger_count": missing,
                    "generated_rows": [],
                    "diff": {"accepted": [], "missing": []},
                    "next_command": "review diff.missing then run invariant-ledger --check",
                }
            ),
            encoding="utf-8",
        )
        return path

    def write_invariant_adoption(self, ws: Path) -> Path:
        aud = ws / ".auditooor"
        aud.mkdir(exist_ok=True)
        review_dir = aud / "invariant_discovery_review_units"
        review_dir.mkdir(exist_ok=True)
        (review_dir / "INV-DISC-ASSET-CUSTODY.json").write_text(
            json.dumps({"unit_id": "INV-DISC-ASSET-CUSTODY", "review_state": "blocked_no_project_source_roots"}),
            encoding="utf-8",
        )
        path = aud / "invariant_discovery_adoption.json"
        path.write_text(
            json.dumps(
                {
                    "schema": "auditooor.invariant_discovery_adoption.v1",
                    "status": "reduced_adopted_blocker_rows",
                    "generated_review": {
                        "generated_count": 1,
                        "terminal_review_count": 1,
                        "unreviewed_missing_count": 0,
                    },
                    "route_family_unit_count": 1,
                    "route_family_units": [
                        {
                            "unit_id": "INV-DISC-ASSET-CUSTODY",
                            "review_state": "blocked_no_project_source_roots",
                            "next_commands": ["make project-source-root-readiness WS=<workspace> JSON=1"],
                        }
                    ],
                    "review_unit_dir": str(review_dir),
                    "ledger_rows_added": 1,
                    "ledger_rows_updated": 0,
                    "adopted_to_canonical_invariant_ledger": True,
                    "closure_candidate_count": 0,
                    "promotion_allowed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                }
            ),
            encoding="utf-8",
        )
        return path

    def write_invariant_adoption_closure_readiness(self, ws: Path, *, ready: bool = False) -> Path:
        aud = ws / ".auditooor"
        aud.mkdir(exist_ok=True)
        path = aud / "invariant_adoption_closure_readiness.json"
        payload = {
            "schema": "auditooor.invariant_adoption_closure_readiness.v1",
            "status": "p0_invariant_adoption_closure_ready" if ready else "p0_invariant_adoption_blocked_exact",
            "p0_closure_ready": ready,
            "fresh_engagement_metrics": {
                "fresh_engagement_count": 3 if ready else 0,
                "valid_fresh_engagement_count": 3 if ready else 0,
                "required_fresh_engagement_count": 3,
            },
            "proof_class_evidence": {
                "proof_ready_execution_manifest_count": 1 if ready else 0,
                "ready_project_source_root_count": 1 if ready else 0,
                "source_line_hit_unit_count": 1 if ready else 0,
            },
            "blockers": [] if ready else [
                "fresh_engagement_adoption_metrics_missing_or_below_threshold",
                "project_source_roots_missing",
                "candidate_bound_source_line_hits_missing",
                "proved_exploit_impact_execution_manifest_missing",
            ],
            "proof_boundary": "test fixture",
        }
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def write_semantic_live_depth_fixture(
        self,
        ws: Path,
        *,
        count: int = 420,
        closed_count: int = 400,
    ) -> None:
        aud = ws / ".auditooor"
        aud.mkdir(exist_ok=True)
        relation_edges = []
        results = []
        proof_pairs = []
        for idx in range(count):
            relation_edges.append(
                {
                    "source_contract": f"Portal{idx}",
                    "source_function": "finalizeWithdrawal",
                    "kind": "bridge-finalizer-call",
                    "target": f"Bridge{idx}",
                    "target_type": f"Bridge{idx}",
                    "method": "finalizeWithdrawal",
                    "file": f"src/Portal{idx}.sol",
                    "line": idx + 10,
                }
            )
            same_block = idx < closed_count
            authority_block = "123" if same_block else "124"
            results.extend(
                [
                    {
                        "id": f"edge-{idx}",
                        "status": "pass",
                        "contract": f"Portal{idx}",
                        "evidence_class": "topology-relation",
                        "block": "123",
                    },
                    {
                        "id": f"authority-{idx}",
                        "status": "pass",
                        "contract": f"Bridge{idx}",
                        "evidence_class": "topology-relation",
                        "block": authority_block,
                    },
                ]
            )
            proof_pairs.append(
                {
                    "id": f"pair-{idx}",
                    "status": "proved" if same_block else "conflicting",
                    "row_ids": [f"edge-{idx}", f"authority-{idx}"],
                    "shared_block": "123" if same_block else "",
                    "pair_blocks": ["123"] if same_block else ["123", "124"],
                }
            )
        (aud / "semantic_graph.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.semantic_graph.v1",
                    "entrypoints": [],
                    "relation_edges": relation_edges,
                    "multi_hop_paths": [],
                }
            ),
            encoding="utf-8",
        )
        (ws / "live_topology_checks.json").write_text(
            json.dumps({"results": results, "proof_pairs": proof_pairs}),
            encoding="utf-8",
        )

    def test_impact_matrix_and_contracts(self):
        ws = self.make_ws()
        matrix = tool.render_impact_matrix(ws)
        self.assertEqual(matrix["status"], "ok")
        self.assertEqual(len(matrix["rows"]), 3)
        self.assertIn("evidence_class", matrix["rows"][0])
        self.assertIn("required_artifacts", matrix["rows"][0])
        self.assertIn("oos_traps", matrix["rows"][0])
        impacts = {row["impact"] for row in matrix["rows"]}
        self.assertNotIn("Single proof: 7 days", impacts)
        self.assertNotIn("Dual proof: 1 day", impacts)

        contracts = tool.render_impact_contracts(ws)
        self.assertEqual(contracts["contracts"][0]["verdict"], "in_scope_direct_submit")
        self.assertTrue((ws / ".auditooor" / "impact_contracts.md").is_file())

    def test_unproved_exact_impact_removes_severity_and_impact(self):
        ws = self.make_ws()
        cand = ws / "critical_hunt" / "candidates" / "c1.json"
        data = json.loads(cand.read_text(encoding="utf-8"))
        data["listed_impact_proven"] = False
        cand.write_text(json.dumps(data), encoding="utf-8")

        contracts = tool.render_impact_contracts(ws)
        row = contracts["contracts"][0]
        self.assertEqual(row["verdict"], "NOT_SUBMIT_READY")
        self.assertEqual(row["terminal_route"], "kill_or_reframe")
        self.assertEqual(row["severity"], "none")
        self.assertEqual(row["selected_impact"], "")
        self.assertEqual(row["original_selected_impact"], "Direct theft of user funds")

    def test_second_workspace_worklist_and_coverage_fields(self):
        ws = self.make_second_ws()
        (ws / ".auditooor" / "semantic_graph.json").write_text(
            json.dumps(
                {
                    "relation_edges": [
                        {
                            "file": "crates/node/src/ingress.rs",
                            "line": 45,
                            "source_contract": "NodeIngress",
                            "source_function": "processBlock",
                            "kind": "validation-call",
                            "receiver": "validator",
                            "receiver_source": "state-variable",
                            "target": "BlockValidator",
                            "target_type": "BlockValidator",
                            "method": "validate",
                            "evidence": "validator.validate(block)",
                        }
                    ],
                    "entrypoints": [
                        {
                            "contract": "NodeIngress",
                            "function": "processBlock",
                            "file": "crates/node/src/ingress.rs",
                            "line": 44,
                            "role": "peer",
                            "state_writes": ["processing"],
                            "external_calls": [],
                        }
                    ],
                    "multi_hop_paths": [
                        {
                            "path_id": "SG-MH-001",
                            "impact_family": "node_or_network_liveness",
                            "source_component": "NodeIngress.processBlock",
                            "mapped_stages": ["parser", "validation"],
                            "missing_stages": ["state_root"],
                            "evidence_edges": [
                                {"file": "crates/node/src/ingress.rs", "line": 44}
                            ],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        (ws / ".auditooor" / "semantic_detector_worklist.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.semantic_detector_worklist.v1",
                    "coverage_claim": "none_source_shape_only",
                    "advisory_only": True,
                    "promotion_allowed": False,
                    "tasks": [
                        {
                            "task_id": "SDW-MH-001",
                            "source_kind": "semantic_multi_hop_path",
                            "source_id": "SG-MH-001",
                            "source_component": "NodeIngress.processBlock",
                            "impact_family": "node_or_network_liveness",
                            "detector_task_kind": "semantic_multihop_detector_rewrite",
                            "candidate_detector_family": "node_or_network_liveness",
                            "submission_posture": "NOT_SUBMIT_READY",
                            "submit_status": "NOT_SUBMIT_READY",
                            "severity": "none",
                            "selected_impact": "",
                            "impact_contract_required": True,
                            "detector_query_bridge": {
                                "backend": "semantic_graph_query",
                                "coverage_claim": "none_source_shape_only",
                                "query_shape": "generic_multihop_source_path",
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        tool.render_impact_matrix(ws)
        tool.render_impact_contracts(ws)
        worklist = tool.render_impact_worklist(ws)
        self.assertEqual(worklist["status"], "ok")
        row = worklist["worklists"][0]
        self.assertEqual(row["impact_family"], "node_or_network_liveness")
        self.assertEqual(row["proof_class"], "executed_with_manifest")
        self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(row["submit_ready"])
        self.assertEqual(row["asset_category"], "Blockchain/DLT")
        self.assertEqual(row["required_evidence_class"], "executed_with_manifest")
        self.assertIn("resource_or_liveness_measurement", row["required_artifacts"])
        self.assertTrue(row["oos_traps"])
        self.assertTrue(row["emergency_downgrade_clauses"])
        self.assertEqual(row["component_count"], 2)
        self.assertIn("crates", row["relevant_source_roots"])
        self.assertEqual(
            row["semantic_source_components"]["components"][0]["component_id"],
            "NodeIngress.processBlock",
        )
        self.assertEqual(row["status"], "covered_by_candidate")
        handoff = row["source_review_handoff"]
        self.assertEqual(handoff["schema"], "auditooor.pr560.impact_source_review_handoff.v1")
        self.assertEqual(handoff["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(handoff["submit_ready"])
        self.assertEqual(handoff["semantic_detector_worklist_status"], "present")
        self.assertGreaterEqual(handoff["route_kind_counts"]["semantic_graph_query"], 1)
        self.assertGreaterEqual(handoff["route_kind_counts"]["detector_worklist_row"], 1)
        self.assertEqual(handoff["route_kind_counts"]["source_mining_packet"], 1)
        self.assertEqual(handoff["semantic_graph_query_result_status"], "missing_or_empty")
        self.assertEqual(handoff["query_result_accounting"]["candidate_query_count"], 2)
        query_routes = [r for r in handoff["routes"] if r["route_kind"] == "semantic_graph_query"]
        self.assertEqual({r["semantic_graph_query"]["source_collection"] for r in query_routes}, {"relation_edges", "multi_hop_paths"})
        self.assertTrue(all(r["query_result_status"] == "not_executed" for r in query_routes))
        detector_routes = [r for r in handoff["routes"] if r["route_kind"] == "detector_worklist_row"]
        self.assertEqual(detector_routes[0]["detector_task_id"], "SDW-MH-001")
        for route in handoff["routes"]:
            self.assertEqual(route["submission_posture"], "NOT_SUBMIT_READY")
            self.assertFalse(route["submit_ready"])
            self.assertFalse(route["promotion_allowed"])

        proc = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools" / "semantic-graph-query.py"),
                "--workspace",
                str(ws),
                "--impact-worklist",
                str(ws / ".auditooor" / "impact_family_worklists.json"),
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        refreshed = tool.render_impact_worklist(ws)
        refreshed_handoff = refreshed["worklists"][0]["source_review_handoff"]
        self.assertEqual(refreshed_handoff["semantic_graph_query_result_status"], "present")
        self.assertEqual(refreshed_handoff["query_result_accounting"]["executed_query_count"], 2)
        self.assertEqual(refreshed_handoff["query_result_accounting"]["matched_query_count"], 2)
        self.assertEqual(refreshed_handoff["query_result_accounting"]["matched_row_count"], 2)
        refreshed_query_routes = [
            r for r in refreshed_handoff["routes"] if r["route_kind"] == "semantic_graph_query"
        ]
        self.assertTrue(all(r["query_result_status"] == "executed" for r in refreshed_query_routes))
        self.assertTrue(all(r["query_match_count"] >= 1 for r in refreshed_query_routes))
        self.assertTrue(all(r["submission_posture"] == "NOT_SUBMIT_READY" for r in refreshed_query_routes))

        coverage = tool.render_coverage_inventory(ws)
        cov = coverage["rows"][0]
        self.assertEqual(coverage["status"], "ok")
        self.assertEqual(cov["coverage_status"], "covered")
        self.assertIn("crates", cov["scanned_roots"])
        self.assertTrue(cov["multi_hop_paths"])
        self.assertFalse(cov["blocked_commands_or_dependencies"])

    def test_no_verified_candidate_is_open_work_not_missing_artifact(self):
        ws = self.make_second_ws()
        # Remove the exact candidate but leave graph + scan artifacts present.
        for path in (ws / "critical_hunt" / "candidates").glob("*.json"):
            path.unlink()
        (ws / "detector_findings.json").unlink()
        tool.render_impact_matrix(ws)
        tool.render_impact_contracts(ws)

        worklist = tool.render_impact_worklist(ws)
        self.assertEqual(worklist["status"], "open_impact_family_work")
        self.assertEqual(
            worklist["blocker_category_counts"],
            {"open_impact_contract_or_family_execution": 1},
        )
        self.assertFalse(worklist["strict_blocking_categories"])
        row = worklist["worklists"][0]
        self.assertEqual(row["status"], "open_impact_family_work")
        self.assertIn("open_work:open_impact_contract_or_family_execution", row["blockers"])
        self.assertEqual(row["family_execution_status"], "open_impact_contract_or_family_execution")
        self.assertEqual(row["concrete_execution_item_target"], 50)
        self.assertGreaterEqual(row["concrete_execution_item_count"], 1)
        self.assertTrue(row["blocker_details"])
        self.assertEqual(row["blocker_details"][0]["category"], "open_impact_contract_or_family_execution")
        self.assertIn("source-mine", row["blocker_details"][0]["next_command"])
        handoff = row["source_review_handoff"]
        self.assertEqual(handoff["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(handoff["semantic_detector_worklist_status"], "missing_or_empty")
        self.assertGreaterEqual(handoff["route_kind_counts"]["semantic_graph_query"], 1)
        self.assertGreaterEqual(handoff["route_kind_counts"]["non_detectorizable_invariant_only"], 1)
        self.assertEqual(handoff["route_kind_counts"]["source_mining_packet"], 1)
        invariant_routes = [r for r in handoff["routes"] if r["route_kind"] == "non_detectorizable_invariant_only"]
        self.assertIn("source-proof", invariant_routes[0]["next_command"])

        coverage = tool.render_coverage_inventory(ws)
        cov = coverage["rows"][0]
        self.assertEqual(coverage["status"], "open_impact_family_work")
        self.assertEqual(cov["coverage_status"], "open_impact_family_work")
        self.assertEqual(
            coverage["blocker_category_counts"],
            {"open_impact_contract_or_family_execution": 1},
        )
        self.assertIn("blocker_details", cov)
        self.assertNotIn("blocked_named:missing_scan_artifacts", cov["blocked_commands_or_dependencies"])
        self.assertEqual(cov["scanner_coverage"], "required_scan_artifact_present")
        self.assertIn("detector_findings", cov["optional_scan_artifacts_missing"])
        self.assertFalse(tool.strict_failure_status(worklist["status"]))
        self.assertFalse(tool.strict_failure_status(coverage["status"]))

    def test_medium_reportable_family_without_candidate_stays_open_until_reduced(self):
        ws = self.make_second_ws()
        (ws / "SEVERITY_BLOCKCHAIN_DLT.md").write_text(
            "# Medium\n\n"
            "- Increasing network processing node resource consumption by at least 30%\n",
            encoding="utf-8",
        )
        for path in (ws / "critical_hunt" / "candidates").glob("*.json"):
            path.unlink()
        (ws / ".auditooor" / "semantic_graph.json").write_text(
            json.dumps(
                {
                    "multi_hop_paths": [
                        {
                            "path_id": "SG-MH-MEDIUM",
                            "impact_family": "node_resource_consumption",
                            "source_component": "NodeIngress.decode",
                            "mapped_stages": ["decode"],
                            "missing_stages": [],
                            "evidence_edges": [
                                {"file": "crates/node/src/ingress.rs", "line": 12}
                            ],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        tool.render_impact_matrix(ws)
        tool.render_impact_contracts(ws)

        worklist = tool.render_impact_worklist(ws)
        self.assertEqual(worklist["status"], "open_impact_family_work")
        row = worklist["worklists"][0]
        self.assertEqual(row["severity"], "Medium")
        self.assertEqual(row["family_execution_status"], "open_impact_contract_or_family_execution")
        self.assertIn("open_work:open_impact_contract_or_family_execution", row["blockers"])
        reduction = row["family_execution_reduction"]
        self.assertEqual(reduction["concrete_item_target"], 50)
        self.assertTrue(reduction["concrete_execution_items"])
        self.assertFalse(reduction["promotion_allowed"])
        self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")

        strict = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--workspace",
                str(ws),
                "--mode",
                "coverage-inventory",
                "--strict",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(strict.returncode, 0, strict.stdout + strict.stderr)

    def test_blockchain_coverage_requires_rust_scan_not_solidity_outputs(self):
        ws = self.make_second_ws()
        (ws / "detector_findings.json").unlink()
        (ws / ".auditooor" / "coverage_introspection.json").unlink()
        tool.render_impact_matrix(ws)
        tool.render_impact_contracts(ws)
        tool.render_impact_worklist(ws)

        coverage = tool.render_coverage_inventory(ws)
        row = coverage["rows"][0]
        self.assertEqual(row["required_scan_artifacts"], ["rust_scan"])
        self.assertEqual(row["missing_required_scan_artifacts"], [])
        self.assertIn("detector_findings", row["missing_optional_scan_artifacts"])
        self.assertNotIn("blocked_named:missing_scan_artifacts", row["blocked_commands_or_dependencies"])
        self.assertEqual(row["coverage_status"], "covered")

    def test_smart_contract_scan_report_satisfies_required_scan(self):
        ws = self.make_smart_contract_ws()
        tool.render_impact_matrix(ws)
        tool.render_impact_contracts(ws)
        tool.render_impact_worklist(ws)

        coverage = tool.render_coverage_inventory(ws)
        self.assertEqual(coverage["status"], "ok")
        row = coverage["rows"][0]
        self.assertEqual(row["asset_category"], "Smart Contract")
        self.assertEqual(row["required_scan_artifacts"], ["scan_report"])
        self.assertEqual(row["missing_required_scan_artifacts"], [])
        self.assertEqual(row["scanner_coverage"], "required_scan_artifact_present")
        self.assertFalse(tool.strict_failure_status(coverage["status"]))

    def test_smart_contract_source_only_workspace_does_not_require_rust_or_live_topology(self):
        ws = self.make_smart_contract_ws_without_optional_topology()
        tool.render_impact_matrix(ws)
        tool.render_impact_contracts(ws)
        tool.render_impact_worklist(ws)

        coverage = tool.render_coverage_inventory(ws)
        self.assertEqual(coverage["status"], "ok")
        row = coverage["rows"][0]
        self.assertEqual(row["required_graph_artifacts"], ["semantic_graph", "invariant_ledger"])
        self.assertEqual(row["missing_required_graph_artifacts"], [])
        self.assertEqual(row["scan_artifact_details"]["scan_report"]["satisfied_by"], str(ws / "scan_report.md"))
        self.assertEqual(row["generated_graph_files"]["rust_source_graph"], "missing")
        self.assertEqual(row["generated_graph_files"]["live_topology"], "missing")
        self.assertEqual(row["generated_graph_files"]["deployment_topology"], "missing")
        self.assertFalse(row["blocked_commands_or_dependencies"])

    def test_smart_contract_missing_all_scan_reports_is_required_scan_blocker(self):
        ws = self.make_smart_contract_ws_without_optional_topology()
        (ws / "scan_report.md").unlink()
        tool.render_impact_matrix(ws)
        tool.render_impact_contracts(ws)
        tool.render_impact_worklist(ws)

        coverage = tool.render_coverage_inventory(ws)
        self.assertEqual(coverage["status"], "blocked_missing_required_artifacts")
        row = coverage["rows"][0]
        self.assertEqual(row["required_scan_artifacts"], ["scan_report"])
        self.assertEqual(row["missing_required_scan_artifacts"], ["scan_report"])
        self.assertIn("blocked_named:missing_required_scan_artifacts", row["blocked_commands_or_dependencies"])
        self.assertTrue(tool.strict_failure_status(coverage["status"]))

    def test_closure_emits_required_artifacts(self):
        ws = self.make_ws()
        generated = self.write_generated_invariants(ws)
        payload = tool.render_closure(ws, "automation_closure")
        self.assertIn(payload["status"], {"ok", "blocked_named"})
        for name in (
            "program_impact_matrix",
            "impact_contracts",
            "impact_family_worklists",
            "tool_coverage_inventory",
            "agent_output_inventory",
            "agent_recall",
            "impact_analysis_queue",
            "coverage_inventory",
            "harness_tasks",
            "pr560_next_actions",
        ):
            self.assertTrue(Path(payload["artifacts"][name]).is_file(), name)
        self.assertEqual(payload["statuses"]["invariant_discovery"], "advisory_missing_invariants")
        self.assertEqual(payload["artifacts"]["generated_invariants"], str(generated))
        self.assertIn("invariant_discovery", payload["next_commands"])
        self.assertTrue(payload["advisory"]["invariant_discovery"]["advisory"])

    def test_closure_missing_generated_invariants_is_advisory(self):
        ws = self.make_second_ws()
        payload = tool.render_closure(ws, "automation_closure")
        self.assertEqual(payload["statuses"]["invariant_discovery"], "advisory_missing_generated_invariants")
        self.assertTrue(payload["artifacts"]["generated_invariants"].endswith(".auditooor/generated_invariants.json"))
        status_without_sidecar = payload["status"]
        self.write_generated_invariants(ws, missing=0)
        with_sidecar = tool.render_closure(ws, "automation_closure")
        self.assertEqual(with_sidecar["statuses"]["invariant_discovery"], "advisory_all_generated_invariants_accepted")
        self.assertEqual(with_sidecar["status"], status_without_sidecar)

    def test_pr560_next_actions_merges_and_sorts_open_queues(self):
        ws = self.make_ws()
        aud = ws / ".auditooor"
        aud.mkdir(exist_ok=True)
        (aud / "coverage_inventory.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "impact_id": "critical-001",
                            "impact": "Direct theft of user funds",
                            "coverage_status": "blocked_missing_required_artifacts",
                            "blocker_details": [
                                {
                                    "category": "missing_required_artifact",
                                    "artifact": "detector_findings.json",
                                    "next_command": "make coverage-inventory WS=<workspace>",
                                    "reason": "missing detector findings",
                                }
                            ],
                        },
                        {
                            "impact_id": "critical-002",
                            "impact": "Network not being able to confirm new transactions",
                            "coverage_status": "open_impact_family_work",
                            "open_work_categories": ["open_high_impact_candidate_absence"],
                            "next_command": "make source-mine WS=<workspace> IMPACT_ID=critical-002",
                        },
                    ],
                    "status": "blocked_missing_required_artifacts",
                }
            ),
            encoding="utf-8",
        )
        (aud / "harness_tasks.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "harness_task_id": "HT-1",
                            "candidate_id": "C-HARNESS",
                            "status": "blocked_missing_impact_contract",
                            "impact_contract_work_status": "impact_contract_suggested",
                            "source_artifact": "agent_outputs/harness.md",
                            "next_command": "make impact-contract-check WS=<workspace> # CANDIDATE=C-HARNESS",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (aud / "impact_analysis_queue.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "queue_id": "IA-1",
                            "action_type": "exact_impact_candidate",
                            "agent_output": "agent_outputs/impact.md",
                            "next_command": "make impact-contract-check WS=<workspace>",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (aud / "source_proof_tasks.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "source_proof_task_id": "SP-1",
                            "status": "blocked_missing_citations",
                            "source_artifact": "agent_outputs/source.md",
                            "next_command": "make source-proof-record WS=<workspace>",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (aud / "agent_output_inventory.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "verification_task_id": "AO-1",
                            "path": "agent_outputs/verify.md",
                            "local_verification_status": "not_verified",
                            "next_command": "make agent-recall WS=<workspace>",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        self.write_generated_invariants(ws, missing=1)

        payload = tool.render_pr560_next_actions(ws)
        self.assertEqual(payload["schema"], "auditooor.pr560.next_actions.v1")
        self.assertEqual(payload["status"], "blocked_strict_next_actions")
        categories = [row["category"] for row in payload["rows"]]
        self.assertEqual(
            categories,
            [
                "strict_blocker",
                "open_impact_family",
                "harness_impact_work",
                "impact_analysis",
                "source_proof",
                "agent_verification",
                "invariant_queue",
            ],
        )
        self.assertTrue(payload["rows"][0]["strict_blocking"])
        self.assertFalse(any(row["submit_ready"] for row in payload["rows"]))
        self.assertTrue((aud / "pr560_next_actions.json").is_file())
        self.assertTrue((aud / "pr560_next_actions.md").is_file())

    def test_pr560_next_actions_cli_json(self):
        ws = self.make_ws()
        aud = ws / ".auditooor"
        aud.mkdir(exist_ok=True)
        (aud / "coverage_inventory.json").write_text(
            json.dumps({"rows": [], "status": "ok"}),
            encoding="utf-8",
        )
        (aud / "harness_tasks.json").write_text(
            json.dumps({"rows": [], "status": "empty_no_harness_tasks"}),
            encoding="utf-8",
        )
        (aud / "impact_analysis_queue.json").write_text(
            json.dumps({"rows": [], "status": "empty_no_blocked_agent_recall_rows"}),
            encoding="utf-8",
        )
        (aud / "source_proof_tasks.json").write_text(
            json.dumps({"rows": [], "status": "empty_no_source_proof_tasks"}),
            encoding="utf-8",
        )
        (aud / "agent_output_inventory.json").write_text(
            json.dumps({"rows": [], "status": "empty_no_agent_outputs"}),
            encoding="utf-8",
        )
        self.write_generated_invariants(ws, missing=0)
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--workspace",
                str(ws),
                "--mode",
                "pr560-next-actions",
                "--json",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "empty_no_pr560_next_actions")
        self.assertEqual(payload["summary"]["row_count"], 0)

    def test_pr560_next_actions_carries_semantic_detector_adjudication_rows(self):
        ws = self.make_ws()
        aud = ws / ".auditooor"
        aud.mkdir(exist_ok=True)
        for name, status in (
            ("coverage_inventory.json", "ok"),
            ("harness_tasks.json", "empty_no_harness_tasks"),
            ("impact_analysis_queue.json", "empty_no_blocked_agent_recall_rows"),
            ("source_proof_tasks.json", "empty_no_source_proof_tasks"),
            ("agent_output_inventory.json", "empty_no_agent_outputs"),
        ):
            (aud / name).write_text(json.dumps({"rows": [], "status": status}), encoding="utf-8")
        self.write_generated_invariants(ws, missing=0)
        (aud / "semantic_detector_adjudication.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.semantic_detector_adjudication.v1",
                    "advisory_only": True,
                    "promotion_allowed": False,
                    "detector_rewrite_briefs": [
                        {
                            "brief_id": "SDA-DET-001",
                            "candidate_detector_family": "verifier_relation",
                            "exact_status": "detector_rewrite_brief",
                            "next_command": "make semantic-detector-adjudication WS=<workspace> # detector",
                        }
                    ],
                    "fixture_requirements": [
                        {
                            "fixture_id": "SDA-FIX-001",
                            "candidate_detector_family": "verifier_relation",
                            "next_command": "make semantic-detector-adjudication WS=<workspace> # fixture",
                        }
                    ],
                    "non_detectorizable_rows": [
                        {
                            "row_id": "SDA-ND-001",
                            "reason": "source_shape_too_generic_for_detector_rewrite",
                            "next_command": "make source-proof-task-queue WS=<workspace>",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        payload = tool.render_pr560_next_actions(ws)
        self.assertEqual(payload["status"], "open_next_actions")
        self.assertEqual(payload["summary"]["by_category"]["semantic_detector"], 3)
        self.assertEqual({row["exact_status"] for row in payload["rows"]}, {
            "detector_rewrite_brief",
            "fixture_requirement",
            "non_detectorizable",
        })
        self.assertFalse(any(row["strict_blocking"] for row in payload["rows"]))
        self.assertFalse(any(row["submit_ready"] for row in payload["rows"]))

    def test_pr560_next_actions_carries_provider_local_verification_rows(self):
        ws = self.make_ws()
        aud = ws / ".auditooor"
        aud.mkdir(exist_ok=True)
        for name, status in (
            ("coverage_inventory.json", "ok"),
            ("harness_tasks.json", "empty_no_harness_tasks"),
            ("impact_analysis_queue.json", "empty_no_blocked_agent_recall_rows"),
            ("source_proof_tasks.json", "empty_no_source_proof_tasks"),
            ("agent_output_inventory.json", "empty_no_agent_outputs"),
        ):
            (aud / name).write_text(json.dumps({"rows": [], "status": status}), encoding="utf-8")
        self.write_generated_invariants(ws, missing=0)
        provider_dir = ws / ".audit_logs" / "pr560_worker_at"
        provider_dir.mkdir(parents=True)
        (provider_dir / "local_provider_verification_queue.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.live_provider_local_verification_queue.v1",
                    "advisory_only": True,
                    "promotion_authority": False,
                    "rows": [
                        {
                            "queue_id": "LPV-GREP-001",
                            "task_id": "worker-at-001",
                            "route": "local_grep",
                            "title": "path-filtering: verify provider-suggested source shape",
                            "next_command": "rg -n 'def _skip_path' tools",
                            "minimum_followup_check": "Confirm local grep before fixture work",
                            "submit_ready": False,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        payload = tool.render_pr560_next_actions(ws)
        self.assertEqual(payload["status"], "open_next_actions")
        self.assertEqual(payload["summary"]["by_category"]["provider_local_verification"], 1)
        row = payload["rows"][0]
        self.assertEqual(row["category"], "provider_local_verification")
        self.assertEqual(row["exact_status"], "local_grep")
        self.assertFalse(row["strict_blocking"])
        self.assertFalse(row["submit_ready"])

    def test_pr560_next_actions_skips_terminal_provider_local_verification_rows(self):
        ws = self.make_ws()
        aud = ws / ".auditooor"
        aud.mkdir(exist_ok=True)
        for name, status in (
            ("coverage_inventory.json", "ok"),
            ("harness_tasks.json", "empty_no_harness_tasks"),
            ("impact_analysis_queue.json", "empty_no_blocked_agent_recall_rows"),
            ("source_proof_tasks.json", "empty_no_source_proof_tasks"),
            ("agent_output_inventory.json", "empty_no_agent_outputs"),
        ):
            (aud / name).write_text(json.dumps({"rows": [], "status": status}), encoding="utf-8")
        self.write_generated_invariants(ws, missing=0)
        provider_dir = ws / ".audit_logs" / "pr560_worker_at"
        provider_dir.mkdir(parents=True)
        (provider_dir / "local_provider_verification_queue.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.live_provider_local_verification_queue.v1",
                    "advisory_only": True,
                    "promotion_authority": False,
                    "rows": [
                        {
                            "queue_id": "LPV-GREP-001",
                            "task_id": "worker-at-001",
                            "route": "local_grep",
                            "title": "path-filtering: verify provider-suggested source shape",
                            "next_command": "rg -n 'def _skip_path' tools",
                            "minimum_followup_check": "Confirm local grep before fixture work",
                            "submit_ready": False,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        closure_dir = ws / ".audit_logs" / "pr560_worker_ax"
        closure_dir.mkdir(parents=True)
        (closure_dir / "provider_local_verification_closure.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.provider_local_verification_closure.v1",
                    "advisory_only": True,
                    "promotion_authority": False,
                    "severity": "none",
                    "submit_ready": False,
                    "row_count": 1,
                    "terminal_row_count": 1,
                    "rows": [
                        {
                            "queue_id": "LPV-GREP-001",
                            "task_id": "worker-at-001",
                            "terminal": True,
                            "terminal_state": "verified_source_shape",
                            "severity": "none",
                            "submit_ready": False,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        payload = tool.render_pr560_next_actions(ws)
        self.assertEqual(payload["summary"]["by_category"].get("provider_local_verification", 0), 0)
        self.assertFalse(any(row["category"] == "provider_local_verification" for row in payload["rows"]))

    def test_pr560_local_progress_generates_doc_from_next_actions(self):
        ws = self.make_ws()
        aud = ws / ".auditooor"
        aud.mkdir(exist_ok=True)
        (aud / "pr560_next_actions.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "next_action_id": "pr560-next-001",
                            "category": "strict_blocker",
                            "source_artifact": "detector_findings.json",
                            "exact_status": "missing_required_artifact",
                            "next_command": "make coverage-inventory WS=<workspace>",
                            "strict_blocking": True,
                            "submit_ready": False,
                        },
                        {
                            "next_action_id": "pr560-next-002",
                            "category": "harness_impact_work",
                            "source_artifact": "agent_outputs/harness.md",
                            "exact_status": "impact_contract_suggested",
                            "next_command": "make impact-contract-check WS=<workspace>",
                            "strict_blocking": False,
                            "submit_ready": False,
                        },
                    ],
                    "summary": {
                        "row_count": 2,
                        "strict_blocking": 1,
                        "by_category": {
                            "strict_blocker": 1,
                            "open_impact_family": 0,
                            "harness_impact_work": 1,
                            "impact_analysis": 0,
                            "source_proof": 0,
                            "agent_verification": 0,
                            "invariant_queue": 0,
                        },
                    },
                }
            ),
            encoding="utf-8",
        )

        payload = tool.render_pr560_local_progress(ws)
        self.assertEqual(payload["schema"], "auditooor.pr560.local_batch_progress.v1")
        self.assertEqual(payload["remaining_queue_count"], 2)
        self.assertEqual(len(payload["strict_blockers"]), 1)
        self.assertGreaterEqual(payload["completed_checklist_count"], 92)
        self.assertEqual(payload["completed_implementation_count"], payload["completed_checklist_count"])
        self.assertEqual(payload["completed_implementation_status"], "complete_local_only")
        self.assertGreaterEqual(payload["lane_output_count"], 26)
        self.assertGreaterEqual(payload["ready_lane_output_count"], 26)
        self.assertEqual(payload["lane_item_total"], payload["completed_checklist_count"])
        self.assertTrue(payload["lane_item_count_matches_completed"])
        self.assertEqual(payload["completed_checklist_count"], len(tool.LOCAL_BATCH_COMPLETED_ITEMS))
        self.assertEqual(payload["bundle_readiness"]["status"], "blocked_strict_next_actions")
        self.assertFalse(payload["bundle_readiness"]["ready_for_eventual_pr"])
        self.assertEqual(payload["remaining_advisory_counts"]["harness_impact_work"], 1)
        self.assertEqual(payload["remaining_advisory_count"], 1)
        self.assertEqual(payload["resolved_advisory_count"], 0)
        self.assertEqual(payload["open_advisory_counts_before_reconciliation"]["harness_impact_work"], 1)
        self.assertIn("foundry_trial_readiness", payload)
        self.assertEqual(payload["foundry_trial_readiness"]["migration_state"], "planned_not_executed")
        self.assertEqual(payload["foundry_trial_readiness"]["fixture_count"], 4)
        self.assertTrue(payload["bundle_readiness"]["consistency_checks"]["lane_item_total_matches_completed"])
        self.assertTrue(payload["bundle_readiness"]["consistency_checks"]["required_tests_present"])
        self.assertTrue(payload["bundle_readiness"]["consistency_checks"]["required_changed_files_present"])
        progress = self.progress_docs_dir / "PR560_LOCAL_BATCH_PROGRESS.md"
        self.assertTrue(progress.is_file())
        text = progress.read_text(encoding="utf-8")
        self.assertIn("Lane Outputs", text)
        self.assertIn("Bundle Readiness", text)
        self.assertIn("Implementation Progress", text)
        self.assertIn("Readiness Blockers", text)
        self.assertIn("Remaining Advisory Counts", text)
        self.assertIn("Resolved Advisory Counts", text)
        self.assertIn("Advisory Reconciliation Sources", text)
        self.assertIn("/private/tmp/auditooor-pr560-scan-artifacts", text)
        self.assertIn("/private/tmp/auditooor-pr560-invariant-queue", text)
        self.assertIn("A5", text)
        self.assertIn("B5", text)
        self.assertIn("D5", text)
        self.assertIn("E5", text)
        self.assertIn("C7", text)
        self.assertIn("C9", text)
        self.assertIn("Impact-first gate accounting slice", text)
        self.assertIn("C10", text)
        self.assertIn("Generated artifact impact-first gate accounting", text)
        self.assertIn("C11", text)
        self.assertIn("ReCon/Chimera and promotion seam gate accounting", text)
        self.assertIn("C12", text)
        self.assertIn("Submission factory, deep replay, and provider seam gate accounting", text)
        self.assertIn("C13", text)
        self.assertIn("Semantic worklist and submission-output gate accounting", text)
        self.assertIn("Foundry Trial-Readiness Progress", text)
        self.assertIn("Remaining Queue Counts", text)
        self.assertIn("pr560-next-001", text)
        progress_json = self.progress_docs_dir / "PR560_LOCAL_BATCH_PROGRESS.json"
        self.assertTrue(progress_json.is_file())
        progress_payload = json.loads(progress_json.read_text(encoding="utf-8"))
        self.assertEqual(progress_payload["lane_outputs"][0]["lane_id"], "A2")
        c9 = {row["lane_id"]: row for row in progress_payload["lane_outputs"]}["C9"]
        self.assertEqual(c9["item_count"], 7)
        self.assertEqual(c9["closure_claim"], "progress_reduced_only_priority_1_not_closed")
        self.assertIn("mining brief gate", c9["covered_gates"])
        self.assertIn("docs/validation", c9["covered_gates"])
        c10 = {row["lane_id"]: row for row in progress_payload["lane_outputs"]}["C10"]
        self.assertEqual(c10["item_count"], 2)
        self.assertEqual(c10["closure_claim"], "progress_reduced_only_priority_1_not_closed")
        self.assertIn("auto-draft-generator draft/PoC write gate", c10["covered_gates"])
        self.assertIn("harness-scaffold-emitter scaffold write gate", c10["covered_gates"])
        c11 = {row["lane_id"]: row for row in progress_payload["lane_outputs"]}["C11"]
        self.assertEqual(c11["item_count"], 4)
        self.assertEqual(c11["closure_claim"], "progress_reduced_only_priority_1_not_closed")
        self.assertIn("detector-promotion Program Impact Mapping gate", c11["covered_gates"])
        self.assertIn("source-mining survivor impact-contract gate", c11["covered_gates"])
        self.assertIn("Chimera scaffold impact-contract gate", c11["covered_gates"])
        self.assertIn("ReCon forge replay impact-contract gate", c11["covered_gates"])
        self.assertIn("python3 -m unittest tools.tests.test_recon_log_bridge", c11["tests"])
        self.assertIn("python3 -m unittest tools.tests.test_chimera_scaffold", c11["tests"])
        self.assertIn("python3 -m unittest tools.tests.test_findings_to_pattern.PromotionGateTests", c11["tests"])
        c12 = {row["lane_id"]: row for row in progress_payload["lane_outputs"]}["C12"]
        self.assertEqual(c12["item_count"], 5)
        self.assertEqual(c12["closure_claim"], "progress_reduced_only_priority_1_not_closed")
        self.assertIn("submission-factory impact-contract refusal", c12["covered_gates"])
        self.assertIn("deep replay impact-contract gate", c12["covered_gates"])
        self.assertIn("source-mining provider input-only routing", c12["covered_gates"])
        self.assertIn("auto-draft-generator machine-detected gate", c12["covered_gates"])
        self.assertIn("harness-scaffold-emitter machine-detected gate", c12["covered_gates"])
        c13 = {row["lane_id"]: row for row in progress_payload["lane_outputs"]}["C13"]
        self.assertEqual(c13["item_count"], 8)
        self.assertEqual(c13["closure_claim"], "progress_reduced_only_priority_1_not_closed")
        self.assertIn("provider/source-mining dispatch preflight gate", c13["covered_gates"])
        self.assertIn("Kimi source-extract captured advisory provider-assist gate", c13["covered_gates"])
        self.assertIn("Minimax adversarial-kill captured advisory provider-assist gate", c13["covered_gates"])
        self.assertIn("semantic-detector-worklist advisory bridge", c13["covered_gates"])
        self.assertIn("typed multihop semantic graph worklist inputs", c13["covered_gates"])
        self.assertIn("submission-factory proof-artifact and tier gate", c13["covered_gates"])
        self.assertIn("submission-packager proof-artifact and High+ evidence-matrix gate", c13["covered_gates"])
        self.assertIn("docs/PR560_LOCAL_BATCH_PROGRESS.json", progress_payload["changed_files"])
        self.assertTrue((aud / "pr560_local_batch_progress.json").is_file())

    def test_impact_first_progress_lane_does_not_close_known_limitation(self):
        ws = self.make_ws()
        old_root = tool.ROOT
        with tempfile.TemporaryDirectory(prefix="automation_closure_impact_first_reduced_") as td:
            repo = Path(td)
            (repo / "docs").mkdir()
            (repo / "tools" / "tests").mkdir(parents=True)
            (repo / "docs" / "KNOWN_LIMITATIONS.md").write_text("# Known\n", encoding="utf-8")
            (repo / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.known_limitations_burndown_map.v1",
                        "rows": [
                            {
                                "limitation_id": "priority-1",
                                "priority_group": "priority_1",
                                "title": "Impact-first work gating",
                                "terminal_state": "deferred_with_owner",
                                "evidence": ["tools/critical-hunt.py"],
                                "next_command": "make impact-contract-check WS=<workspace> STRICT=1",
                                "stop_condition": "No missing-proof candidate keeps selected impact or reportable severity.",
                                "stop_condition_met": False,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (repo / "tools" / "critical-hunt.py").write_text(
                "def _load_exact_impact_contracts(): pass\n"
                "impact_contracts.json missing_exact_impact_contract advisory_missing_exact_impact_contract\n",
                encoding="utf-8",
            )
            (repo / "tools" / "paste-ready-generator.py").write_text(
                "def _impact_contract_refusal_reasons(): pass\n"
                "validate_impact_contract_text matching workspace impact_contract proof is missing listed_impact_proven\n",
                encoding="utf-8",
            )
            (repo / "tools" / "submission-packager.py").write_text(
                "def _impact_mapping_packager_refusal(): pass\n"
                "build_impact_mapping_manifest Program Impact Mapping promotion contract refused packaging "
                "packager_should_refuse proof_artifact required_for_high_plus ready_verdict\n",
                encoding="utf-8",
            )
            (repo / "tools" / "swarm-orchestrator.py").write_text(
                "def mining_brief_impact_contract_gate(): pass\n"
                "dispatch_blocked_missing_impact_contract REFUSING dispatch blocked_missing_impact_contract\n",
                encoding="utf-8",
            )
            (repo / "tools" / "mining-brief-generator.py").write_text(
                "def ranked_row_requires_impact_contract(row): pass\n"
                "def impact_contract_id_from_row(row): pass\n"
                "impact_contract_required blocked_missing_impact_contract VERDICT=blocked_missing_impact_contract\n",
                encoding="utf-8",
            )
            (repo / "tools" / "poc-scaffold.py").write_text(
                "def require_locked_impact_contract(candidate, workspace): pass\n"
                "blocked_missing_impact_contract listed_impact_proven=true exact_impact_row\n",
                encoding="utf-8",
            )
            (repo / "tools" / "auto-draft-generator.py").write_text(
                "def require_locked_impact_contract(): pass\n"
                "auto-draft-generator requires before writing drafts or PoC scaffolds "
                "listed_impact_proven=true\n",
                encoding="utf-8",
            )
            (repo / "tools" / "harness-scaffold-emitter.py").write_text(
                "def require_locked_impact_contract(): pass\n"
                "blocked_missing_impact_contract listed_impact_proven=true attempt_manifest\n",
                encoding="utf-8",
            )
            (repo / "tools" / "submission-factory.py").write_text(
                "def impact_contract_refusal(): pass\n"
                "validate_impact_contract_text impact_contract_invalid:listed_impact_not_proven "
                "severity_claim_not_backed_by_selected_impact_tier proof_artifact_missing "
                "proof_artifact_not_found selected_impact_not_exact_listed_sentence\n",
                encoding="utf-8",
            )
            (repo / "tools" / "deep-counterexample-replay-scaffold.py").write_text(
                "def locked_impact_contract(): pass\n"
                "deep replay scaffolds require record.impact_contract_id "
                "listed_impact_proven=true Do not promote until the Forge replay executes\n",
                encoding="utf-8",
            )
            (repo / "tools" / "promote-typed-candidate.py").write_text(
                "def _impact_contract_report(): pass\n"
                "impact_contract_required program_impact_mapping_unresolved impact_unresolved\n",
                encoding="utf-8",
            )
            (repo / "tools" / "source-mining-campaign.py").write_text(
                "submission_posture NOT_SUBMIT_READY impact_contract_required "
                "source_mining_generated_hypothesis GENERATED_HYPOTHESIS\n"
                "def build_outcome_routing_manifest(): pass\nprovider_rows "
                "input_only_local_verification_required llm_corpus_mining_is_proof "
                "outcome_calibrated_routing.json\n"
                "dispatch-preflight.py --template source-extract --template adversarial-kill "
                "Never auto-promote a candidate\n"
                "provider=\"kimi\" task_type=\"source-extract\" _record_packet_done "
                "kimi_candidates.json KEEP_FOR_LOCAL_VERIFICATION\n"
                "provider=\"minimax\" task_type=\"adversarial-kill\" _record_packet_done "
                "minimax_challenges.json rejected.json\n",
                encoding="utf-8",
            )
            (repo / "tools" / "dispatch-preflight.py").write_text(
                "MANDATORY_TASK_TYPES source-extract adversarial-kill "
                "BYPASS_DISPATCH_PREFLIGHT_REASON AUDITOOOR_DISPATCH_PREFLIGHT_OK\n",
                encoding="utf-8",
            )
            (repo / "tools" / "llm-dispatch.py").write_text(
                "dispatch-preflight-required AUDITOOOR_DISPATCH_PREFLIGHT_OK "
                "BYPASS_DISPATCH_PREFLIGHT_REASON\n",
                encoding="utf-8",
            )
            (repo / "tools" / "semantic-graph.py").write_text(
                "def evidence_edges_from_body(): pass\n"
                "def build_multi_hop_paths(): pass\n"
                "impact_family_for_path mapped_stages source_reader_coverage "
                "route semantic path to exact-impact candidate or mark non-detectorizable\n",
                encoding="utf-8",
            )
            (repo / "tools" / "semantic-detector-worklist.py").write_text(
                "SCHEMA_VERSION = \"auditooor.semantic_detector_worklist.v1\"\n"
                "semantic_relation_detector_rewrite semantic_multihop_detector_rewrite "
                "submission_posture\": \"NOT_SUBMIT_READY\" impact_contract_required\": True "
                "promotion_allowed\": False none_source_shape_only\n",
                encoding="utf-8",
            )
            (repo / "tools" / "chimera-scaffold.py").write_text(
                "def _require_locked_impact_contract(): pass\n"
                "blocked_missing_impact_contract listed_impact_proven=true submit_ready\n",
                encoding="utf-8",
            )
            (repo / "tools" / "chimera-ledger-scaffold.py").write_text(
                "blocked_missing_impact_contract impact_contract_required impact_contract_id\n",
                encoding="utf-8",
            )
            (repo / "tools" / "recon-log-bridge.py").write_text(
                "def _locked_impact_contract(): pass\n"
                "--forge-test-out requires --impact-contract-id impact_contract_blocker "
                "blocked_missing_impact_contract\n",
                encoding="utf-8",
            )
            (repo / "tools" / "corpus-detectorization-inventory.py").write_text(
                "ReCon/deep-counterexample source-mining survivors "
                "submission_posture=\"NOT_SUBMIT_READY\" impact_contract_required=true "
                "source-mining-harness-task\n",
                encoding="utf-8",
            )
            (repo / "docs" / "TOOL_STATUS.md").write_text(
                "make critical-hunt WS=... tools/poc-scaffold.py --plan-json "
                "locked to a proved exact impact contract make docs-check\n",
                encoding="utf-8",
            )
            (repo / "docs" / "WORKFLOW.md").write_text(
                "selected source-mining briefs that inherited `blocked_missing_impact_contract`\n",
                encoding="utf-8",
            )
            tool.ROOT = repo
            try:
                payload = tool.render_known_limitations_burndown(ws)
            finally:
                tool.ROOT = old_root

        row = payload["rows"][0]
        self.assertEqual(row["terminal_state"], "progress_reduced_with_remaining_paths")
        self.assertFalse(row["stop_condition_met"])
        self.assertEqual(row["reduction_status"], "reduced_detected_paths_not_closed")
        self.assertIn("mining-brief", row["covered_paths_after_560"])
        self.assertIn("poc-scaffold-plan-json", row["covered_paths_after_560"])
        self.assertIn("auto-draft-generator", row["covered_paths_after_560"])
        self.assertIn("harness-scaffold-emitter", row["covered_paths_after_560"])
        self.assertIn("submission-factory", row["covered_paths_after_560"])
        self.assertIn("deep-counterexample-replay-scaffold", row["covered_paths_after_560"])
        self.assertIn("detector-promotion", row["covered_paths_after_560"])
        self.assertIn("source-mining-survivor", row["covered_paths_after_560"])
        self.assertIn("source-mining-provider-routing", row["covered_paths_after_560"])
        self.assertIn("source-mining-provider-preflight", row["covered_paths_after_560"])
        self.assertIn("source-mining-kimi-source-extract-advisory", row["covered_paths_after_560"])
        self.assertIn("source-mining-minimax-adversarial-kill-advisory", row["covered_paths_after_560"])
        self.assertIn("semantic-graph-typed-multihop", row["covered_paths_after_560"])
        self.assertIn("semantic-detector-worklist", row["covered_paths_after_560"])
        self.assertIn("submission-factory-proof-artifact-tier", row["covered_paths_after_560"])
        self.assertIn("submission-packager-proof-artifact-tier", row["covered_paths_after_560"])
        self.assertIn("chimera-scaffold", row["covered_paths_after_560"])
        self.assertIn("recon-log-bridge", row["covered_paths_after_560"])
        self.assertIn("docs-validation", row["covered_paths_after_560"])
        self.assertIn("generic-harness-planning", row["remaining_unproven_paths_after_560"])

    def test_pr560_local_progress_cli_json(self):
        ws = self.make_ws()
        aud = ws / ".auditooor"
        aud.mkdir(exist_ok=True)
        (aud / "pr560_next_actions.json").write_text(
            json.dumps({"rows": [], "summary": {"row_count": 0, "by_category": {}}}),
            encoding="utf-8",
        )
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--workspace",
                str(ws),
                "--mode",
                "pr560-local-progress",
                "--json",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "ready_for_operator_batch_integration")
        self.assertEqual(payload["remaining_queue_count"], 0)
        self.assertTrue(payload["bundle_readiness"]["ready_for_eventual_pr"])
        self.assertEqual(payload["bundle_readiness"]["refusal_reasons"], [])

    def test_pr560_integration_readiness_generates_split_plan_and_guards(self):
        ws = self.make_ws()
        aud = ws / ".auditooor"
        aud.mkdir(exist_ok=True)
        (aud / "pr560_next_actions.json").write_text(
            json.dumps({"rows": [], "summary": {"row_count": 0, "by_category": {}}}),
            encoding="utf-8",
        )

        payload = tool.render_pr560_integration_readiness(ws)

        self.assertEqual(payload["schema"], "auditooor.pr560.integration_readiness.v1")
        self.assertEqual(payload["completed_worker_ad_item_count"], 9)
        self.assertGreaterEqual(payload["completed_worker_aj_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_ap_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_ao_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_ar_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_aw_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_bb_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_bg_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_bl_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_bq_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_bv_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_ca_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_cf_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_ck_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_cv_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_cw_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_db_item_count"], 150)
        self.assertGreaterEqual(payload["completed_worker_dg_item_count"], 150)
        self.assertLessEqual(payload["completed_worker_dg_item_count"], 300)
        self.assertGreaterEqual(payload["completed_worker_dl_item_count"], 150)
        self.assertLessEqual(payload["completed_worker_dl_item_count"], 300)
        self.assertGreaterEqual(payload["completed_worker_dg_item_count"], 150)
        self.assertLessEqual(payload["completed_worker_dg_item_count"], 300)
        self.assertGreaterEqual(payload["completed_worker_dl_item_count"], 150)
        self.assertLessEqual(payload["completed_worker_dl_item_count"], 300)
        self.assertEqual(payload["automation_id"], "auditooor-watchdog-closure-loop")
        self.assertTrue(payload["local_only"])
        self.assertFalse(payload["github_actions_opened"])
        self.assertFalse(payload["git_operations_performed"]["commit"])
        self.assertFalse(payload["git_operations_performed"]["push"])
        self.assertFalse(payload["git_operations_performed"]["pull_request"])
        self.assertFalse(payload["git_operations_performed"]["merge"])
        self.assertEqual(payload["readiness_verdict"], "ready_for_operator_review")
        self.assertEqual(payload["proof_claims"]["full_scanner_coverage"], "not_claimed")
        self.assertEqual(payload["proof_claims"]["live_provider_proof"], "not_claimed")
        self.assertTrue(payload["provider_live_consent_blocker"]["blocked"])
        self.assertTrue(payload["validation"]["valid"])
        self.assertTrue(payload["validation"]["required_slice_ids_present"])
        self.assertTrue(payload["validation"]["no_live_provider_proof_claimed"])
        self.assertTrue(payload["validation"]["no_full_coverage_claimed"])
        self.assertTrue(payload["validation"]["exactly_one_generated_artifact_slice"])
        self.assertTrue(payload["validation"]["per_slice_test_matrix_present"])
        self.assertTrue(payload["validation"]["per_slice_stop_conditions_present"])
        self.assertTrue(payload["validation"]["local_git_github_operations_clear"])
        self.assertTrue(payload["validation"]["proof_claims_not_claimed"])
        self.assertTrue(payload["validation"]["required_not_closed_boundaries_present"])
        self.assertTrue(payload["validation"]["operator_handoff_populated"])
        self.assertTrue(payload["validation"]["roadmap_accounting_foundry_slice_present"])
        self.assertTrue(payload["validation"]["aj_target_met"])
        self.assertTrue(payload["validation"]["ap_target_met"])
        self.assertTrue(payload["validation"]["ao_target_met"])
        self.assertTrue(payload["validation"]["ar_target_met"])
        self.assertTrue(payload["validation"]["aw_target_met"])
        self.assertTrue(payload["validation"]["aw_valid_not_full_closure"])
        self.assertTrue(payload["validation"]["bb_target_met"])
        self.assertTrue(payload["validation"]["bb_valid_not_full_closure"])
        self.assertTrue(payload["validation"]["bg_target_met"])
        self.assertTrue(payload["validation"]["bg_valid_not_full_closure"])
        self.assertTrue(payload["validation"]["bl_target_met"])
        self.assertTrue(payload["validation"]["bl_valid_not_full_closure"])
        self.assertTrue(payload["validation"]["bq_target_met"])
        self.assertTrue(payload["validation"]["bq_valid_not_full_closure"])
        self.assertTrue(payload["validation"]["bv_target_met"])
        self.assertTrue(payload["validation"]["bv_valid_not_full_closure"])
        self.assertTrue(payload["validation"]["ca_target_met"])
        self.assertTrue(payload["validation"]["ca_valid_not_full_closure"])
        self.assertTrue(payload["validation"]["cf_target_met"])
        self.assertTrue(payload["validation"]["cf_valid_not_full_closure"])
        self.assertTrue(payload["validation"]["ck_target_met"])
        self.assertTrue(payload["validation"]["ck_valid_not_full_closure"])
        self.assertTrue(payload["validation"]["cv_target_met"])
        self.assertTrue(payload["validation"]["cw_target_met"])
        self.assertTrue(payload["validation"]["cw_valid_final_accounting"])
        self.assertTrue(payload["validation"]["db_target_met"])
        self.assertTrue(payload["validation"]["db_valid_final_accounting"])
        self.assertTrue(payload["validation"]["dg_valid_final_accounting"])
        self.assertTrue(payload["validation"]["dl_valid_final_accounting"])
        self.assertTrue(payload["validation"]["db_scanner_autonomy_percentages_present"])
        self.assertTrue(payload["validation"]["dl_scanner_autonomy_percentages_present"])
        self.assertTrue(payload["validation"]["db_impact_miss_docs_reflected"])
        self.assertTrue(payload["validation"]["dl_impact_miss_docs_reflected"])
        self.assertTrue(payload["validation"]["db_genericity_docs_reflected"])
        self.assertTrue(payload["validation"]["dl_genericity_docs_reflected"])
        self.assertTrue(payload["validation"]["db_impact_miss_benchmark_posture_valid"])
        self.assertTrue(payload["validation"]["dl_impact_miss_benchmark_posture_valid"])
        self.assertTrue(payload["validation"]["provider_status_reflected"])
        self.assertTrue(payload["validation"]["bw_bz_generated_artifacts_recognized"])
        self.assertTrue(payload["validation"]["cb_cf_generated_artifacts_recognized"])
        self.assertTrue(payload["validation"]["cg_cj_artifacts_recognized"])
        self.assertTrue(payload["validation"]["cl_co_artifacts_recognized"])
        self.assertTrue(payload["validation"]["automation_id_present"])
        self.assertTrue(payload["validation"]["active_agent_slot_accounting_present"])
        self.assertTrue(payload["validation"]["active_agent_stale_running_quarantine_active"])
        self.assertTrue(payload["validation"]["roadmap_percentage_accounting_present"])
        self.assertEqual(payload["validation"]["blockers"], [])
        self.assertEqual(payload["aw_reconciliation"]["status"], "valid_local_integration_readiness_not_full_closure")
        self.assertTrue(payload["aw_reconciliation"]["readiness_valid_expected"])
        self.assertFalse(payload["aw_reconciliation"]["full_closure_claimed"])
        self.assertFalse(payload["aw_reconciliation"]["full_closure_achieved"])
        self.assertEqual(payload["aw_reconciliation"]["live_provider_triage"]["proof_claim"], "not_claimed")
        self.assertEqual(payload["aw_reconciliation"]["semantic_adjudication"]["proof_claim"], "not_claimed")
        self.assertEqual(payload["aw_reconciliation"]["foundry_slice"]["proof_claim"], "not_claimed")
        self.assertTrue(payload["aw_reconciliation"]["changed_file_group_counts"]["all_required_groups_present"])
        self.assertEqual(payload["bb_reconciliation"]["status"], "valid_local_capability_not_full_roadmap_closure")
        self.assertTrue(payload["bb_reconciliation"]["readiness_valid_expected"])
        self.assertFalse(payload["bb_reconciliation"]["full_closure_claimed"])
        self.assertFalse(payload["bb_reconciliation"]["full_closure_achieved"])
        self.assertIn("roadmap_percentage_accounting", payload["bb_reconciliation"])
        self.assertEqual(
            payload["bg_reconciliation"]["status"],
            "final_local_integration_ready_not_full_roadmap_closure",
        )
        self.assertTrue(payload["bg_reconciliation"]["readiness_valid_expected"])
        self.assertTrue(payload["bg_reconciliation"]["local_implementation_ready"])
        self.assertFalse(payload["bg_reconciliation"]["full_closure_claimed"])
        self.assertFalse(payload["bg_reconciliation"]["full_closure_achieved"])
        self.assertEqual(payload["bg_reconciliation"]["proof_claim"], "not_claimed")
        self.assertGreaterEqual(
            payload["bg_reconciliation"]["percentage_accounting"]["local_pr560_implementation_pct"],
            100.0,
        )
        self.assertGreater(
            payload["bg_reconciliation"]["percentage_accounting"]["known_limitations_open_pct"],
            0.0,
        )
        self.assertEqual(
            payload["bg_reconciliation"]["percentage_accounting"]["full_roadmap_closure_pct"],
            0.0,
        )
        self.assertEqual(
            payload["bl_reconciliation"]["status"],
            "post_bh_bk_local_integration_ready_not_full_roadmap_closure",
        )
        self.assertTrue(payload["bl_reconciliation"]["readiness_valid_expected"])
        self.assertTrue(payload["bl_reconciliation"]["local_implementation_ready"])
        self.assertFalse(payload["bl_reconciliation"]["full_closure_claimed"])
        self.assertFalse(payload["bl_reconciliation"]["full_closure_achieved"])
        self.assertEqual(payload["bl_reconciliation"]["proof_claim"], "not_claimed")
        self.assertEqual(
            payload["bl_reconciliation"]["percentage_accounting"]["full_roadmap_closure_pct"],
            0.0,
        )
        self.assertEqual(
            payload["bq_reconciliation"]["status"],
            "slot_readiness_reliability_accounted_not_full_roadmap_closure",
        )
        self.assertTrue(payload["bq_reconciliation"]["readiness_valid_expected"])
        self.assertFalse(payload["bq_reconciliation"]["full_closure_claimed"])
        self.assertFalse(payload["bq_reconciliation"]["full_closure_achieved"])
        self.assertTrue(payload["bq_reconciliation"]["slot_reliability"]["future_false_running_guard_active"])
        self.assertIn("bm_bp_artifact_window", payload["bq_reconciliation"])
        self.assertEqual(
            payload["ca_reconciliation"]["bw_bz_artifact_window"]["status"],
            "bw_bz_generated_accounting_artifacts_present",
        )
        self.assertGreater(
            payload["ca_reconciliation"]["bw_bz_artifact_window"]["generated_accounting_artifact_count"],
            0,
        )
        self.assertEqual(
            payload["cf_reconciliation"]["status"],
            "final_accounting_after_cb_ce_not_full_roadmap_closure",
        )
        self.assertTrue(payload["cf_reconciliation"]["bw_bz_generated_artifacts_recognized"])
        self.assertFalse(payload["cf_reconciliation"]["full_closure_claimed"])
        self.assertFalse(payload["cf_reconciliation"]["full_closure_achieved"])
        self.assertEqual(
            payload["ck_reconciliation"]["status"],
            "final_accounting_after_cg_cj_not_full_roadmap_closure",
        )
        self.assertTrue(payload["ck_reconciliation"]["cb_cf_generated_artifacts_recognized"])
        self.assertTrue(payload["ck_reconciliation"]["cg_cj_artifacts_recognized"])
        self.assertEqual(
            payload["ck_reconciliation"]["percentage_accounting"]["known_limitations_reduction_pct"],
            payload["ck_reconciliation"]["percentage_accounting"]["known_limitations_stop_condition_pct"],
        )
        self.assertFalse(payload["ck_reconciliation"]["full_closure_claimed"])
        self.assertFalse(payload["ck_reconciliation"]["full_closure_achieved"])
        self.assertEqual(
            payload["cw_reconciliation"]["status"],
            "final_accounting_after_cs_cv_provider_status_not_full_roadmap_closure",
        )
        self.assertTrue(payload["cw_reconciliation"]["provider_status_reflected"])
        self.assertEqual(payload["cw_reconciliation"]["provider_local_verification"]["proof_claim"], "not_claimed")
        self.assertEqual(payload["cw_reconciliation"]["provider_local_verification"]["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(payload["cw_reconciliation"]["provider_local_verification"]["submit_ready"])
        self.assertEqual(
            payload["db_reconciliation"]["status"],
            "final_accounting_after_cx_da_scanner_autonomy_not_full_roadmap_closure",
        )
        self.assertFalse(payload["db_reconciliation"]["full_closure_claimed"])
        self.assertFalse(payload["db_reconciliation"]["full_closure_achieved"])
        self.assertTrue(payload["db_reconciliation"]["impact_miss_docs_reflected"])
        self.assertTrue(payload["db_reconciliation"]["genericity_docs_reflected"])
        self.assertTrue(payload["db_reconciliation"]["impact_miss_benchmark_posture_valid"])
        self.assertEqual(payload["db_reconciliation"]["impact_miss_benchmark"]["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(payload["db_reconciliation"]["impact_miss_benchmark"]["promotion_allowed"])
        self.assertIn("impact_miss_benchmark_accuracy_pct", payload["db_reconciliation"]["percentage_accounting"])
        self.assertTrue(payload["db_reconciliation"]["scanner_autonomy_posture_valid"])
        self.assertIn("scanner_autonomy_pct", payload["db_reconciliation"]["percentage_accounting"])
        self.assertEqual(payload["db_reconciliation"]["scanner_autonomy"]["proof_claim"], "not_claimed")
        self.assertEqual(payload["db_reconciliation"]["scanner_autonomy"]["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(
            payload["dl_reconciliation"]["status"],
            "final_accounting_after_dh_dk_refreshed_maps_not_full_roadmap_closure",
        )
        self.assertFalse(payload["dl_reconciliation"]["full_closure_claimed"])
        self.assertFalse(payload["dl_reconciliation"]["full_closure_achieved"])
        self.assertTrue(payload["dl_reconciliation"]["progress_readiness_known_limitations_regenerated"])
        self.assertTrue(payload["dl_reconciliation"]["impact_miss_docs_reflected"])
        self.assertTrue(payload["dl_reconciliation"]["genericity_docs_reflected"])
        self.assertTrue(payload["dl_reconciliation"]["impact_miss_benchmark_posture_valid"])
        self.assertTrue(payload["dl_reconciliation"]["scanner_autonomy_posture_valid"])
        self.assertEqual(payload["dl_reconciliation"]["scanner_autonomy"]["proof_claim"], "not_claimed")
        self.assertEqual(payload["dl_reconciliation"]["scanner_autonomy"]["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(payload["dl_reconciliation"]["impact_miss_benchmark"]["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(payload["dl_reconciliation"]["impact_miss_benchmark"]["promotion_allowed"])
        self.assertIn("impact_miss_benchmark_accuracy_pct", payload["dl_reconciliation"]["percentage_accounting"])
        self.assertIn("known_limitations_stop_condition_pct", payload["roadmap_accounting"])
        self.assertEqual(payload["roadmap_accounting"]["automation_id"], "auditooor-watchdog-closure-loop")
        self.assertEqual(payload["operator_handoff"]["automation_id"], "auditooor-watchdog-closure-loop")
        self.assertIn("full_roadmap_closure_pct", payload["roadmap_accounting"])
        self.assertIn("active_agent_slot_accounting", payload)
        self.assertGreaterEqual(payload["active_agent_slot_accounting"]["slot_count"], 1)
        self.assertIn("freshness_policy", payload["active_agent_slot_accounting"])
        self.assertIn("effective_status_counts", payload["active_agent_slot_accounting"])
        self.assertFalse(payload["remaining_not_closed"]["full_scanner_coverage"]["closed"])
        self.assertFalse(payload["remaining_not_closed"]["invariant_discovery_completeness"]["closed"])
        self.assertFalse(payload["remaining_not_closed"]["executed_harnesses"]["closed"])
        self.assertFalse(payload["remaining_not_closed"]["rust_dlt_semantic_depth"]["closed"])
        self.assertEqual(payload["generated_artifact_isolation"]["owning_slice"], "PR560-G-generated-artifacts-optional")
        self.assertEqual(payload["generated_artifact_isolation"]["status"], "isolated_optional_slice")
        self.assertEqual(payload["roadmap_accounting"]["foundry_migration_slice"], "PR560-H-foundry-v1.7-migration")
        self.assertTrue(payload["roadmap_accounting"]["foundry_migration_doc_present"])
        self.assertIn("foundry_fixture_manifest_status", payload["roadmap_accounting"])
        self.assertIn("known_limitations_open_row_count", payload["roadmap_accounting"])
        self.assertIn(
            payload["roadmap_accounting"]["known_limitations_count_source"],
            {"seed_map", "workspace_generated_burndown"},
        )
        self.assertIn("known_limitations_seed_stop_conditions_met", payload["roadmap_accounting"])
        self.assertIn("foundry_representative_fixture_manifests", payload)
        foundry_fixtures = payload["foundry_representative_fixture_manifests"]
        self.assertEqual(foundry_fixtures["migration_state"], "planned_not_executed")
        self.assertFalse(foundry_fixtures["upgrade_performed"])
        self.assertFalse(foundry_fixtures["install_or_upgrade_allowed"])
        self.assertEqual(foundry_fixtures["fixture_count"], 4)
        self.assertEqual(len(foundry_fixtures["rows"]), 4)
        self.assertTrue(foundry_fixtures["operator_commands"])
        self.assertTrue(payload["operator_handoff"]["commands"])
        self.assertTrue(payload["operator_handoff"]["warnings"])

        slices = {row["slice_id"]: row for row in payload["future_pr_slices"]}
        self.assertEqual(set(slices), set(tool.INTEGRATION_REQUIRED_SLICE_IDS))
        self.assertEqual(slices["PR560-A-impact-gates"]["overclaim_guard"], "reduction_only_not_full_closure")
        self.assertIn("submission readiness", slices["PR560-A-impact-gates"]["must_not_claim"])
        self.assertEqual(
            slices["PR560-B-provider-assist"]["overclaim_guard"],
            "advisory_only_requires_operator_live_consent",
        )
        self.assertIn("live provider consent", slices["PR560-B-provider-assist"]["must_not_claim"])
        self.assertFalse(slices["PR560-C-semantic-multihop"]["full_coverage_claimed"])
        self.assertFalse(slices["PR560-D-detector-worklists"]["generated_artifacts_allowed"])
        self.assertIn("make docs-check", slices["PR560-E-docs-known-limitations"]["representative_tests"])
        self.assertIn("make automation-closure-test", slices["PR560-F-tests-accounting"]["representative_tests"])
        self.assertTrue(slices["PR560-G-generated-artifacts-optional"]["generated_artifacts_allowed"])
        self.assertEqual(
            slices["PR560-H-foundry-v1.7-migration"]["overclaim_guard"],
            "performance_and_capability_upgrade_not_submission_proof",
        )
        self.assertIn("PoC proof", slices["PR560-H-foundry-v1.7-migration"]["must_not_claim"])
        self.assertIn(
            "python3 -m unittest tools.tests.test_harness_scaffold_emitter",
            slices["PR560-H-foundry-v1.7-migration"]["representative_tests"],
        )
        self.assertFalse(slices["PR560-H-foundry-v1.7-migration"]["generated_artifacts_allowed"])

        matrix = {row["slice_id"]: row for row in payload["per_slice_test_matrix"]}
        self.assertEqual(set(matrix), set(tool.INTEGRATION_REQUIRED_SLICE_IDS))
        self.assertIn("make docs-check", matrix["PR560-E-docs-known-limitations"]["required_local_tests"])
        self.assertTrue(matrix["PR560-H-foundry-v1.7-migration"]["operator_approved_tests"])
        self.assertTrue(matrix["PR560-H-foundry-v1.7-migration"]["stop_conditions"])

        groups = {row["group"]: row for row in payload["changed_file_groups"]}
        self.assertIn("impact_gates", groups)
        self.assertIn("provider_assist", groups)
        self.assertIn("semantic_multihop", groups)
        self.assertIn("detector_worklists", groups)
        self.assertIn("docs_known_limitations", groups)
        self.assertIn("tests_accounting", groups)
        self.assertIn("foundry_migration", groups)
        self.assertIn("generated_artifacts_optional", groups)

        readiness_md = self.progress_docs_dir / "PR560_LOCAL_INTEGRATION_READINESS.md"
        readiness_json = self.progress_docs_dir / "PR560_LOCAL_INTEGRATION_READINESS.json"
        self.assertTrue(readiness_md.is_file())
        self.assertTrue(readiness_json.is_file())
        text = readiness_md.read_text(encoding="utf-8")
        self.assertIn("Future PR Slice Plan", text)
        self.assertIn("Completed Worker AJ Items", text)
        self.assertIn("Completed Worker AP Items", text)
        self.assertIn("Completed Worker AR Items", text)
        self.assertIn("Completed Worker AW Items", text)
        self.assertIn("Completed Worker BB Items", text)
        self.assertIn("Completed Worker BG Items", text)
        self.assertIn("Completed Worker BL Items", text)
        self.assertIn("Completed Worker BQ Items", text)
        self.assertIn("Completed Worker BV Items", text)
        self.assertIn("Completed Worker CA Items", text)
        self.assertIn("Completed Worker CF Items", text)
        self.assertIn("Completed Worker CK Items", text)
        self.assertIn("Completed Worker CP Items", text)
        self.assertIn("Completed Worker CR Items", text)
        self.assertIn("Completed Worker CV Items", text)
        self.assertIn("Completed Worker CW Items", text)
        self.assertIn("Completed Worker DB Items", text)
        self.assertIn("Completed Worker DG Items", text)
        self.assertIn("Completed Worker DL Items", text)
        self.assertIn("Worker AW Reconciliation", text)
        self.assertIn("Worker BB Reconciliation", text)
        self.assertIn("Worker BG Final Reconciliation", text)
        self.assertIn("Worker BL Reconciliation", text)
        self.assertIn("Worker BQ Slot Reliability Reconciliation", text)
        self.assertIn("Worker BV Final Accounting Reconciliation", text)
        self.assertIn("Worker CA Active-Loop Reconciliation", text)
        self.assertIn("Worker CF Final Accounting Reconciliation", text)
        self.assertIn("Worker CK Final Accounting Reconciliation", text)
        self.assertIn("Worker CP Final Accounting Reconciliation", text)
        self.assertIn("Worker CR Permission-Loop Reconciliation", text)
        self.assertIn("Worker CW Final Accounting Reconciliation", text)
        self.assertIn("Worker DB Final Accounting Reconciliation", text)
        self.assertIn("Worker DG Final Accounting Reconciliation", text)
        self.assertIn("Worker DL Final Accounting Reconciliation", text)
        self.assertIn("Provider local-verification status", text)
        self.assertIn("Scanner Autonomy Accounting", text)
        self.assertIn("Impact-Miss benchmark accuracy", text)
        self.assertIn("Local commands allowed: `true`", text)
        self.assertIn("Approval prompts for local commands forbidden: `true`", text)
        self.assertIn("Try commands before blocker: `true`", text)
        self.assertIn("Git/GitHub actions allowed: `false`", text)
        self.assertIn("auditooor-watchdog-closure-loop", text)
        self.assertIn("Roadmap Percentage Accounting", text)
        self.assertIn("Active Agent Slot Accounting", text)
        self.assertIn("Foundry Fixture Trial Manifests", text)
        self.assertIn("Remaining Not Closed", text)
        self.assertIn("full_scanner_coverage", text)
        self.assertIn("Per-Slice Test Matrix", text)
        self.assertIn("Generated-Artifact Isolation", text)
        self.assertIn("Roadmap Accounting", text)
        self.assertIn("Operator Handoff", text)
        self.assertIn("Overclaim Guardrails", text)
        self.assertIn("Submission/scanner/provider proof verdict: `not_claimed`", text)
        json_payload = json.loads(readiness_json.read_text(encoding="utf-8"))
        self.assertEqual(json_payload["validation"]["valid"], True)

    def test_pr560_integration_readiness_cli_json(self):
        ws = self.make_ws()
        aud = ws / ".auditooor"
        aud.mkdir(exist_ok=True)
        (aud / "pr560_next_actions.json").write_text(
            json.dumps({"rows": [], "summary": {"row_count": 0, "by_category": {}}}),
            encoding="utf-8",
        )
        env = os.environ.copy()
        env["AUDITOOOR_PR560_PROGRESS_DOCS_DIR"] = str(self.progress_docs_dir)
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--workspace",
                str(ws),
                "--mode",
                "pr560-integration-readiness",
                "--json",
            ],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["readiness_verdict"], "ready_for_operator_review")
        self.assertEqual(payload["completed_worker_ad_item_count"], 9)
        self.assertGreaterEqual(payload["completed_worker_aj_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_ap_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_ao_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_ar_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_aw_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_bb_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_bg_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_bl_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_bq_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_bv_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_ca_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_cf_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_ck_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_cp_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_cr_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_cv_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_cw_item_count"], 50)
        self.assertGreaterEqual(payload["completed_worker_db_item_count"], 150)
        self.assertTrue(payload["validation"]["valid"])
        self.assertTrue(payload["validation"]["required_not_closed_boundaries_present"])
        self.assertTrue(payload["validation"]["aw_valid_not_full_closure"])
        self.assertTrue(payload["validation"]["bb_valid_not_full_closure"])
        self.assertTrue(payload["validation"]["bg_valid_not_full_closure"])
        self.assertTrue(payload["validation"]["bl_valid_not_full_closure"])
        self.assertTrue(payload["validation"]["bq_valid_not_full_closure"])
        self.assertTrue(payload["validation"]["bv_valid_not_full_closure"])
        self.assertTrue(payload["validation"]["ca_valid_not_full_closure"])
        self.assertTrue(payload["validation"]["cf_valid_not_full_closure"])
        self.assertTrue(payload["validation"]["ck_valid_not_full_closure"])
        self.assertTrue(payload["validation"]["cp_valid_not_full_closure"])
        self.assertTrue(payload["validation"]["cr_valid_permission_loop"])
        self.assertTrue(payload["validation"]["cr_target_met"])
        self.assertTrue(payload["validation"]["cv_target_met"])
        self.assertTrue(payload["validation"]["cw_valid_final_accounting"])
        self.assertTrue(payload["validation"]["cw_target_met"])
        self.assertTrue(payload["validation"]["db_valid_final_accounting"])
        self.assertTrue(payload["validation"]["db_target_met"])
        self.assertTrue(payload["validation"]["dg_valid_final_accounting"])
        self.assertTrue(payload["validation"]["dg_target_met"])
        self.assertTrue(payload["validation"]["dl_valid_final_accounting"])
        self.assertTrue(payload["validation"]["dl_target_met"])
        self.assertTrue(payload["validation"]["db_scanner_autonomy_percentages_present"])
        self.assertTrue(payload["validation"]["dl_scanner_autonomy_percentages_present"])
        self.assertTrue(payload["validation"]["db_impact_miss_benchmark_posture_valid"])
        self.assertTrue(payload["validation"]["dl_impact_miss_benchmark_posture_valid"])
        self.assertTrue(payload["validation"]["provider_status_reflected"])
        self.assertTrue(payload["validation"]["bw_bz_generated_artifacts_recognized"])
        self.assertTrue(payload["validation"]["cb_cf_generated_artifacts_recognized"])
        self.assertTrue(payload["validation"]["cg_cj_artifacts_recognized"])
        self.assertTrue(payload["validation"]["cl_co_artifacts_recognized"])
        self.assertTrue(payload["validation"]["automation_id_present"])
        self.assertEqual(payload["db_reconciliation"]["scanner_autonomy"]["proof_claim"], "not_claimed")
        self.assertEqual(payload["db_reconciliation"]["impact_miss_benchmark"]["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(payload["db_reconciliation"]["percentage_accounting"]["full_roadmap_closure_pct"], 0.0)
        self.assertEqual(payload["dl_reconciliation"]["scanner_autonomy"]["proof_claim"], "not_claimed")
        self.assertEqual(payload["dl_reconciliation"]["impact_miss_benchmark"]["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(payload["dl_reconciliation"]["percentage_accounting"]["full_roadmap_closure_pct"], 0.0)
        self.assertTrue(payload["cr_reconciliation"]["local_write_policy"]["writes_allowed_inside_worktree"])
        self.assertTrue(payload["cr_reconciliation"]["local_write_policy"]["local_commands_allowed"])
        self.assertTrue(payload["cr_reconciliation"]["local_write_policy"]["tests_allowed"])
        self.assertTrue(payload["cr_reconciliation"]["local_write_policy"]["repo_tools_allowed"])
        self.assertTrue(payload["cr_reconciliation"]["local_write_policy"]["approval_prompts_for_local_commands_forbidden"])
        self.assertTrue(payload["cr_reconciliation"]["local_write_policy"]["try_commands_before_blocker"])
        self.assertEqual(
            payload["cr_reconciliation"]["local_write_policy"]["blocked_command_fallback"],
            "write_exact_blocker_artifact",
        )
        self.assertEqual(
            payload["cr_reconciliation"]["local_write_policy"]["blocker_policy"],
            "real_missing_prerequisite_failing_tool_unsafe_semantic_gap_or_git_github_boundary_only",
        )
        self.assertFalse(any(
            payload["cr_reconciliation"]["no_git_actions_policy"][key]
            for key in ("stage", "commit", "push", "pull_request", "merge", "github_actions")
        ))
        self.assertIn(
            payload["provider_local_verification_accounting"]["status"],
            {
                "provider_local_terminal_status_reflected",
                "provider_local_artifacts_partial",
                "provider_local_artifacts_missing",
            },
        )

    def test_scanner_autonomy_accounting_records_er_terminal_state_without_overflow_pct(self):
        ws = self.make_ws()
        audit = ws / ".auditooor"
        audit.mkdir(exist_ok=True)
        (audit / "scanner_autonomy_plan.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.scanner_autonomy_executor.v1",
                    "task_count": 200,
                    "candidate_count": 200,
                    "runnable_count": 169,
                    "execution_allowed_count": 169,
                    "stop_condition_summary": {
                        "manual_triage_items_mechanically_accounted": 200,
                        "runnable_local_command_items": 169,
                        "allowlisted_execution_items": 169,
                        "execution_blocker_counts": {"no_command": 31},
                    },
                    "coverage_claim": "none_scanner_autonomy_only",
                    "submission_posture": "NOT_SUBMIT_READY",
                    "severity": "none",
                    "selected_impact": "",
                    "promotion_allowed": False,
                }
            ),
            encoding="utf-8",
        )
        (audit / "scanner_autonomy_execution.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.scanner_autonomy_execution.v1",
                    "outcome_count": 200,
                    "allowlisted_outcome_count": 169,
                    "effective_executed_count": 100,
                    "executed_count": 52,
                    "unique_command_execution_count": 52,
                    "prior_detector_smoke_execution_count": 48,
                    "status_counts": {
                        "blocked_no_command": 29,
                        "covered_by_prior_detector_smoke": 48,
                        "covered_by_prior_execution": 69,
                        "executed_failed": 46,
                        "executed_ok": 6,
                        "terminal_detector_smoke_blocker": 2,
                    },
                    "submission_posture": "NOT_SUBMIT_READY",
                    "promotion_allowed": False,
                }
            ),
            encoding="utf-8",
        )

        accounting = tool.scanner_autonomy_accounting(ws)

        self.assertEqual(accounting["manual_triage_accounting_target"], 200)
        self.assertEqual(accounting["manual_triage_accounted_pct"], 100.0)
        self.assertEqual(accounting["allowlisted_outcome_items"], 169)
        self.assertEqual(accounting["unexecuted_allowlisted_local_command_items"], 0)
        self.assertTrue(accounting["local_allowlisted_command_accounting_complete"])
        self.assertEqual(accounting["executed_items"], 100)
        self.assertEqual(accounting["unique_command_execution_items"], 52)
        self.assertEqual(accounting["executed_ok_items"], 6)
        self.assertEqual(accounting["executed_failed_items"], 46)
        self.assertEqual(accounting["blocked_no_command_items"], 29)
        self.assertEqual(accounting["terminal_detector_smoke_blocker_items"], 2)
        self.assertFalse(accounting["scanner_completeness_claimed"])
        self.assertEqual(accounting["proof_claim"], "not_claimed")

    def test_active_agent_slot_accounting_ignores_stale_running_rows(self):
        old_root = tool.ROOT
        with tempfile.TemporaryDirectory(prefix="automation_closure_slots_") as td:
            repo = Path(td)
            (repo / "docs").mkdir()
            (repo / "docs" / "PR560_ACTIVE_AGENT_SLOTS.md").write_text(
                "# PR560 Active Agent Slots\n\n"
                "## Current Slots\n\n"
                "| Slot | Agent | Handle | Current ownership | Status | Last update | Closed reason |\n"
                "|---|---|---|---|---|---|---|\n"
                "| A | Old Runner | `old-handle` | stale lane | running | 2026-04-28 | missing heartbeat |\n"
                f"| B | Current Runner | `pid-{os.getpid()}` | current lane | running | 2999-01-01 | active heartbeat |\n"
                "| C | No Metadata | `missing-date` | stale lane | running |  | missing freshness |\n"
                "| E | Dead Fresh Pid | `pid-99999999` | stale lane | running | 2999-01-01 | exited process |\n"
                "| D | Done Worker | `done` | integration readiness | completed | 2026-05-01 | complete |\n"
                "\n## Recently Closed Local Accounting Slots\n\n"
                "| Agent | Lane | Ownership / result | Status | Artifact |\n"
                "|---|---|---|---|---|\n"
                "| Worker ES | `pid-1` | completed | completed_process_exited | `.auditooor/es.json` |\n",
                encoding="utf-8",
            )
            tool.ROOT = repo
            try:
                payload = tool.pr560_active_agent_slot_accounting()
            finally:
                tool.ROOT = old_root

        self.assertEqual(payload["raw_running_count"], 4)
        self.assertEqual(payload["effective_running_count"], 1)
        self.assertEqual(payload["slot_count"], 5)
        self.assertEqual(payload["running_count"], 1)
        self.assertEqual(payload["stale_running_ignored_count"], 3)
        self.assertEqual(payload["effective_status_counts"]["stale_running_ignored"], 3)
        self.assertEqual(payload["completed_count"], 1)
        self.assertTrue(payload["freshness_policy"]["running_slots_require_parseable_last_update"])
        self.assertTrue(payload["freshness_policy"]["pid_handles_require_live_process"])
        self.assertEqual(
            payload["freshness_policy"]["unparseable_running_rows_count_as"],
            "stale_running_ignored",
        )
        self.assertEqual(
            payload["freshness_policy"]["unparseable_or_dead_pid_running_rows_count_as"],
            "stale_running_ignored",
        )
        self.assertIn(
            "pid_not_alive",
            next(row for row in payload["rows"] if row["slot"] == "E")["stale_running_reasons"],
        )

    def test_pr560_local_progress_refuses_unverified_agent_outputs(self):
        ws = self.make_ws()
        aud = ws / ".auditooor"
        aud.mkdir(exist_ok=True)
        (aud / "pr560_next_actions.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "next_action_id": "pr560-next-agent-001",
                            "category": "agent_verification",
                            "source_artifact": "agent_outputs/unverified.md",
                            "exact_status": "actionable_verification_queue",
                            "next_command": "python3 tools/automation-closure.py --mode agent-output-verify-record",
                            "strict_blocking": False,
                            "submit_ready": False,
                        }
                    ],
                    "summary": {
                        "row_count": 1,
                        "strict_blocking": 0,
                        "by_category": {
                            "agent_verification": 1,
                            "strict_blocker": 0,
                        },
                    },
                }
            ),
            encoding="utf-8",
        )

        payload = tool.render_pr560_local_progress(ws)
        readiness = payload["bundle_readiness"]
        self.assertEqual(payload["status"], "unverified_agent_output_rows")
        self.assertFalse(readiness["ready_for_eventual_pr"])
        self.assertEqual(readiness["agent_output_verification_open_count"], 1)
        self.assertEqual(payload["remaining_advisory_counts"]["agent_verification"], 1)
        self.assertEqual(payload["remaining_advisory_count"], 1)
        self.assertEqual(payload["resolved_advisory_counts"]["agent_verification"], 0)
        self.assertFalse(readiness["consistency_checks"]["agent_output_verification_clear"])
        self.assertIn("unverified_agent_output_rows", {row["reason"] for row in readiness["refusal_reasons"]})

    def test_pr560_local_progress_reconciles_resolved_advisory_rows(self):
        ws = self.make_ws()
        aud = ws / ".auditooor"
        aud.mkdir(exist_ok=True)
        (aud / "pr560_next_actions.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "next_action_id": "pr560-next-source-001",
                            "category": "source_proof",
                            "source_artifact": "agent_outputs/source.md",
                            "exact_status": "blocked_missing_impact_contract",
                            "next_command": "make source-proof-record WS=<workspace>",
                            "strict_blocking": False,
                            "submit_ready": False,
                        },
                        {
                            "next_action_id": "pr560-next-source-002",
                            "category": "source_proof",
                            "source_artifact": "agent_outputs/source-2.md",
                            "exact_status": "blocked_missing_impact_contract",
                            "next_command": "make source-proof-record WS=<workspace>",
                            "strict_blocking": False,
                            "submit_ready": False,
                        },
                        {
                            "next_action_id": "pr560-next-source-003",
                            "category": "source_proof",
                            "source_artifact": "agent_outputs/source-3.md",
                            "exact_status": "blocked_missing_impact_contract",
                            "next_command": "make source-proof-record WS=<workspace>",
                            "strict_blocking": False,
                            "submit_ready": False,
                        },
                    ],
                    "summary": {
                        "row_count": 3,
                        "strict_blocking": 0,
                        "by_category": {
                            "source_proof": 3,
                            "strict_blocker": 0,
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        (aud / "source_proof_tasks.json").write_text(
            json.dumps(
                {
                    "rows": [],
                    "summary": {
                        "terminal_evidence_present": 2,
                        "local_evidence_missing": 1,
                    },
                }
            ),
            encoding="utf-8",
        )

        payload = tool.render_pr560_local_progress(ws)
        self.assertEqual(payload["open_advisory_counts_before_reconciliation"]["source_proof"], 3)
        self.assertEqual(payload["resolved_advisory_counts"]["source_proof"], 2)
        self.assertEqual(payload["remaining_advisory_counts"]["source_proof"], 1)
        self.assertEqual(payload["remaining_advisory_count"], 1)
        self.assertEqual(payload["advisory_reconciliation"]["remaining_total"], 1)

    def test_agent_output_inventory_ignores_repo_tmp_outputs_by_default(self):
        ws = self.make_second_ws()
        (ws / "agent_outputs").mkdir()
        (ws / "agent_outputs" / "base-local.md").write_text(
            "VERDICT: Base local candidate needs verification\n",
            encoding="utf-8",
        )
        (ws / "swarm").mkdir()
        (ws / "swarm" / "brief_candidate.md").write_text(
            "High candidate from workspace swarm output\n",
            encoding="utf-8",
        )

        old_root = tool.ROOT
        old_env = os.environ.pop("AUDITOOOR_INCLUDE_REPO_AGENT_OUTPUTS", None)
        with tempfile.TemporaryDirectory(prefix="automation_closure_repo_outputs_") as td:
            repo = Path(td)
            (repo / "agent_outputs").mkdir()
            (repo / "agent_outputs" / "tmp-repo-noise.md").write_text(
                "Critical candidate from unrelated /private/tmp repo output\n",
                encoding="utf-8",
            )
            tool.ROOT = repo
            try:
                payload = tool.render_agent_output_inventory(ws)
            finally:
                tool.ROOT = old_root
                if old_env is not None:
                    os.environ["AUDITOOOR_INCLUDE_REPO_AGENT_OUTPUTS"] = old_env

        paths = {Path(row["path"]).name for row in payload["rows"]}
        self.assertEqual(paths, {"base-local.md", "brief_candidate.md"})
        scopes = {row["source_scope"] for row in payload["rows"]}
        self.assertEqual(scopes, {"workspace_agent_outputs", "workspace_swarm"})
        self.assertEqual(payload["status"], "actionable_verification_queue")
        self.assertFalse(any(row["submit_ready"] for row in payload["rows"]))
        self.assertTrue(all(row["source_path"] == row["path"] for row in payload["rows"]))
        self.assertTrue(all(row["next_command"] for row in payload["rows"]))
        self.assertFalse(payload["discovery_policy"]["repo_agent_outputs_included"])

    def test_agent_output_inventory_can_explicitly_include_repo_outputs(self):
        ws = self.make_second_ws()
        old_root = tool.ROOT
        old_env = os.environ.get("AUDITOOOR_INCLUDE_REPO_AGENT_OUTPUTS")
        with tempfile.TemporaryDirectory(prefix="automation_closure_repo_outputs_optin_") as td:
            repo = Path(td)
            (repo / "agent_outputs").mkdir()
            (repo / "agent_outputs" / "repo-provider.md").write_text(
                "VERDICT: repo-level provider candidate for explicit inventory\n",
                encoding="utf-8",
            )
            tool.ROOT = repo
            os.environ["AUDITOOOR_INCLUDE_REPO_AGENT_OUTPUTS"] = "1"
            try:
                payload = tool.render_agent_output_inventory(ws)
            finally:
                tool.ROOT = old_root
                if old_env is None:
                    os.environ.pop("AUDITOOOR_INCLUDE_REPO_AGENT_OUTPUTS", None)
                else:
                    os.environ["AUDITOOOR_INCLUDE_REPO_AGENT_OUTPUTS"] = old_env

        self.assertTrue(payload["discovery_policy"]["repo_agent_outputs_included"])
        self.assertIn("repo_agent_outputs", {row["source_scope"] for row in payload["rows"]})
        row = payload["rows"][0]
        self.assertEqual(Path(row["path"]).name, "repo-provider.md")
        self.assertEqual(row["terminal_route"], "agent_recall")
        self.assertFalse(row["submit_ready"])

    def test_harness_task_queue_ready_blocked_and_scope_only(self):
        ws = self.make_ws()
        tool.render_impact_matrix(ws)
        contracts_payload = tool.render_impact_contracts(ws)
        aud = ws / ".auditooor"
        aud.mkdir(exist_ok=True)
        contract = contracts_payload["contracts"][0]
        contract["source_id"] = "SRC-1"
        contracts_payload["contracts"].append(
            {
                "impact_contract_id": "impact-contract-unlocked",
                "candidate_id": "UNLOCKED",
                "selected_impact": "Unproven exact impact sentence",
                "severity": "Critical",
                "exact_impact_row": True,
                "listed_impact_proven": False,
                "posture": "NOT_SUBMIT_READY",
                "verdict": "NOT_SUBMIT_READY",
            }
        )
        (aud / "impact_contracts.json").write_text(json.dumps(contracts_payload), encoding="utf-8")
        (aud / "corpus_detectorization_inventory.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "status": "detectorized",
                            "claims_detected": ["anonymous row with no harness precondition"],
                        },
                        {
                            "status": "harness_task_required",
                            "agent_output": "agent_outputs/snappy.md",
                            "claims_detected": ["resource consumption harness still needs exact impact"],
                        },
                        {
                            "source_id": "CORPUS-1",
                            "title": "Detectorized behavior still needs exact impact",
                            "terminal_state": "harness_task",
                            "detector_or_lane": "source-mining-harness-task",
                        },
                        {
                            "source_id": "CORPUS-2",
                            "title": "Harness candidate with bogus impact contract id",
                            "terminal_state": "harness_task",
                            "impact_contract_id": "impact-contract-does-not-exist",
                        },
                        {
                            "source_id": "CORPUS-CANDIDATE",
                            "candidate_id": "C1",
                            "title": "Harness candidate matched by candidate id",
                            "terminal_state": "harness_task",
                        },
                        {
                            "source_id": "SRC-1",
                            "title": "Harness candidate matched by source id",
                            "terminal_state": "harness_task",
                        },
                        {
                            "source_id": "CORPUS-IMPACT",
                            "title": "Harness candidate matched by selected impact",
                            "selected_impact": "Direct theft of user funds",
                            "terminal_state": "harness_task",
                        },
                        {
                            "source_id": "CORPUS-EXPLICIT",
                            "title": "Harness candidate matched by explicit impact contract id",
                            "impact_contract_id": contract["impact_contract_id"],
                            "terminal_state": "harness_task",
                        },
                        {
                            "source_id": "CORPUS-NO-GUESS",
                            "title": "Harness candidate with impact prose but no selected impact",
                            "impact": "Direct theft of user funds",
                            "severity": "Critical",
                            "terminal_state": "harness_task",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (ws / "detector_findings.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "id": "OOS-1",
                            "title": "Out-of-scope admin-only route check",
                            "task_type": "scope_only",
                            "oos_status": "out_of_scope_as_report",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        payload = tool.render_harness_task_queue(ws)
        rows = payload["rows"]
        self.assertTrue((aud / "harness_tasks.json").is_file())

        locked_contract = [row for row in rows if row["source"] == "impact_contract" and row["candidate_id"] == "C1"][0]
        self.assertEqual(locked_contract["status"], "ready_to_execute")
        self.assertTrue(locked_contract["impact_contract_id"])

        unlocked_contract = [row for row in rows if row["source"] == "impact_contract" and row["candidate_id"] == "UNLOCKED"][0]
        self.assertEqual(unlocked_contract["status"], "blocked_missing_impact_contract")
        self.assertEqual(unlocked_contract["selected_impact"], "")
        self.assertEqual(unlocked_contract["severity"], "none")

        blocked = [row for row in rows if row["source"] == "corpus_detectorization"][0]
        self.assertEqual(blocked["status"], "blocked_missing_impact_contract")
        self.assertEqual(blocked["selected_impact"], "")
        self.assertEqual(blocked["severity"], "none")
        stable_agent = [row for row in rows if row["candidate_id"] == "corpus_detectorization-snappy-md"][0]
        self.assertEqual(stable_agent["status"], "blocked_missing_impact_contract")
        self.assertEqual(stable_agent["candidate_id_source"], "source_context")
        bogus = [row for row in rows if row["source_id"] == "CORPUS-2"][0]
        self.assertEqual(bogus["status"], "blocked_missing_impact_contract")
        self.assertEqual(bogus["impact_contract_id"], "")
        for title in (
            "Harness candidate matched by candidate id",
            "Harness candidate matched by source id",
            "Harness candidate matched by selected impact",
            "Harness candidate matched by explicit impact contract id",
        ):
            matched = [row for row in rows if row["source"] == "corpus_detectorization" and row["title"] == title][0]
            self.assertEqual(matched["status"], "ready_to_execute", title)
            self.assertEqual(matched["impact_contract_id"], contract["impact_contract_id"])
            self.assertEqual(matched["selected_impact"], "Direct theft of user funds")
            self.assertEqual(matched["severity"], "Critical")
        no_guess = [row for row in rows if row["source_id"] == "CORPUS-NO-GUESS"][0]
        self.assertEqual(no_guess["status"], "blocked_missing_impact_contract")
        self.assertEqual(no_guess["impact_contract_id"], "")
        self.assertEqual(no_guess["selected_impact"], "")
        self.assertEqual(no_guess["severity"], "none")

        scope = [row for row in rows if row["task_type"] == "scope_only"][0]
        self.assertEqual(scope["status"], "ready_to_execute")
        self.assertEqual(scope["impact_contract_id"], "")
        self.assertEqual(scope["reason"], "explicit_scope_or_impact_analysis_task")
        self.assertGreaterEqual(payload["summary"]["routed_to_impact_analysis"], 1)
        impact_queue = json.loads((aud / "impact_analysis_queue.json").read_text(encoding="utf-8"))
        routed = [row for row in impact_queue["rows"] if row.get("route_reason") == "not_harness_task_required"]
        self.assertEqual(len(routed), 1)
        self.assertEqual(routed[0]["source"], "corpus_detectorization")
        self.assertFalse(any(row["source_id"].startswith("corpus_detectorization-1") for row in rows))

    def test_harness_queue_links_exact_impact_candidates_fail_closed(self):
        ws = self.make_ws()
        aud = ws / ".auditooor"
        aud.mkdir(exist_ok=True)
        tool.render_impact_matrix(ws)
        (aud / "impact_contracts.json").write_text(json.dumps({"contracts": []}), encoding="utf-8")
        (aud / "corpus_detectorization_inventory.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "source_id": "SRC-DIRECT-THEFT",
                            "title": "Harness task for Direct theft of user funds",
                            "terminal_state": "harness_task",
                            "source_artifact": "agent_outputs/direct_theft.md",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        payload = tool.render_harness_task_queue(ws)
        row = [r for r in payload["rows"] if r["source_id"] == "SRC-DIRECT-THEFT"][0]
        self.assertEqual(row["status"], "blocked_missing_impact_contract")
        self.assertEqual(row["severity"], "none")
        self.assertEqual(row["selected_impact"], "")
        self.assertEqual(row["impact_contract_work_status"], "impact_contract_suggested")
        self.assertTrue(row["impact_contract_suggestions"])
        self.assertFalse(row["impact_contract_suggestions"][0]["listed_impact_proven"])
        self.assertIn("listed_impact_proven=true", row["next_command"])
        self.assertEqual(payload["status"], "open_harness_impact_contract_work")
        impact_queue = json.loads((aud / "impact_analysis_queue.json").read_text(encoding="utf-8"))
        linked = [r for r in impact_queue["rows"] if r.get("source_id") == "SRC-DIRECT-THEFT"]
        self.assertTrue(linked)
        self.assertEqual(linked[0]["action_type"], "exact_impact_candidate")

    def test_harness_queue_no_exact_candidate_still_has_stable_action(self):
        ws = self.make_ws()
        aud = ws / ".auditooor"
        aud.mkdir(exist_ok=True)
        tool.render_impact_matrix(ws)
        (aud / "impact_contracts.json").write_text(json.dumps({"contracts": []}), encoding="utf-8")
        (aud / "corpus_detectorization_inventory.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "title": "Harness task for custom parser edge",
                            "terminal_state": "harness_task",
                            "source_artifact": "agent_outputs/custom_parser_edge.md",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        payload = tool.render_harness_task_queue(ws)
        row = payload["rows"][0]
        self.assertTrue(row["candidate_id"])
        self.assertNotIn(row["candidate_id"].lower(), {"", "source-proof-001", "source-proof-053"})
        self.assertEqual(row["status"], "blocked_missing_impact_contract")
        self.assertEqual(row["impact_contract_work_status"], "exact_impact_candidate_required")
        self.assertEqual(row["impact_contract_suggestions"], [])
        self.assertIn("make impact-analysis-queue", row["next_command"])
        self.assertIn("impact_contract_id", row["next_command"])
        self.assertEqual(payload["status"], "open_harness_impact_contract_work")

    def test_harness_queue_locked_impact_contract_ready_to_execute(self):
        ws = self.make_ws()
        aud = ws / ".auditooor"
        aud.mkdir(exist_ok=True)
        (aud / "impact_contracts.json").write_text(
            json.dumps(
                {
                    "contracts": [
                        {
                            "impact_contract_id": "impact-contract-locked",
                            "candidate_id": "LOCKED-HARNESS",
                            "selected_impact": "Direct theft of user funds",
                            "severity": "Critical",
                            "exact_impact_row": True,
                            "listed_impact_proven": True,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        payload = tool.render_harness_task_queue(ws)
        row = payload["rows"][0]
        self.assertEqual(row["candidate_id"], "LOCKED-HARNESS")
        self.assertEqual(row["status"], "ready_to_execute")
        self.assertEqual(row["selected_impact"], "Direct theft of user funds")
        self.assertEqual(row["severity"], "Critical")
        self.assertEqual(row["impact_contract_work_status"], "none")
        self.assertEqual(payload["status"], "ok")

    def test_agent_recall_cli(self):
        ws = self.make_ws()
        out = ws / "agent_outputs"
        out.mkdir()
        (out / "claim.md").write_text("VERDICT: Critical candidate killed", encoding="utf-8")
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--workspace",
                str(ws),
                "--mode",
                "agent-recall",
                "--json",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertEqual(data["schema"], "auditooor.pr560.agent_recall.v1")
        self.assertTrue((ws / ".auditooor" / "agent_found_not_detector_found.json").is_file())

    def test_agent_recall_classifies_base_and_polymarket_fixtures(self):
        ws = self.make_second_ws()
        aud = ws / ".auditooor"
        out = ws / "agent_outputs"
        out.mkdir(exist_ok=True)
        fixtures = {
            "iter4_T1_revalidate_negrisk.log": """
pre-submit-check — source-draft.md
Detected severity: High
PoC reference in submission (lib/exchange-fee-module/test/NegRiskFeeModuleCtfRevert.t.sol)
PoC NegRiskFeeModuleCtfRevert.t.sol: forge exited 0 (assumed pass)
ALL 22 CHECKS PASSED — safe to submit
""",
            "capv3_iter5_T1_live_R83-A.notes.json": json.dumps(
                {
                    "verdicts_extracted": [
                        "DUPE of existing submission",
                        "DUPLICATE of Cantina #84 (paid)",
                    ],
                    "counter_brief_body": "Primary-agent verdicts: DUPE of existing submission",
                }
            ),
            "FN7_EXPLOITABILITY_RESEARCH_2026-04-29.md": """
# FN7 Exploitability Research — base-azul Isthmus Withdrawals-Root Silent-Pass
Severity: Critical candidate after the production-handler Scenario C harness.
Recommended severity: file as a Critical candidate.
No exact impact contract is selected in this fixture.
""",
            "capv3_iter9_T1_review_candidate_vault_Holdings_RedemptionBounds.md": """
# Review candidate — vault_Holdings_RedemptionBounds.sym.t.sol
halmos status: counterexample
Status: FAIL — counterexample surfaced.
Follow-up: narrow check_overdraw_on_holding_reverts and re-run symbolically.
""",
            "base_source_reader_invariant.md": """
# Base source-reader note
VERDICT HOLDS: invariant provider.state_by_block_hash must be line-cited in crates/execution/node/src/engine.rs.
Need source proof before detectorization.
""",
        }
        for name, body in fixtures.items():
            (out / name).write_text(body, encoding="utf-8")
        (aud / "agent_output_inventory.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "path": str(out / name),
                            "claims_detected": ["verdict", "candidate"],
                        }
                        for name in fixtures
                    ]
                }
            ),
            encoding="utf-8",
        )
        (aud / "coverage_inventory.json").write_text(
            json.dumps({"rows": [], "status": "ok"}),
            encoding="utf-8",
        )
        (aud / "impact_contracts.json").write_text(
            json.dumps(
                {
                    "contracts": [
                        {
                            "impact_contract_id": "impact-contract-vault-redemption",
                            "candidate_id": "vault_Holdings_RedemptionBounds",
                            "selected_impact": "Temporary freezing of user funds",
                            "severity": "High",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (ws / "detector_findings.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "id": "detector-negrisk-feemodule",
                            "title": "NegRiskFeeModuleCtfRevert",
                            "detector_id": "polymarket-negrisk-feemodule",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        payload = tool.render_agent_recall(ws)
        self.assertEqual(payload["status"], "ok")
        by_name = {Path(row["agent_output"]).name: row for row in payload["rows"]}
        self.assertEqual(
            by_name["iter4_T1_revalidate_negrisk.log"]["status"],
            "detectorized",
        )
        self.assertEqual(
            by_name["capv3_iter5_T1_live_R83-A.notes.json"]["status"],
            "killed_duplicate_or_oos",
        )
        self.assertEqual(
            by_name["FN7_EXPLOITABILITY_RESEARCH_2026-04-29.md"]["status"],
            "blocked_missing_impact_contract",
        )
        self.assertEqual(
            by_name["capv3_iter9_T1_review_candidate_vault_Holdings_RedemptionBounds.md"]["status"],
            "harness_task_required",
        )
        self.assertEqual(
            by_name["base_source_reader_invariant.md"]["status"],
            "source_proof_required",
        )
        self.assertFalse(
            any(row["status"] == "needs_local_verification" for row in payload["rows"])
        )

    def test_source_proof_task_queue_routes_three_base_recall_rows_without_proof(self):
        ws = self.make_ws()
        audit = ws / ".auditooor"
        audit.mkdir(exist_ok=True)
        (audit / "impact_contracts.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.pr560.impact_contracts.v1",
                    "contracts": [
                        {
                            "impact_contract_id": "impact-contract-base-snappy-resource",
                            "candidate_id": "BASE-SNAPPY-SOURCE",
                            "selected_impact": "Increasing network processing node resource consumption by at least 30%",
                            "severity": "Medium",
                            "exact_impact_row": True,
                            "listed_impact_proven": False,
                            "posture": "NOT_SUBMIT_READY",
                        },
                        {
                            "impact_contract_id": "impact-contract-base-node-shutdown",
                            "candidate_id": "BASE-NODE-SHUTDOWN-SOURCE",
                            "selected_impact": "Network not being able to confirm new transactions",
                            "severity": "Critical",
                            "exact_impact_row": True,
                            "listed_impact_proven": False,
                            "posture": "NOT_SUBMIT_READY",
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        (audit / "agent_found_not_detector_found.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.pr560.agent_recall.v1",
                    "rows": [
                        {
                            "status": "source_proof_required",
                            "agent_output": "agent_outputs/base_snappy_source.md",
                            "candidate_id": "BASE-SNAPPY-SOURCE",
                            "claims_detected": ["op-node/p2p/snappy.rs:40-55"],
                            "oos_status": "in_scope",
                            "reason": "Base source-reader row needs source proof only",
                        },
                        {
                            "status": "source_proof_required",
                            "agent_output": "agent_outputs/base_missing_contract.md",
                            "candidate_id": "BASE-MISSING-CONTRACT",
                            "claims_detected": ["op-node/engine/validator.rs:10-12"],
                            "oos_status": "in_scope",
                            "reason": "missing exact impact contract",
                        },
                        {
                            "status": "source_proof_required",
                            "agent_output": "agent_outputs/base_oos_unknown.md",
                            "candidate_id": "BASE-NODE-SHUTDOWN-SOURCE",
                            "claims_detected": ["op-node/rollup/driver.rs:90-110"],
                            "reason": "OOS not checked yet",
                        },
                        {
                            "status": "harness_task_required",
                            "candidate_id": "BASE-HARNESS-ROW",
                            "claims_detected": ["forge test required"],
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )

        payload = tool.render_source_proof_task_queue(ws)
        self.assertEqual(payload["schema"], "auditooor.pr560.source_proof_tasks.v1")
        self.assertEqual(payload["summary"]["row_count"], 3)
        by_candidate = {row["candidate_id"]: row for row in payload["rows"]}
        self.assertEqual(
            by_candidate["BASE-SNAPPY-SOURCE"]["status"],
            "ready_for_source_review",
        )
        self.assertEqual(
            by_candidate["BASE-MISSING-CONTRACT"]["status"],
            "blocked_missing_impact_contract",
        )
        self.assertEqual(
            by_candidate["BASE-NODE-SHUTDOWN-SOURCE"]["status"],
            "blocked_oos_not_checked",
        )
        for row in payload["rows"]:
            self.assertFalse(row["proof_fabricated"])
            self.assertIn("make source-proof-record", row["next_command"])
            self.assertIn(f"CANDIDATE={row['candidate_id']}", row["next_command"])
            self.assertIn("VERDICT=blocked_missing_impact_contract", row["next_command"])
            self.assertIn("required_citations", row)
            self.assertEqual(row["local_evidence_status"], "missing")
            self.assertFalse(row["resolved_by_local_evidence"])
            self.assertEqual(row["submit_ready"], False)
            self.assertEqual(row["severity"], "none")
            self.assertIn("required_evidence", row)
            self.assertIn(row["terminal_evidence_path"], row["required_evidence"][0])
            self.assertIn("VERDICT=proved_source_only", row["proved_after_review_command"])
        self.assertIn(
            "op-node/p2p/snappy.rs:40-55",
            by_candidate["BASE-SNAPPY-SOURCE"]["required_citations"],
        )
        self.assertTrue((audit / "source_proof_tasks.json").is_file())
        self.assertTrue((audit / "source_proof_tasks.md").is_file())

    def test_source_proof_task_queue_cli_json(self):
        ws = self.make_ws()
        audit = ws / ".auditooor"
        audit.mkdir(exist_ok=True)
        (audit / "agent_found_not_detector_found.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "status": "source_proof_required",
                            "candidate_id": "BASE-CLI-SOURCE",
                            "claims_detected": ["op-node/source.rs:1-2"],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--workspace",
                str(ws),
                "--mode",
                "source-proof-task-queue",
                "--json",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["summary"]["row_count"], 1)
        self.assertEqual(payload["rows"][0]["candidate_id"], "BASE-CLI-SOURCE")

    def test_source_proof_queue_extracts_citation_and_stable_id_from_recall_fields(self):
        ws = self.make_ws()
        audit = ws / ".auditooor"
        audit.mkdir(exist_ok=True)
        (audit / "impact_contracts.json").write_text(
            json.dumps(
                {
                    "contracts": [
                        {
                            "impact_contract_id": "impact-contract-source-path",
                            "source_id": "SRC-ENGINE-1",
                            "selected_impact": "Direct theft of user funds",
                            "severity": "Critical",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (audit / "agent_found_not_detector_found.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "status": "source_proof_required",
                            "source_id": "SRC-ENGINE-1",
                            "agent_output": "agent_outputs/base_engine_source.md",
                            "claims_detected": ["source reader found crates/engine/src/lib.rs:44-49"],
                            "oos_status": "in_scope",
                            "reason": "line-cited source proof required",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        row = tool.render_source_proof_task_queue(ws)["rows"][0]
        self.assertEqual(row["candidate_id"], "SOURCE-PROOF-SRC-ENGINE-1-AGENT-OUTPUTS-BASE-ENGINE-SOURCE-MD")
        self.assertEqual(row["source_artifact"], "agent_outputs/base_engine_source.md")
        self.assertEqual(row["required_citations"], ["crates/engine/src/lib.rs:44-49"])
        self.assertEqual(row["status"], "ready_for_source_review")
        self.assertEqual(row["missing_preconditions"], [])
        self.assertFalse(row["proof_fabricated"])
        self.assertEqual(row["default_verdict"], "blocked_missing_impact_contract")
        self.assertIn("VERDICT=blocked_missing_impact_contract", row["next_command"])
        self.assertEqual(row["local_evidence_status"], "missing")
        self.assertIn("write_terminal_source_proof_record", row["required_evidence"][0])

    def test_source_proof_queue_missing_citation_has_manual_step(self):
        ws = self.make_ws()
        audit = ws / ".auditooor"
        audit.mkdir(exist_ok=True)
        (audit / "impact_contracts.json").write_text(
            json.dumps(
                {
                    "contracts": [
                        {
                            "impact_contract_id": "impact-contract-manual-citation",
                            "candidate_id": "MANUAL-CITATION",
                            "selected_impact": "Direct theft of user funds",
                            "severity": "Critical",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (audit / "agent_found_not_detector_found.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "status": "source_proof_required",
                            "candidate_id": "MANUAL-CITATION",
                            "agent_output": "agent_outputs/manual_citation_needed.md",
                            "claims_detected": ["source proof needed but no line citation"],
                            "oos_status": "in_scope",
                            "reason": "inspect agent_outputs/manual_citation_needed.md",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        row = tool.render_source_proof_task_queue(ws)["rows"][0]
        self.assertEqual(row["status"], "blocked_missing_citations")
        self.assertIn("required_source_citation", row["missing_preconditions"])
        self.assertIn("agent_outputs/manual_citation_needed.md", row["required_manual_step"])
        self.assertIn("missing_preconditions=required_source_citation", row["next_command"])
        self.assertIn("add at least one exact source file:line citation", row["required_evidence"])
        self.assertFalse(row["proof_fabricated"])

    def test_source_proof_queue_oos_not_checked_blocks_with_exact_precondition(self):
        ws = self.make_ws()
        audit = ws / ".auditooor"
        audit.mkdir(exist_ok=True)
        (audit / "impact_contracts.json").write_text(
            json.dumps(
                {
                    "contracts": [
                        {
                            "impact_contract_id": "impact-contract-oos",
                            "candidate_id": "OOS-CHECK",
                            "selected_impact": "Direct theft of user funds",
                            "severity": "Critical",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (audit / "agent_found_not_detector_found.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "status": "source_proof_required",
                            "candidate_id": "OOS-CHECK",
                            "agent_output": "agent_outputs/oos.md",
                            "claims_detected": ["contracts/Vault.sol:22-25"],
                            "reason": "OOS not checked yet",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        row = tool.render_source_proof_task_queue(ws)["rows"][0]
        self.assertEqual(row["oos_status"], "not_checked")
        self.assertEqual(row["status"], "blocked_oos_not_checked")
        self.assertIn("oos_status:not_checked", row["missing_preconditions"])
        self.assertIn("missing_preconditions=oos_status:not_checked", row["next_command"])
        self.assertIn("run/record OOS check with oos_status=in_scope before proved_source_only", row["required_evidence"])

    def test_source_proof_queue_missing_impact_contract_keeps_artifact_and_blocks(self):
        ws = self.make_ws()
        audit = ws / ".auditooor"
        audit.mkdir(exist_ok=True)
        (audit / "impact_contracts.json").write_text(json.dumps({"contracts": []}), encoding="utf-8")
        (audit / "agent_found_not_detector_found.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "status": "source_proof_required",
                            "source_id": "SRC-MISSING-IMPACT",
                            "agent_output": "agent_outputs/missing_impact.md",
                            "claims_detected": ["src/Router.sol:5-7"],
                            "oos_status": "in_scope",
                            "reason": "reportable claim lacks impact contract",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        row = tool.render_source_proof_task_queue(ws)["rows"][0]
        self.assertEqual(row["status"], "blocked_missing_impact_contract")
        self.assertEqual(row["impact_contract_precondition"], "missing")
        self.assertEqual(row["source_artifact"], "agent_outputs/missing_impact.md")
        self.assertEqual(row["selected_impact"], "")
        self.assertIn("impact_contract_id", row["missing_preconditions"])
        self.assertIn("src/Router.sol:5-7", row["required_citations"])
        self.assertIn("missing_preconditions=impact_contract_id", row["next_command"])
        self.assertIn("lock exact impact_contract_id before proved_source_only", row["required_evidence"])

    def test_source_proof_queue_terminal_only_when_local_evidence_exists(self):
        ws = self.make_ws()
        audit = ws / ".auditooor"
        audit.mkdir(exist_ok=True)
        (ws / "src").mkdir()
        (ws / "src" / "Vault.sol").write_text("contract Vault {\nfunction withdraw() external {}\n}\n", encoding="utf-8")
        (audit / "impact_contracts.json").write_text(
            json.dumps(
                {
                    "contracts": [
                        {
                            "impact_contract_id": "impact-contract-source-terminal",
                            "candidate_id": "SOURCE-TERMINAL",
                            "selected_impact": "Direct theft of user funds",
                            "original_selected_impact": "Direct theft of user funds",
                            "severity": "Critical",
                            "exact_impact_row": True,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (audit / "agent_found_not_detector_found.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "status": "source_proof_required",
                            "candidate_id": "SOURCE-TERMINAL",
                            "claims_detected": ["src/Vault.sol:1-2"],
                            "oos_status": "in_scope",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        proof_dir = ws / "source_proofs" / "SOURCE-TERMINAL"
        proof_dir.mkdir(parents=True)
        (proof_dir / "source_proof.json").write_text(
            json.dumps(
                {
                    "schema_version": "auditooor.source_proof.v1",
                    "candidate_id": "SOURCE-TERMINAL",
                    "final_verdict": "proved_source_only",
                    "source_citations": [{"raw": "src/Vault.sol:1-2"}],
                }
            ),
            encoding="utf-8",
        )

        payload = tool.render_source_proof_task_queue(ws)
        row = payload["rows"][0]
        self.assertEqual(row["status"], "terminal_evidence_present")
        self.assertEqual(row["local_evidence_status"], "present")
        self.assertTrue(row["resolved_by_local_evidence"])
        self.assertEqual(row["local_evidence_final_verdict"], "proved_source_only")
        self.assertEqual(payload["summary"]["local_evidence_present"], 1)
        self.assertEqual(payload["summary"]["local_evidence_missing"], 0)
        self.assertEqual(row["next_command"], "local source proof evidence already recorded; inspect terminal_evidence_path")
        self.assertEqual(row["severity"], "none")
        self.assertFalse(row["submit_ready"])

    def test_impact_analysis_queue_routes_blocked_recall_rows(self):
        ws = self.make_second_ws()
        aud = ws / ".auditooor"
        out = ws / "agent_outputs"
        out.mkdir(exist_ok=True)
        fixtures = {
            "base_exact.md": (
                "Critical candidate: Network nodes can be forced to stop "
                "processing new blocks through one crafted peer message."
            ),
            "base_harness.md": (
                "Critical candidate with Scenario C harness and PoC replay, "
                "but no exact impact contract yet."
            ),
            "base_source.md": (
                "High candidate needs source proof at crates/node/src/engine.rs "
                "before an impact contract can be selected."
            ),
            "base_dupe.md": "Critical candidate killed as duplicate / OOS.",
        }
        for name, body in fixtures.items():
            (out / name).write_text(body, encoding="utf-8")
        (aud / "agent_found_not_detector_found.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "agent_output": str(out / name),
                            "claims_detected": ["candidate"],
                            "status": "blocked_missing_impact_contract",
                        }
                        for name in fixtures
                    ]
                }
            ),
            encoding="utf-8",
        )
        tool.render_impact_matrix(ws)

        payload = tool.render_impact_analysis_queue(ws)
        self.assertEqual(payload["status"], "ok")
        by_name = {Path(row["agent_output"]).name: row for row in payload["rows"]}
        self.assertEqual(by_name["base_exact.md"]["action_type"], "exact_impact_candidate")
        self.assertTrue(by_name["base_exact.md"]["exact_impact_candidates"])
        self.assertEqual(by_name["base_harness.md"]["action_type"], "harness_precondition")
        self.assertEqual(by_name["base_source.md"]["action_type"], "source_proof_precondition")
        self.assertEqual(by_name["base_dupe.md"]["action_type"], "oos_duplicate_kill")
        self.assertTrue(all(row["severity"] == "none" for row in payload["rows"]))
        self.assertFalse(any(row["submit_ready"] for row in payload["rows"]))
        self.assertTrue((aud / "impact_analysis_queue.json").is_file())

    def test_impact_analysis_queue_base_smoke_17_blocked_rows(self):
        ws = self.make_second_ws()
        aud = ws / ".auditooor"
        out = ws / "agent_outputs"
        out.mkdir(exist_ok=True)
        rows = []
        for idx in range(17):
            if idx % 4 == 0:
                body = (
                    "Base agent recall: Network nodes can be forced to stop "
                    "processing new blocks through one crafted peer message."
                )
            elif idx % 4 == 1:
                body = "Base agent recall: Scenario C harness required before proof."
            elif idx % 4 == 2:
                body = "Base agent recall: source proof needed in crates/node/src/engine.rs."
            else:
                body = "Base agent recall: duplicate / OOS killed row."
            path = out / f"base_blocked_{idx:02d}.md"
            path.write_text(body, encoding="utf-8")
            rows.append(
                {
                    "agent_output": str(path),
                    "claims_detected": ["candidate"],
                    "status": "blocked_missing_impact_contract",
                }
            )
        (aud / "agent_found_not_detector_found.json").write_text(
            json.dumps({"rows": rows}),
            encoding="utf-8",
        )
        tool.render_impact_matrix(ws)

        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--workspace",
                str(ws),
                "--mode",
                "impact-analysis-queue",
                "--json",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["summary"]["blocked_missing_impact_contract"], 17)
        self.assertEqual(len(payload["rows"]), 17)
        self.assertFalse(any(row["submit_ready"] for row in payload["rows"]))
        self.assertTrue(
            all(row["action_type"] in payload["allowed_actions"] for row in payload["rows"])
        )

    def test_cli_json(self):
        ws = self.make_ws()
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--workspace",
                str(ws),
                "--mode",
                "automation-closure",
                "--json",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertEqual(data["schema"], "auditooor.pr560.automation_closure.v1")

    def test_strict_mode_fails_named_blockers_and_passes_complete_fixture(self):
        blocked_ws = self.make_ws()
        blocked = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--workspace",
                str(blocked_ws),
                "--mode",
                "coverage-inventory",
                "--strict",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(blocked.returncode, 1, blocked.stdout + blocked.stderr)

        ok_ws = self.make_second_ws()
        ok = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--workspace",
                str(ok_ws),
                "--mode",
                "coverage-inventory",
                "--strict",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)

    def test_known_limitations_burndown_artifact(self):
        ws = self.make_ws()
        generated = self.write_generated_invariants(ws, missing=0)
        payload = tool.render_known_limitations_burndown(ws)
        self.assertEqual(payload["schema"], "auditooor.pr560.known_limitations_burndown.v1")
        self.assertIn("strict_policy", payload)
        self.assertEqual(
            payload["truth_source_policy"]["canonical_for_github_packaging"],
            "workspace_generated_burndown",
        )
        self.assertEqual(
            payload["truth_source_policy"]["workspace_generated_row_count"],
            len(payload["rows"]),
        )
        self.assertEqual(
            payload["truth_source_policy"]["workspace_generated_stop_conditions_met"],
            sum(1 for row in payload["rows"] if row.get("stop_condition_met")),
        )
        self.assertLessEqual(
            payload["truth_source_policy"]["seed_map_stop_conditions_met"],
            payload["truth_source_policy"]["workspace_generated_row_count"],
        )
        self.assertIn("baseline input only", payload["truth_source_policy"]["count_policy"])
        self.assertEqual(payload["checklist_accounting"]["item_count"], len(payload["rows"]) * 9)
        self.assertGreaterEqual(payload["checklist_accounting"]["item_count"], 50)
        self.assertGreaterEqual(payload["checklist_accounting"]["command_level_blocker_count"], 48)
        self.assertEqual(
            set(payload["checklist_accounting"]["command_blocker_category_counts"]),
            set(payload["checklist_accounting"]["blocker_category_counts"]),
        )
        self.assertTrue(
            all(
                blocker.get("next_command") and blocker.get("blocker")
                for blocker in payload["command_level_blockers"]
            )
        )
        self.assertEqual(payload["invariant_discovery"]["status"], "advisory_all_generated_invariants_accepted")
        self.assertEqual(payload["invariant_discovery"]["artifact_path"], str(generated))
        self.assertIn("impact_miss_benchmark_accounting", payload)
        self.assertEqual(payload["impact_miss_benchmark_accounting"]["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(payload["impact_miss_benchmark_accounting"]["promotion_allowed"])
        self.assertTrue(payload["rows"])
        current_p0 = [r for r in payload["rows"] if r.get("priority_group") in {"current_priority", "P0"}]
        self.assertTrue(current_p0)
        self.assertTrue(all("strict_status" in r for r in current_p0))
        inv_rows = [r for r in current_p0 if "Invariant discovery" in r.get("title", "")]
        self.assertTrue(inv_rows)
        self.assertTrue(all(r["invariant_discovery_status"] == "advisory_all_generated_invariants_accepted" for r in inv_rows))
        self.assertTrue(all(r["invariant_discovery_artifact_path"] == str(generated) for r in inv_rows))
        self.assertTrue(all(r.get("closure_checklist") for r in current_p0))
        checklist_ids = {
            item.get("check_id")
            for row in payload["rows"]
            for item in row.get("closure_checklist", [])
        }
        self.assertIn("command-blockers", checklist_ids)
        self.assertIn("next-command-shape", checklist_ids)
        self.assertIn("blocked_named:priority-4", payload["checklist_accounting"]["blocker_category_counts"])
        self.assertNotIn("open_stop_condition_not_met", payload["checklist_accounting"]["blocker_category_counts"])
        self.assertEqual(payload["execution_proof_task_queue"]["summary"]["task_count"], 50)
        self.assertEqual(payload["execution_proof_task_queue"]["summary"]["open_limitation_count"], 5)
        self.assertEqual(payload["execution_proof_task_queue"]["summary"]["tasks_per_limitation"], 10)
        self.assertEqual(payload["execution_proof_task_queue"]["summary"]["invalid_proved_manifest"], 0)
        self.assertEqual(
            payload["execution_proof_task_queue"]["summary"]["tasks_by_limitation"]["P0-6"],
            10,
        )
        self.assertTrue((ws / ".auditooor" / "known_limitations_burndown.json").is_file())
        self.assertTrue((ws / ".auditooor" / "execution_proof_task_queue.json").is_file())
        self.assertTrue((ws / ".auditooor" / "execution_proof_task_queue.md").is_file())

    def test_invariant_adoption_closes_priority4_but_not_full_p0(self):
        ws = self.make_ws()
        self.write_generated_invariants(ws, missing=0)
        adoption = self.write_invariant_adoption(ws)
        readiness = self.write_invariant_adoption_closure_readiness(ws)
        payload = tool.render_known_limitations_burndown(ws)
        rows = {r["limitation_id"]: r for r in payload["rows"]}
        self.assertTrue(rows["priority-4"]["stop_condition_met"])
        self.assertEqual(
            rows["priority-4"]["blocker_category"],
            "stop_condition_met",
        )
        self.assertEqual(
            rows["priority-4"]["invariant_discovery_adoption_artifact_path"],
            str(adoption),
        )
        self.assertFalse(rows["P0-0"]["stop_condition_met"])
        self.assertEqual(
            rows["P0-0"]["reduction_status"],
            "reduced_current_workspace_invariant_adoption_not_full_p0",
        )
        self.assertEqual(
            rows["P0-0"]["invariant_adoption_closure_readiness_artifact_path"],
            str(readiness),
        )
        self.assertIn(
            "fresh_engagement_adoption_metrics_missing_or_below_threshold",
            rows["P0-0"]["remaining_after_560"],
        )
        self.assertEqual(
            payload["invariant_discovery_adoption_accounting"]["status"],
            "high_critical_route_families_have_invariant_blocker_rows",
        )
        self.assertEqual(
            payload["invariant_adoption_closure_readiness_accounting"]["status"],
            "p0_invariant_adoption_blocked_exact",
        )

    def test_invariant_adoption_readiness_can_close_p0_when_strict_gate_passes(self):
        ws = self.make_ws()
        self.write_generated_invariants(ws, missing=0)
        self.write_invariant_adoption(ws)
        self.write_invariant_adoption_closure_readiness(ws, ready=True)
        payload = tool.render_known_limitations_burndown(ws)
        rows = {r["limitation_id"]: r for r in payload["rows"]}
        self.assertTrue(rows["P0-0"]["stop_condition_met"])
        self.assertEqual(
            rows["P0-0"]["reduction_status"],
            "p0_invariant_adoption_stop_condition_met",
        )

    def test_known_limitations_execution_proof_queue_validates_manifest_gates(self):
        ws = self.make_ws()
        for candidate_id, manifest in {
            "good": {
                "candidate_id": "good",
                "final_result": "proved",
                "impact_assertion": "exploit_impact",
                "commands_attempted": [{"command": "forge test", "status": "pass", "exit_code": 0}],
                "evidence_class": "executed_with_manifest",
            },
            "bad-proved": {
                "candidate_id": "bad-proved",
                "final_result": "proved",
                "impact_assertion": "setup_or_branch_only",
                "commands_attempted": [{"command": "forge test", "status": "pass", "exit_code": 0}],
                "evidence_class": "executed_with_manifest",
            },
            "needs-human": {
                "candidate_id": "needs-human",
                "final_result": "needs_human",
                "impact_assertion": "unknown",
                "commands_attempted": [],
                "evidence_class": "scaffolded_unverified",
            },
        }.items():
            path = ws / "poc_execution" / candidate_id / "execution_manifest.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(manifest), encoding="utf-8")

        payload = tool.render_known_limitations_burndown(ws)
        queue = json.loads(
            (ws / ".auditooor" / "execution_proof_task_queue.json").read_text(encoding="utf-8")
        )
        self.assertEqual(queue["status"], "blocked_invalid_proved_manifest")
        self.assertEqual(queue["summary"]["task_count"], 50)
        self.assertEqual(queue["summary"]["proof_counted"], 1)
        self.assertEqual(queue["summary"]["invalid_proved_manifest"], 1)
        self.assertEqual(
            queue["execution_manifest_gate_validation"]["summary"]["status_counts"],
            {"invalid_proved_manifest": 1, "not_proof": 1, "proof_counted": 1},
        )
        self.assertEqual(payload["execution_proof_task_queue"]["status"], "blocked_invalid_proved_manifest")
        self.assertEqual(payload["execution_proof_task_queue"]["summary"]["proof_counted"], 1)

    def test_known_limitations_reduces_execution_rows_with_source_import_readiness_without_promotion(self):
        ws = self.make_ws()
        audit_dir = ws / ".auditooor"
        audit_dir.mkdir(exist_ok=True)
        (audit_dir / "project_source_root_readiness.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.project_source_root_readiness.v1",
                    "declared_root_count": 0,
                    "ready_root_count": 0,
                    "rejected_root_count": 0,
                    "source_file_count": 0,
                    "promotion_allowed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                    "summary": {"status_counts": {}},
                }
            ),
            encoding="utf-8",
        )
        (audit_dir / "impact_binding_source_import_readiness.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.pr560.impact_binding_source_import_readiness.v1",
                    "source_import_unit_count": 480,
                    "ready_source_file_count": 0,
                    "line_hit_unit_count": 0,
                    "promotion_allowed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                    "summary": {
                        "missing_input_counts": {
                            "candidate_bound_project_source_citation": 480,
                            "project_source_root": 480,
                        },
                        "source_import_status_counts": {
                            "terminal_no_ready_project_source_roots": 480,
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        (audit_dir / "execution_manifest_proof_readiness.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.pr560.execution_manifest_proof_readiness.v1",
                    "proved_execution_requirement_count": 160,
                    "proof_ready_count": 0,
                    "closed_proof_count": 0,
                    "promotion_allowed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                    "summary": {
                        "missing_input_counts": {
                            "candidate_bound_project_source_citation": 160,
                            "final_result_proved": 160,
                            "impact_assertion_exploit_impact": 160,
                            "project_harness_binding": 160,
                            "project_source_root": 160,
                        },
                        "readiness_status_counts": {
                            "terminal_no_project_source_root_for_execution_proof": 160,
                        },
                    },
                }
            ),
            encoding="utf-8",
        )

        payload = tool.render_known_limitations_burndown(ws)
        accounting = payload["execution_source_import_workflow_accounting"]
        self.assertEqual(
            accounting["status"],
            "workflow_reduced_real_source_and_proved_manifest_missing",
        )
        self.assertTrue(accounting["workflow_reduction_stop_condition_accounted"])
        self.assertEqual(accounting["proved_execution_requirement_count"], 160)
        self.assertEqual(accounting["source_import_unit_count"], 480)
        self.assertEqual(accounting["proof_ready_count"], 0)
        self.assertEqual(accounting["ready_project_source_root_count"], 0)
        self.assertTrue((audit_dir / "execution_source_import_workflow_accounting.json").is_file())
        self.assertTrue((audit_dir / "execution_source_import_workflow_accounting.md").is_file())

        rows = {row["limitation_id"]: row for row in payload["rows"]}
        for limitation_id in ("P0-1", "P0-6", "P1-5", "priority-5", "priority-6"):
            row = rows[limitation_id]
            self.assertEqual(
                row["reduction_status"],
                "execution_source_import_workflow_reduced_real_proof_missing",
            )
            self.assertFalse(row.get("stop_condition_met", False))
            self.assertFalse(row["promotion_allowed"])
            self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
            self.assertIn("candidate-bound project source citations", row["remaining_after_560"])

    def test_known_limitations_burndown_wires_semantic_live_depth_counts_without_promotion(self):
        ws = self.make_ws()
        self.write_semantic_live_depth_fixture(ws, count=420, closed_count=400)

        payload = tool.render_known_limitations_burndown(ws)
        accounting = payload["semantic_live_depth_accounting"]
        self.assertEqual(accounting["concrete_item_target"], 400)
        self.assertEqual(accounting["concrete_item_count"], 400)
        self.assertEqual(accounting["terminal_depth_closed_count"], 400)
        self.assertEqual(accounting["blocked_depth_count"], 0)
        self.assertEqual(accounting["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(accounting["promotion_allowed"])
        self.assertTrue((ws / ".auditooor" / "semantic_live_depth_blockers.json").is_file())
        self.assertTrue((ws / ".auditooor" / "semantic_live_depth_queue.json").is_file())

        semantic_rows = [
            row for row in payload["rows"]
            if row.get("blocker_category") == "open_semantic_or_live_topology_depth"
            and row.get("limitation_id") != "P1-3"
        ]
        self.assertTrue(semantic_rows)
        for row in semantic_rows:
            self.assertEqual(row["semantic_live_terminal_depth_closed_count"], 400)
            self.assertEqual(row["semantic_live_blocked_depth_count"], 0)
            self.assertEqual(row["semantic_live_concrete_item_target"], 400)
            self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
            self.assertFalse(row["promotion_allowed"])
            self.assertEqual(row["reduction_status"], "semantic_live_depth_rows_closed_accounting_only")
            self.assertFalse(row.get("stop_condition_met", False))

    def test_known_limitations_burndown_keeps_semantic_live_rows_blocked_without_exact_pairs(self):
        ws = self.make_ws()
        self.write_semantic_live_depth_fixture(ws, count=3, closed_count=0)

        payload = tool.render_known_limitations_burndown(ws)
        accounting = payload["semantic_live_depth_accounting"]
        self.assertEqual(accounting["terminal_depth_closed_count"], 0)
        self.assertEqual(accounting["blocked_depth_count"], 3)
        self.assertEqual(accounting["status"], "blocked_missing_exact_same_block_pairs")
        self.assertEqual(accounting["submission_posture"], "NOT_SUBMIT_READY")

        semantic_rows = [
            row for row in payload["rows"]
            if row.get("blocker_category") == "open_semantic_or_live_topology_depth"
            and row.get("limitation_id") != "P1-3"
        ]
        self.assertTrue(semantic_rows)
        self.assertTrue(
            all(row["reduction_status"] == "semantic_live_depth_rows_blocked_or_missing" for row in semantic_rows)
        )
        self.assertTrue(all(not row.get("stop_condition_met", False) for row in semantic_rows))

    def test_known_limitations_burndown_reduces_semantic_live_with_hermetic_workflow_only(self):
        ws = self.make_ws()
        self.write_semantic_live_depth_fixture(ws, count=3, closed_count=0)
        audit_dir = ws / ".auditooor"
        (audit_dir / "pr560_worker_manual_proof_materializer_executor_integration.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.pr560_worker_manual_proof_materializer_executor_integration.v1",
                    "proof_workflow_reductions": {
                        "hermetic_same_block_positive_fixture": {
                            "validator_rows": 2,
                            "materialized_manual_proofs": 2,
                            "manual_import_rows": 2,
                            "executor_depth_closure_candidates": 1,
                            "submission_posture": "NOT_SUBMIT_READY",
                            "severity": "none",
                            "promotion_allowed": False,
                            "claim_boundary": "semantic_live_topology_depth_only",
                        },
                        "hermetic_cross_block_negative_fixture": {
                            "validator_rows": 2,
                            "materialized_manual_proofs": 0,
                            "executor_depth_closure_candidates": 0,
                            "blocked_status": "terminal_missing_live_topology_checks",
                            "blocker_kind": "missing_live_topology_artifact",
                        },
                    },
                    "closed_real_workspace_proof_pairs": 0,
                    "promoted_findings": 0,
                }
            ),
            encoding="utf-8",
        )
        (audit_dir / "live_topology_proof_input_validator.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.live_topology_proof_input_validator.v1",
                    "promotion_allowed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                    "summary": {
                        "proof_pairs_total": 350,
                        "rows_total": 700,
                        "proof_pairs_closed": 0,
                        "proof_pairs_promoted": 0,
                        "import_ready_pairs": 0,
                        "pair_validation_state_counts": {"manual_proof_files_missing": 350},
                    },
                }
            ),
            encoding="utf-8",
        )
        (audit_dir / "live_topology_manual_proof_materializer.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.live_topology_manual_proof_materializer.v1",
                    "promotion_allowed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                    "summary": {
                        "proof_pairs_total": 350,
                        "rows_total": 700,
                        "proof_pairs_closed": 0,
                        "proof_pairs_promoted": 0,
                        "canonical_import_ready_pairs": 0,
                        "canonical_rows_materialized": 0,
                        "pair_materialization_state_counts": {"no_canonical_manual_proofs_ready": 350},
                    },
                }
            ),
            encoding="utf-8",
        )

        payload = tool.render_known_limitations_burndown(ws)
        workflow = payload["live_topology_hermetic_workflow_accounting"]
        self.assertEqual(workflow["status"], "hermetic_workflow_validated_real_workspace_proof_missing")
        self.assertTrue(workflow["hermetic_workflow_validated"])
        self.assertEqual(workflow["hermetic_same_block_depth_closure_candidates"], 1)
        self.assertEqual(workflow["closed_real_workspace_semantic_live_rows"], 0)
        self.assertFalse(workflow["promotion_allowed"])
        self.assertTrue((audit_dir / "live_topology_hermetic_workflow_bridge.json").is_file())
        self.assertTrue((audit_dir / "live_topology_hermetic_workflow_bridge.md").is_file())

        semantic_rows = [
            row for row in payload["rows"]
            if row.get("blocker_category") == "open_semantic_or_live_topology_depth"
        ]
        self.assertTrue(semantic_rows)
        self.assertTrue(
            all(
                row["reduction_status"] == "semantic_live_hermetic_workflow_validated_real_pairs_missing"
                for row in semantic_rows
            )
        )
        self.assertTrue(all(row["semantic_live_terminal_depth_closed_count"] == 0 for row in semantic_rows))
        self.assertTrue(all(not row.get("stop_condition_met", False) for row in semantic_rows))

    def test_known_limitations_burndown_reduces_semantic_live_with_real_input_workflow(self):
        ws = self.make_ws()
        self.write_semantic_live_depth_fixture(ws, count=3, closed_count=0)
        audit_dir = ws / ".auditooor"
        (audit_dir / "live_topology_real_proof_input_router.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.live_topology_real_proof_input_router.v1",
                    "promotion_allowed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                    "summary": {
                        "proof_pairs_total": 350,
                        "rows_total": 700,
                        "proof_pairs_closed": 0,
                        "proof_pairs_promoted": 0,
                        "same_block_ready_pairs": 0,
                        "provided_rows_written": 0,
                        "pair_routing_state_counts": {"real_proof_inputs_missing": 350},
                        "row_routing_state_counts": {"real_proof_row_missing": 700},
                    },
                }
            ),
            encoding="utf-8",
        )
        (audit_dir / "live_topology_manual_proof_materializer.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.live_topology_manual_proof_materializer.v1",
                    "promotion_allowed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                    "summary": {
                        "proof_pairs_total": 350,
                        "rows_total": 700,
                        "proof_pairs_closed": 0,
                        "proof_pairs_promoted": 0,
                        "canonical_import_ready_pairs": 0,
                        "canonical_rows_materialized": 0,
                        "pair_materialization_state_counts": {"no_canonical_manual_proofs_ready": 350},
                    },
                }
            ),
            encoding="utf-8",
        )

        payload = tool.render_known_limitations_burndown(ws)
        workflow = payload["live_topology_real_input_workflow_accounting"]
        self.assertEqual(workflow["status"], "real_input_workflow_reduced_exact_inputs_missing")
        self.assertTrue(workflow["real_input_workflow_reduced"])
        self.assertEqual(workflow["proof_pairs_total"], 350)
        self.assertEqual(workflow["rows_total"], 700)
        self.assertEqual(workflow["same_block_ready_pairs"], 0)
        self.assertEqual(workflow["provided_rows_written"], 0)
        self.assertEqual(workflow["proof_pairs_closed"], 0)
        self.assertFalse(workflow["promotion_allowed"])
        self.assertTrue((audit_dir / "live_topology_real_input_workflow_reduction.json").is_file())
        self.assertTrue((audit_dir / "live_topology_real_input_workflow_reduction.md").is_file())

        semantic_rows = [
            row for row in payload["rows"]
            if row.get("blocker_category") == "open_semantic_or_live_topology_depth"
            and row.get("limitation_id") != "P1-3"
        ]
        self.assertTrue(semantic_rows)
        self.assertTrue(
            all(
                row["reduction_status"] == "semantic_live_real_input_workflow_reduced_inputs_missing"
                for row in semantic_rows
            )
        )
        self.assertTrue(all(row["live_topology_real_input_workflow_accounting"]["real_input_workflow_reduced"] for row in semantic_rows))
        self.assertTrue(all(not row.get("stop_condition_met", False) for row in semantic_rows))

    def test_known_limitations_burndown_counts_scoped_semantic_rows_blocked_when_live_topology_missing(self):
        ws = self.make_ws()
        aud = ws / ".auditooor"
        aud.mkdir(exist_ok=True)
        relation_edges = []
        for idx in range(420):
            relation_edges.append(
                {
                    "source_contract": f"Portal{idx}",
                    "source_function": "finalizeWithdrawal",
                    "kind": "bridge-finalizer-call",
                    "target": f"Bridge{idx}",
                    "target_type": f"Bridge{idx}",
                    "method": "finalizeWithdrawal",
                    "file": f"src/Portal{idx}.sol",
                    "line": idx + 10,
                }
            )
        (aud / "callgraph_de_semantic_graph_fixtures.json").write_text(
            json.dumps(
                {
                    "schema_version": "auditooor.semantic_graph.v1",
                    "workspace": str(ws),
                    "contracts": [],
                    "entrypoints": [],
                    "relation_edges": relation_edges,
                    "multi_hop_paths": [],
                }
            ),
            encoding="utf-8",
        )

        payload = tool.render_known_limitations_burndown(ws)
        accounting = payload["semantic_live_depth_accounting"]
        self.assertEqual(accounting["status"], "proof_requirements_generated_missing_live_topology")
        self.assertEqual(accounting["concrete_item_count"], 400)
        self.assertEqual(accounting["blocked_depth_count"], 400)
        self.assertEqual(accounting["proof_requirement_count"], 400)
        self.assertEqual(accounting["queue_run"]["status"], "requirements_generated_missing_live_topology")
        self.assertEqual(accounting["requirements_run"]["status"], "generated")
        self.assertTrue((aud / "semantic_graph.scoped.json").is_file())
        self.assertTrue((aud / "live_topology_proof_requirements.json").is_file())

    def test_known_limitations_burndown_wires_fixture_smoke_precision_accounting_without_promotion(self):
        ws = self.make_ws()
        audit_dir = ws / ".auditooor"
        audit_dir.mkdir(exist_ok=True)
        (audit_dir / "semantic_fixture_smoke_tasks.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.semantic_fixture_smoke_tasks.v1",
                    "detector_precision_accounting": {
                        "accounting_mode": "fixture_smoke_precision_accounting_only",
                        "precision_claim": "not_computed_fixture_smoke_only",
                        "processed_count": 50,
                        "smoke_required_count": 50,
                        "terminal_clean_positive_count": 7,
                        "blocked_missing_fixture_or_smoke_count": 43,
                        "not_applicable_count": 0,
                        "ingested_record_count": 2,
                        "promotion_allowed": False,
                        "severity": "none",
                    },
                }
            ),
            encoding="utf-8",
        )

        payload = tool.render_known_limitations_burndown(ws)
        accounting = payload["semantic_fixture_smoke_accounting"]
        self.assertEqual(accounting["terminal_clean_positive_count"], 7)
        self.assertEqual(accounting["blocked_missing_fixture_or_smoke_count"], 43)
        self.assertFalse(accounting["promotion_allowed"])
        self.assertEqual(accounting["severity"], "none")

        detector_rows = [
            row for row in payload["rows"]
            if row.get("blocker_category") == "open_detector_precision_or_semantics"
        ]
        self.assertTrue(detector_rows)
        for row in detector_rows:
            self.assertEqual(row["semantic_fixture_smoke_accounting"]["terminal_clean_positive_count"], 7)
            self.assertEqual(row["semantic_fixture_smoke_accounting"]["blocked_missing_fixture_or_smoke_count"], 43)
            self.assertEqual(row["semantic_fixture_smoke_artifact_path"], str(audit_dir / "semantic_fixture_smoke_tasks.json"))
            self.assertEqual(row["reduction_status"], "semantic_fixture_smoke_accounted_not_precision_proof")
            self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
            self.assertFalse(row["promotion_allowed"])
            self.assertFalse(row.get("stop_condition_met", False))

    def test_known_limitations_burndown_prefers_detector_smoke_executor_accounting(self):
        ws = self.make_ws()
        audit_dir = ws / ".auditooor"
        audit_dir.mkdir(exist_ok=True)
        (audit_dir / "semantic_fixture_smoke_tasks.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.semantic_fixture_smoke_tasks.v1",
                    "detector_precision_accounting": {
                        "terminal_clean_positive_count": 0,
                        "blocked_missing_fixture_or_smoke_count": 50,
                        "promotion_allowed": False,
                        "severity": "none",
                    },
                }
            ),
            encoding="utf-8",
        )
        (audit_dir / "semantic_detector_smoke_executor.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.semantic_detector_smoke_executor.v1",
                    "counts": {"passed_vulnerable_clean_smoke": 48, "not_executed": 2},
                    "promotion_allowed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                    "rows": [
                        *[
                            {
                                "argument": f"detector-{idx}",
                                "status": "passed_vulnerable_clean_smoke",
                            }
                            for idx in range(48)
                        ],
                        {
                            "argument": "blocked-a",
                            "status": "not_executed",
                            "reason": "terminal_extraction_failed_detector_argument_unresolved",
                        },
                        {
                            "argument": "blocked-b",
                            "status": "not_executed",
                            "reason": "terminal_extraction_failed_detector_argument_unresolved",
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )

        payload = tool.render_known_limitations_burndown(ws)
        accounting = payload["semantic_fixture_smoke_accounting"]
        self.assertEqual(accounting["accounting_mode"], "detector_fixture_smoke_execution_accounting_only")
        self.assertEqual(accounting["terminal_clean_positive_count"], 48)
        self.assertEqual(accounting["blocked_missing_fixture_or_smoke_count"], 2)
        self.assertEqual(accounting["submission_posture"], "NOT_SUBMIT_READY")

        detector_rows = [
            row for row in payload["rows"]
            if row.get("blocker_category") == "open_detector_precision_or_semantics"
        ]
        self.assertTrue(detector_rows)
        for row in detector_rows:
            self.assertEqual(row["semantic_fixture_smoke_accounting"]["terminal_clean_positive_count"], 48)
            self.assertEqual(row["semantic_fixture_smoke_accounting"]["blocked_missing_fixture_or_smoke_count"], 2)
            self.assertEqual(row["semantic_fixture_smoke_artifact_path"], str(audit_dir / "semantic_detector_smoke_executor.json"))
            self.assertFalse(row.get("stop_condition_met", False))
            self.assertFalse(row["promotion_allowed"])

    def test_known_limitations_burndown_closes_detector_rows_for_fixture_smoke_scope(self):
        ws = self.make_ws()
        audit_dir = ws / ".auditooor"
        audit_dir.mkdir(exist_ok=True)
        smoke_rows = [
            {"argument": f"detector-{idx}", "status": "passed_vulnerable_clean_smoke"}
            for idx in range(50)
        ]
        (audit_dir / "semantic_detector_smoke_executor.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.semantic_detector_smoke_executor.v1",
                    "counts": {"passed_vulnerable_clean_smoke": 50, "not_executed": 0},
                    "promotion_allowed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                    "rows": smoke_rows,
                }
            ),
            encoding="utf-8",
        )
        repair_rows = [
            {
                "source_id": f"SSI-FIX-{idx:03d}",
                "status": "local_semantic_repair_smoke_passed",
                "coverage_claim": "detector_fixture_smoke_only",
            }
            for idx in range(47)
        ]
        (audit_dir / "scanner_autonomy_semantic_repair_worker_after_predicate_fixtures.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.scanner_autonomy_semantic_repair.v1",
                    "baseline_counts": {
                        "terminal_generated_fixture_compile_failure": 16,
                        "terminal_vulnerable_fixture_no_detector_hit": 22,
                        "terminal_clean_fixture_false_positive": 8,
                        "terminal_fixture_pair_materialized_canonical_smoke_blocked": 1,
                    },
                    "blockers_left": 0,
                    "closed_rows": 47,
                    "promotion_allowed": False,
                    "rows": repair_rows,
                    "status_counts": {"local_semantic_repair_smoke_passed": 47},
                    "submission_posture": "NOT_SUBMIT_READY",
                }
            ),
            encoding="utf-8",
        )
        (audit_dir / "pr560_worker_detector_semantic_predicate_repair.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.pr560.detector_semantic_predicate_repair.v1",
                    "exact_reduction": {
                        "local_semantic_repair_smoke_passed_after": 47,
                        "scanner_semantic_blockers_left": 0,
                        "closed_by_detector_skeleton": {"name_match_missing_call": 37},
                    },
                    "promotion_allowed": False,
                    "proof_boundary": "Detector/fixture smoke only.",
                    "submission_posture": "NOT_SUBMIT_READY",
                }
            ),
            encoding="utf-8",
        )
        materialized_rows = [
            {
                "source_id": f"SSI-FIX-{idx:03d}",
                "status": "canonical_smoke_passed",
                "coverage_claim": "detector_fixture_smoke_only",
                "canonical_vulnerable_fixture": f"detectors/test_fixtures/fixture_{idx}_vulnerable.sol",
                "canonical_clean_fixture": f"detectors/test_fixtures/fixture_{idx}_clean.sol",
                "fixture_manifest_path": f"detectors/test_fixtures/fixture_{idx}_manifest.json",
                "positive_hits": 1,
                "clean_hits": 0,
                "promotion_allowed": False,
                "submission_posture": "NOT_SUBMIT_READY",
            }
            for idx in range(47)
        ]
        (audit_dir / "scanner_autonomy_canonical_fixture_materialization.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.scanner_autonomy_canonical_fixture_materialization.v1",
                    "coverage_claim": "detector_fixture_smoke_only",
                    "canonical_smoke_passed_count": 47,
                    "canonical_smoke_failed_count": 0,
                    "blocked_count": 0,
                    "promotion_allowed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                    "status_counts": {"canonical_smoke_passed": 47},
                    "rows": materialized_rows,
                }
            ),
            encoding="utf-8",
        )

        payload = tool.render_known_limitations_burndown(ws)
        self.assertEqual(payload["semantic_fixture_smoke_accounting"]["terminal_clean_positive_count"], 50)
        self.assertEqual(payload["detector_semantic_repair_accounting"]["local_semantic_repair_smoke_passed"], 47)
        self.assertEqual(
            payload["canonical_fixture_materialization_accounting"]["canonical_smoke_passed_count"],
            47,
        )
        self.assertTrue(payload["canonical_fixture_materialization_accounting"]["stop_condition_met"])
        detector_rows = [
            row for row in payload["rows"]
            if str(row.get("limitation_id") or "").lower() in {"p1-1", "p1-4"}
        ]
        self.assertEqual(len(detector_rows), 2)
        for row in detector_rows:
            self.assertTrue(row["stop_condition_met"])
            self.assertEqual(row["blocker_category"], "stop_condition_met")
            self.assertEqual(row["command_level_blockers"], [])
            self.assertEqual(row["reduction_status"], "detector_canonical_fixture_smoke_stop_condition_met")
            self.assertEqual(row["terminal_state"], "already_satisfied_with_fixture_smoke_citation")
            self.assertEqual(
                row["canonical_fixture_materialization_accounting"]["canonical_smoke_passed_count"],
                47,
            )
            self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
            self.assertFalse(row["promotion_allowed"])
            self.assertIn("Canonical materialization is also complete", row["remaining_after_560"])
            self.assertIn("fixture-smoke", row["remaining_after_560"])

    def test_known_limitations_burndown_closes_worklist_and_live_explicit_blockers_only(self):
        ws = self.make_ws()
        audit_dir = ws / ".auditooor"
        audit_dir.mkdir(exist_ok=True)
        route_counts = {f"family-{idx}": 64 for idx in range(12)}
        requirement_counts = {
            "bounded_project_input_fixture": 32,
            "candidate_bound_project_source_citation": 128,
            "paired_live_or_fork_proof": 32,
            "production_path_dossier": 64,
            "project_specific_harness_execution": 352,
            "proved_exploit_impact_execution_manifest": 160,
        }
        (audit_dir / "impact_binding_next_input_validator.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.pr560.impact_binding_next_input_validator.v1",
                    "contract_count": 384,
                    "actionable_unit_count": 768,
                    "ready_unit_count": 0,
                    "closure_candidate_count": 0,
                    "promotion_allowed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                    "summary": {
                        "requirement_counts": requirement_counts,
                        "route_family_counts": route_counts,
                    },
                }
            ),
            encoding="utf-8",
        )
        (audit_dir / "impact_binding_source_harness_discovery.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.pr560.impact_binding_source_harness_discovery.v1",
                    "terminal_reduced_unit_count": 480,
                    "project_source_root_count": 0,
                    "promotion_allowed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                    "summary": {
                        "requirement_counts": {
                            "candidate_bound_project_source_citation": 128,
                            "project_specific_harness_execution": 352,
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        live_summary = {
            "proof_pairs_total": 350,
            "rows_total": 700,
            "proof_pairs_closed": 0,
            "proof_pairs_promoted": 0,
        }
        (audit_dir / "live_topology_proof_input_validator.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.live_topology_proof_input_validator.v1",
                    "promotion_allowed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                    "summary": {
                        **live_summary,
                        "import_ready_pairs": 0,
                        "pair_validation_state_counts": {"manual_proof_files_missing": 350},
                    },
                }
            ),
            encoding="utf-8",
        )
        (audit_dir / "live_topology_manual_proof_materializer.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.live_topology_manual_proof_materializer.v1",
                    "promotion_allowed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                    "summary": {
                        **live_summary,
                        "canonical_import_ready_pairs": 0,
                        "canonical_rows_materialized": 0,
                        "pair_materialization_state_counts": {"no_canonical_manual_proofs_ready": 350},
                    },
                }
            ),
            encoding="utf-8",
        )
        old_root = tool.ROOT
        with tempfile.TemporaryDirectory(prefix="automation_closure_worklist_live_") as td:
            repo = Path(td)
            (repo / "docs").mkdir()
            (repo / "docs" / "KNOWN_LIMITATIONS.md").write_text("# Known\n", encoding="utf-8")
            (repo / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.known_limitations_burndown_map.v1",
                        "rows": [
                            {
                                "limitation_id": "priority-2",
                                "priority_group": "current_priority",
                                "title": "Mechanical impact-family worklists",
                                "terminal_state": "deferred_with_owner",
                                "next_command": "make impact-worklist WS=<workspace> STRICT=1",
                                "evidence": [".auditooor/impact_binding_next_input_validator.json"],
                                "stop_condition": "Worklist and coverage inventory show mapped impact families, uncovered families, named blockers, and next commands.",
                                "stop_condition_met": False,
                            },
                            {
                                "limitation_id": "P1-3",
                                "priority_group": "P1",
                                "title": "Live-topology synthesis",
                                "terminal_state": "deferred_with_owner",
                                "next_command": "make live-topology-proof-input-validator WS=<workspace>",
                                "evidence": [".auditooor/live_topology_manual_proof_materializer.json"],
                                "stop_condition": "Cross-contract claims have same-block paired proof or explicit blockers.",
                                "stop_condition_met": False,
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            tool.ROOT = repo
            try:
                payload = tool.render_known_limitations_burndown(ws)
            finally:
                tool.ROOT = old_root

        self.assertTrue(payload["impact_family_worklist_accounting"]["complete_worklist_stop_condition_met"])
        self.assertTrue(payload["live_topology_explicit_blocker_accounting"]["explicit_blocker_stop_condition_met"])
        rows = {row["limitation_id"]: row for row in payload["rows"]}
        self.assertEqual(rows["priority-2"]["blocker_category"], "stop_condition_met")
        self.assertEqual(rows["priority-2"]["reduction_status"], "mechanical_impact_family_worklist_stop_condition_met")
        self.assertEqual(rows["priority-2"]["command_level_blockers"], [])
        self.assertEqual(rows["P1-3"]["blocker_category"], "stop_condition_met")
        self.assertEqual(rows["P1-3"]["reduction_status"], "live_topology_explicit_blocker_stop_condition_met")
        self.assertEqual(rows["P1-3"]["command_level_blockers"], [])
        self.assertEqual(rows["P1-3"]["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(rows["P1-3"]["promotion_allowed"])

    def test_known_limitations_burndown_records_project_source_import_workflow_without_promotion(self):
        ws = self.make_ws()
        audit_dir = ws / ".auditooor"
        audit_dir.mkdir(exist_ok=True)
        route_counts = {f"family-{idx}": 64 for idx in range(12)}
        requirement_counts = {
            "bounded_project_input_fixture": 32,
            "candidate_bound_project_source_citation": 128,
            "paired_live_or_fork_proof": 32,
            "production_path_dossier": 64,
            "project_specific_harness_execution": 352,
            "proved_exploit_impact_execution_manifest": 160,
        }
        (audit_dir / "project_source_root_readiness.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.project_source_root_readiness.v1",
                    "declared_root_count": 0,
                    "ready_root_count": 0,
                    "rejected_root_count": 0,
                    "promotion_allowed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                    "roots": [],
                }
            ),
            encoding="utf-8",
        )
        (audit_dir / "impact_binding_next_input_validator.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.pr560.impact_binding_next_input_validator.v1",
                    "contract_count": 384,
                    "actionable_unit_count": 768,
                    "ready_unit_count": 0,
                    "closure_candidate_count": 0,
                    "promotion_allowed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                    "summary": {
                        "requirement_counts": requirement_counts,
                        "route_family_counts": route_counts,
                    },
                }
            ),
            encoding="utf-8",
        )
        (audit_dir / "impact_binding_source_harness_discovery.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.pr560.impact_binding_source_harness_discovery.v1",
                    "project_source_readiness_path": str(audit_dir / "project_source_root_readiness.json"),
                    "terminal_reduced_unit_count": 480,
                    "project_source_root_count": 0,
                    "promotion_allowed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                    "summary": {
                        "requirement_counts": {
                            "candidate_bound_project_source_citation": 128,
                            "project_specific_harness_execution": 352,
                        },
                        "discovery_status_counts": {
                            "terminal_no_project_source_roots": 128,
                            "terminal_harness_blocked_no_project_source_roots": 352,
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        old_root = tool.ROOT
        with tempfile.TemporaryDirectory(prefix="automation_closure_project_source_") as td:
            repo = Path(td)
            (repo / "docs").mkdir()
            (repo / "docs" / "KNOWN_LIMITATIONS.md").write_text("# Known\n", encoding="utf-8")
            (repo / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.known_limitations_burndown_map.v1",
                        "rows": [
                            {
                                "limitation_id": "priority-1",
                                "priority_group": "current_priority",
                                "title": "Impact-contract gating before work starts",
                                "terminal_state": "deferred_with_owner",
                                "next_command": "make impact-contract-check WS=<workspace> STRICT=1",
                                "evidence": [".auditooor/impact_binding_source_harness_discovery.json"],
                                "stop_condition": "Impact gates prove candidate-generation paths cannot skip exact impact contracts.",
                                "stop_condition_met": False,
                            },
                            {
                                "limitation_id": "priority-2",
                                "priority_group": "current_priority",
                                "title": "Mechanical impact-family worklists",
                                "terminal_state": "deferred_with_owner",
                                "next_command": "make impact-worklist WS=<workspace> STRICT=1",
                                "evidence": [".auditooor/impact_binding_next_input_validator.json"],
                                "stop_condition": "Worklist and coverage inventory show mapped impact families, uncovered families, named blockers, and next commands.",
                                "stop_condition_met": False,
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            tool.ROOT = repo
            try:
                payload = tool.render_known_limitations_burndown(ws)
            finally:
                tool.ROOT = old_root

        accounting = payload["impact_family_worklist_accounting"]
        self.assertTrue(accounting["complete_worklist_stop_condition_met"])
        self.assertTrue(accounting["source_import_workflow_ready"])
        self.assertTrue(accounting["source_import_terminal_no_roots"])
        self.assertEqual(accounting["source_root_declared_count"], 0)
        self.assertEqual(accounting["source_root_ready_count"], 0)
        self.assertEqual(
            accounting["source_import_discovery_status_counts"]["terminal_no_project_source_roots"],
            128,
        )
        self.assertEqual(
            accounting["source_import_discovery_status_counts"]["terminal_harness_blocked_no_project_source_roots"],
            352,
        )
        rows = {row["limitation_id"]: row for row in payload["rows"]}
        self.assertTrue(rows["priority-2"]["stop_condition_met"])
        self.assertEqual(rows["priority-2"]["blocker_category"], "stop_condition_met")
        self.assertIn("Project-source declaration/import support", rows["priority-2"]["remaining_after_560"])
        self.assertFalse(rows["priority-1"]["stop_condition_met"])
        self.assertEqual(rows["priority-1"]["blocker_category"], "open_impact_contract_or_family_execution")
        self.assertGreater(len(rows["priority-1"]["command_level_blockers"]), 0)

    def test_known_limitations_burndown_reduces_runtime_dlt_without_closure(self):
        ws = self.make_ws()
        audit_dir = ws / ".auditooor"
        audit_dir.mkdir(exist_ok=True)
        (audit_dir / "runtime_dlt_execution_evidence_validator.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.pr560.runtime_dlt_execution_evidence_validator.v1",
                    "dlt_row_count": 96,
                    "proved_exploit_impact_count": 0,
                    "closure_candidate_count": 0,
                    "promotion_allowed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                    "hermetic_fixture_check": {"status": "passed"},
                    "summary": {
                        "blocker_counts": {
                            "execution_manifest_not_proved": 96,
                            "runtime_harness_not_project_bound": 96,
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        old_root = tool.ROOT
        with tempfile.TemporaryDirectory(prefix="automation_closure_runtime_dlt_") as td:
            repo = Path(td)
            (repo / "docs").mkdir()
            (repo / "docs" / "KNOWN_LIMITATIONS.md").write_text("# Known\n", encoding="utf-8")
            (repo / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.known_limitations_burndown_map.v1",
                        "rows": [
                            {
                                "limitation_id": "P1-2",
                                "priority_group": "P1",
                                "title": "Rust cross-crate semantic analysis",
                                "terminal_state": "deferred_with_owner",
                                "next_command": "make runtime-dlt-execution-evidence WS=<workspace>",
                                "evidence": [".auditooor/runtime_dlt_execution_evidence_validator.json"],
                                "stop_condition": "Rust dossiers include concrete cross-crate invocation resolution with heuristic limits documented.",
                                "stop_condition_met": False,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            tool.ROOT = repo
            try:
                payload = tool.render_known_limitations_burndown(ws)
            finally:
                tool.ROOT = old_root

        row = payload["rows"][0]
        self.assertFalse(row["stop_condition_met"])
        self.assertEqual(row["blocker_category"], "open_semantic_or_live_topology_depth")
        self.assertEqual(row["reduction_status"], "runtime_dlt_execution_evidence_reduced_not_closed")
        self.assertEqual(row["runtime_dlt_execution_evidence_accounting"]["dlt_row_count"], 96)
        self.assertIn("proved exploit-impact", row["remaining_after_560"])

    def test_known_limitations_burndown_blocks_outcome_calibration_without_resolved_linkage(self):
        ws = self.make_ws()
        audit_dir = ws / ".auditooor"
        audit_dir.mkdir(exist_ok=True)
        (audit_dir / "outcome_calibration_scorecard.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.outcome_calibration_scorecard.v1",
                    "advisory_only": True,
                    "scorecard": {
                        "outcome_rows": {
                            "resolved": 2,
                            "linked_for_calibration": 0,
                            "missing_linkage": 2,
                        },
                        "routing_rows": [
                            {"provider": "kimi", "task_type": "source-extraction", "route_status": "needs_samples"}
                        ],
                    },
                    "queue": [
                        {"item_id": "OCQ-OUT-001", "queue_type": "outcome_linkage_backfill"},
                        {"item_id": "OCQ-PROV-001", "queue_type": "provider_local_terminal_adjudication"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        old_root = tool.ROOT
        with tempfile.TemporaryDirectory(prefix="automation_closure_outcome_calibration_") as td:
            repo = Path(td)
            (repo / "docs").mkdir()
            (repo / "docs" / "KNOWN_LIMITATIONS.md").write_text("# Known\n", encoding="utf-8")
            (repo / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.known_limitations_burndown_map.v1",
                        "rows": [
                            {
                                "limitation_id": "P0-3",
                                "priority_group": "P0",
                                "title": "Model output precision by task class",
                                "terminal_state": "deferred_with_owner",
                                "next_command": "make outcome-calibration-scorecard",
                                "evidence": ["tools/outcome-calibration-scorecard.py"],
                                "stop_condition": "Every lane has outcome-backed precision.",
                                "stop_condition_met": True,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            tool.ROOT = repo
            try:
                payload = tool.render_known_limitations_burndown(ws)
            finally:
                tool.ROOT = old_root

        accounting = payload["outcome_calibration_accounting"]
        self.assertEqual(accounting["status"], "blocked_missing_resolved_linkage")
        self.assertFalse(accounting["resolved_linkage_exists"])
        row = payload["rows"][0]
        self.assertEqual(row["blocker_category"], "open_outcome_calibration")
        self.assertEqual(row["reduction_status"], "outcome_calibration_blocked_missing_resolved_linkage")
        self.assertFalse(row["stop_condition_met"])
        self.assertEqual(row["outcome_calibration_missing_linkage"], 2)
        self.assertEqual(row["outcome_calibration_outcome_linkage_backfill_items"], 1)
        self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(row["promotion_allowed"])

    def test_known_limitations_burndown_reduces_outcome_calibration_with_resolved_linkage(self):
        ws = self.make_ws()
        audit_dir = ws / ".auditooor"
        audit_dir.mkdir(exist_ok=True)
        (audit_dir / "outcome_calibration_scorecard.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.outcome_calibration_scorecard.v1",
                    "advisory_only": True,
                    "scorecard": {
                        "outcome_rows": {
                            "resolved": 2,
                            "linked_for_calibration": 2,
                            "missing_linkage": 0,
                        },
                        "routing_rows": [
                            {"provider": "kimi", "task_type": "source-extraction", "route_status": "primary_ready"},
                            {"provider": "minimax", "task_type": "adversarial-kill", "route_status": "primary_ready"},
                        ],
                    },
                    "queue": [],
                }
            ),
            encoding="utf-8",
        )
        old_root = tool.ROOT
        with tempfile.TemporaryDirectory(prefix="automation_closure_outcome_calibration_linked_") as td:
            repo = Path(td)
            (repo / "docs").mkdir()
            (repo / "docs" / "KNOWN_LIMITATIONS.md").write_text("# Known\n", encoding="utf-8")
            (repo / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.known_limitations_burndown_map.v1",
                        "rows": [
                            {
                                "limitation_id": "P0-3",
                                "priority_group": "P0",
                                "title": "Model output precision by task class",
                                "terminal_state": "deferred_with_owner",
                                "next_command": "make outcome-calibration-scorecard",
                                "evidence": ["tools/outcome-calibration-scorecard.py"],
                                "stop_condition": "Every lane has outcome-backed precision.",
                                "stop_condition_met": True,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            tool.ROOT = repo
            try:
                payload = tool.render_known_limitations_burndown(ws)
            finally:
                tool.ROOT = old_root

        accounting = payload["outcome_calibration_accounting"]
        self.assertEqual(accounting["status"], "resolved_linkage_present")
        self.assertTrue(accounting["resolved_linkage_exists"])
        row = payload["rows"][0]
        self.assertEqual(row["reduction_status"], "outcome_calibration_resolved_linkage_accounted")
        self.assertTrue(row["stop_condition_met"])
        self.assertEqual(row["outcome_calibration_linked_for_calibration"], 2)
        self.assertEqual(row["outcome_calibration_missing_linkage"], 0)
        self.assertEqual(row["outcome_calibration_artifact_path"], str(audit_dir / "outcome_calibration_scorecard.json"))
        self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(row["promotion_allowed"])

    def test_known_limitations_burndown_reduces_outcome_calibration_with_strict_import_workflow(self):
        ws = self.make_ws()
        audit_dir = ws / ".audit_logs" / "outcome_calibration"
        audit_dir.mkdir(parents=True, exist_ok=True)
        (audit_dir / "outcome_calibration_scorecard.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.outcome_calibration_scorecard.v1",
                    "advisory_only": True,
                    "scorecard": {
                        "outcome_rows": {
                            "resolved": 6,
                            "linked_for_calibration": 0,
                            "missing_linkage": 0,
                            "terminalized_missing_linkage": 6,
                            "resolved_linkage_validator_status": "terminalized_missing_linkage_not_calibration",
                        },
                        "routing_rows": [
                            {"provider": "kimi", "task_type": "source-extraction", "route_status": "needs_samples"}
                        ],
                    },
                    "queue": [
                        {"item_id": "OCQ-OUT-001", "queue_type": "outcome_linkage_terminalized_missing_linkage"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        (audit_dir / "outcome_calibration_resolved_linkage_validation.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.outcome_calibration_resolved_linkage_validator.v1",
                    "summary": {
                        "valid_linked_rows": 0,
                        "invalid_linkage_rows": 0,
                        "terminalized_missing_linkage_rows": 6,
                        "missing_linkage_rows": 0,
                        "calibration_closure_status": "terminalized_missing_linkage_not_calibration",
                    },
                }
            ),
            encoding="utf-8",
        )
        old_root = tool.ROOT
        with tempfile.TemporaryDirectory(prefix="automation_closure_outcome_import_") as td:
            repo = Path(td)
            (repo / "docs").mkdir()
            (repo / "docs" / "KNOWN_LIMITATIONS.md").write_text("# Known\n", encoding="utf-8")
            (repo / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.known_limitations_burndown_map.v1",
                        "rows": [
                            {
                                "limitation_id": "P0-4",
                                "priority_group": "P0",
                                "title": "Outcome telemetry linkage",
                                "terminal_state": "deferred_with_owner",
                                "next_command": "make outcome-calibration-scorecard",
                                "evidence": ["tools/outcome-calibration-scorecard.py"],
                                "stop_condition": "Every resolved row has strict linkage.",
                                "stop_condition_met": True,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            tool.ROOT = repo
            try:
                payload = tool.render_known_limitations_burndown(ws)
            finally:
                tool.ROOT = old_root

        row = payload["rows"][0]
        self.assertFalse(row["stop_condition_met"])
        self.assertEqual(row["reduction_status"], "outcome_calibration_strict_import_ready_no_linked_rows")
        self.assertEqual(row["outcome_calibration_resolved_linkage_validation_status"], "terminalized_missing_linkage_not_calibration")
        self.assertEqual(row["outcome_calibration_resolved_linkage_validation_terminalized_rows"], 6)
        self.assertIn("Strict resolved-linkage import validation is wired", row["remaining_after_560"])

    def test_known_limitations_burndown_reduces_outcome_calibration_with_route_import_workflow(self):
        ws = self.make_ws()
        audit_dir = ws / ".audit_logs" / "outcome_calibration"
        audit_dir.mkdir(parents=True, exist_ok=True)
        (audit_dir / "outcome_calibration_scorecard.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.outcome_calibration_scorecard.v1",
                    "advisory_only": True,
                    "scorecard": {
                        "outcome_rows": {
                            "resolved": 6,
                            "linked_for_calibration": 0,
                            "missing_linkage": 6,
                            "terminalized_missing_linkage": 0,
                            "resolved_linkage_validator_status": "open_missing_linkage",
                        },
                        "routing_rows": [
                            {"provider": "kimi", "task_type": "source-extraction", "route_status": "needs_samples"}
                        ],
                    },
                    "queue": [
                        {"item_id": "OCQ-OUT-001", "queue_type": "outcome_linkage_backfill"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        (audit_dir / "outcome_calibration_route_evidence_import.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.outcome_calibration_route_evidence_importer.v1",
                    "summary": {
                        "route_evidence_rows_seen": 2,
                        "valid_import_rows": 0,
                        "invalid_import_rows": 2,
                        "import_status": "no_valid_route_evidence_rows",
                    },
                }
            ),
            encoding="utf-8",
        )
        old_root = tool.ROOT
        with tempfile.TemporaryDirectory(prefix="automation_closure_route_import_") as td:
            repo = Path(td)
            (repo / "docs").mkdir()
            (repo / "docs" / "KNOWN_LIMITATIONS.md").write_text("# Known\n", encoding="utf-8")
            (repo / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.known_limitations_burndown_map.v1",
                        "rows": [
                            {
                                "limitation_id": "P0-3",
                                "priority_group": "P0",
                                "title": "Outcome calibration route precision",
                                "terminal_state": "deferred_with_owner",
                                "next_command": "make outcome-calibration-route-evidence-importer",
                                "evidence": ["tools/outcome-calibration-route-evidence-importer.py"],
                                "stop_condition": "Route evidence has terminal linked outcomes.",
                                "stop_condition_met": True,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            tool.ROOT = repo
            try:
                payload = tool.render_known_limitations_burndown(ws)
            finally:
                tool.ROOT = old_root

        row = payload["rows"][0]
        self.assertFalse(row["stop_condition_met"])
        self.assertEqual(row["reduction_status"], "outcome_calibration_route_evidence_import_workflow_reduced_no_linked_rows")
        self.assertTrue(row["outcome_calibration_route_evidence_import_exists"])
        self.assertEqual(row["outcome_calibration_route_evidence_rows_seen"], 2)
        self.assertEqual(row["outcome_calibration_route_evidence_import_valid_rows"], 0)

    def test_known_limitations_burndown_closes_agent_recall_from_full_corpus_evidence(self):
        ws = self.make_ws()
        audit_dir = ws / ".auditooor"
        audit_dir.mkdir(exist_ok=True)
        (audit_dir / "agent_recall_full_corpus_proof.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.pr560.agent_recall_full_corpus_proof.v1",
                    "full_recall_closure_status": "closed_for_current_local_evidence",
                    "total_candidate_rows": 3,
                    "terminalized_or_bounded_rows": 3,
                    "open_actionable_rows": 0,
                    "terminal_state_counts": {
                        "detectorized_terminal": 1,
                        "non_detectorizable_terminal": 1,
                        "local_proof_recorded_terminal": 1,
                    },
                    "task_type_counts": {
                        "detector_task": 0,
                        "source_proof_task": 0,
                        "local_proof_task": 0,
                        "terminal_blocker": 3,
                    },
                    "promotion_allowed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                }
            ),
            encoding="utf-8",
        )
        (audit_dir / "agent_recall_detector_queue_full_corpus.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.agent_recall_detector_queue.v1",
                    "rows": [
                        {
                            "queue_id": "ARDQ-001",
                            "terminal_state": "detectorized_terminal",
                            "reason": "vulnerable/clean detector smoke proof exists",
                        },
                        {
                            "queue_id": "ARDQ-002",
                            "terminal_state": "non_detectorizable_terminal",
                            "reason": "source review route is terminal for this internal-tool row",
                        },
                        {
                            "queue_id": "ARDQ-003",
                            "terminal_state": "local_proof_recorded_terminal",
                            "reason": "bounded local proof recorded no-counterexample",
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        (audit_dir / "agent_recall_source_local_proof_closure.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.pr560.agent_recall_source_local_proof_closure.v1",
                    "rows": [
                        {
                            "queue_id": "ARDQ-003",
                            "terminal_state": "local_proof_recorded_terminal",
                            "reason": "bounded local proof recorded no-counterexample",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        old_root = tool.ROOT
        with tempfile.TemporaryDirectory(prefix="automation_closure_agent_recall_") as td:
            repo = Path(td)
            (repo / "docs").mkdir()
            (repo / "docs" / "KNOWN_LIMITATIONS.md").write_text("# Known\n", encoding="utf-8")
            (repo / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.known_limitations_burndown_map.v1",
                        "rows": [
                            {
                                "limitation_id": "priority-3",
                                "priority_group": "current_priority",
                                "title": "Agent-found behavior recall and scanner improvement",
                                "terminal_state": "deferred_with_owner",
                                "next_command": "make agent-recall WS=<workspace> STRICT=1",
                                "evidence": [".auditooor/agent_recall_full_corpus_proof.json"],
                                "stop_condition": (
                                    "At least three prior agent-found behaviors are replayed through the loop, "
                                    "with one detectorized and one non-detectorizable route recorded."
                                ),
                                "stop_condition_met": False,
                            },
                            {
                                "limitation_id": "cross-cut-agent-found-behavior-recall",
                                "priority_group": "cross_cut",
                                "title": "Agent-found behavior recall",
                                "terminal_state": "deferred_with_owner",
                                "next_command": "make agent-recall WS=<workspace> STRICT=1",
                                "evidence": [".auditooor/agent_recall_full_corpus_proof.json"],
                                "stop_condition": (
                                    "Every agent-found behavior has a terminal route and scanner-miss reason."
                                ),
                                "stop_condition_met": False,
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            tool.ROOT = repo
            try:
                payload = tool.render_known_limitations_burndown(ws)
            finally:
                tool.ROOT = old_root

        accounting = payload["agent_recall_closure_accounting"]
        self.assertEqual(accounting["status"], "full_recall_closed_for_current_local_evidence")
        self.assertTrue(accounting["priority_stop_condition_met"])
        self.assertTrue(accounting["cross_cut_stop_condition_met"])
        rows = {row["limitation_id"]: row for row in payload["rows"]}
        for limitation_id in ("priority-3", "cross-cut-agent-found-behavior-recall"):
            row = rows[limitation_id]
            self.assertTrue(row["stop_condition_met"])
            self.assertEqual(row["terminal_state"], "already_satisfied_with_citation")
            self.assertEqual(row["blocker_category"], "stop_condition_met")
            self.assertEqual(row["command_level_blockers"], [])
            self.assertEqual(row["agent_recall_open_actionable_rows"], 0)

    def test_execution_proof_task_queue_does_not_count_proved_without_commands(self):
        ws = self.make_ws()
        path = ws / "poc_execution" / "empty-run" / "execution_manifest.json"
        path.parent.mkdir(parents=True)
        path.write_text(
            json.dumps(
                {
                    "candidate_id": "empty-run",
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "commands_attempted": [],
                    "evidence_class": "executed_with_manifest",
                }
            ),
            encoding="utf-8",
        )

        payload = tool.render_known_limitations_burndown(ws)
        gate = payload["execution_proof_task_queue"]["summary"]
        self.assertEqual(gate["proof_counted"], 0)
        self.assertEqual(gate["invalid_proved_manifest"], 1)

    def test_execution_proof_task_queue_requires_strict_evidence_class(self):
        ws = self.make_ws()
        manifests = {
            "missing-evidence-class": {
                "candidate_id": "missing-evidence-class",
                "final_result": "proved",
                "impact_assertion": "exploit_impact",
                "commands_attempted": [{"command": "forge test", "status": "pass", "exit_code": 0}],
            },
            "empty-evidence-class": {
                "candidate_id": "empty-evidence-class",
                "final_result": "proved",
                "impact_assertion": "exploit_impact",
                "commands_attempted": [{"command": "forge test", "status": "pass", "exit_code": 0}],
                "evidence_class": "",
            },
            "strict-evidence-class": {
                "candidate_id": "strict-evidence-class",
                "final_result": "proved",
                "impact_assertion": "exploit_impact",
                "commands_attempted": [{"command": "forge test", "status": "pass", "exit_code": "0"}],
                "evidence_class": "executed_with_manifest",
            },
        }
        for candidate_id, manifest in manifests.items():
            path = ws / "poc_execution" / candidate_id / "execution_manifest.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(manifest), encoding="utf-8")

        validation = tool.collect_execution_manifest_gate_validation(ws)
        rows = {row["candidate_id"]: row for row in validation["rows"]}
        self.assertFalse(rows["missing-evidence-class"]["proof_counted"])
        self.assertFalse(rows["empty-evidence-class"]["proof_counted"])
        self.assertTrue(rows["strict-evidence-class"]["proof_counted"])
        self.assertEqual(validation["summary"]["proof_counted"], 1)
        self.assertEqual(validation["summary"]["invalid_proved_manifest"], 2)

    def test_execution_proof_task_queue_rejects_legacy_command_rows(self):
        ws = self.make_ws()
        manifests = {
            "legacy-string-command": {
                "candidate_id": "legacy-string-command",
                "final_result": "proved",
                "impact_assertion": "exploit_impact",
                "commands_attempted": ["forge test"],
                "evidence_class": "executed_with_manifest",
            },
            "missing-command-text": {
                "candidate_id": "missing-command-text",
                "final_result": "proved",
                "impact_assertion": "exploit_impact",
                "commands_attempted": [{"command": "", "status": "pass", "exit_code": 0}],
                "evidence_class": "executed_with_manifest",
            },
            "missing-exit-code": {
                "candidate_id": "missing-exit-code",
                "final_result": "proved",
                "impact_assertion": "exploit_impact",
                "commands_attempted": [{"command": "forge test", "status": "pass"}],
                "evidence_class": "executed_with_manifest",
            },
            "bool-exit-code": {
                "candidate_id": "bool-exit-code",
                "final_result": "proved",
                "impact_assertion": "exploit_impact",
                "commands_attempted": [{"command": "forge test", "status": "pass", "exit_code": True}],
                "evidence_class": "executed_with_manifest",
            },
            "failing-command": {
                "candidate_id": "failing-command",
                "final_result": "proved",
                "impact_assertion": "exploit_impact",
                "commands_attempted": [{"command": "forge test", "status": "fail", "exit_code": 0}],
                "evidence_class": "executed_with_manifest",
            },
            "passing-command": {
                "candidate_id": "passing-command",
                "final_result": "proved",
                "impact_assertion": "exploit_impact",
                "commands_attempted": [{"command": "forge test", "status": "pass", "exit_code": 0}],
                "evidence_class": "executed_with_manifest",
            },
        }
        for candidate_id, manifest in manifests.items():
            path = ws / "poc_execution" / candidate_id / "execution_manifest.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(manifest), encoding="utf-8")

        validation = tool.collect_execution_manifest_gate_validation(ws)
        rows = {row["candidate_id"]: row for row in validation["rows"]}
        self.assertFalse(rows["legacy-string-command"]["proof_counted"])
        self.assertFalse(rows["missing-command-text"]["proof_counted"])
        self.assertFalse(rows["missing-exit-code"]["proof_counted"])
        self.assertFalse(rows["bool-exit-code"]["proof_counted"])
        self.assertFalse(rows["failing-command"]["proof_counted"])
        self.assertTrue(rows["passing-command"]["proof_counted"])
        self.assertEqual(validation["summary"]["proof_counted"], 1)
        self.assertEqual(validation["summary"]["invalid_proved_manifest"], 5)

    def test_known_limitations_burndown_strict_fails_missing_current_row_fields(self):
        ws = self.make_ws()
        old_root = tool.ROOT
        with tempfile.TemporaryDirectory(prefix="automation_closure_burndown_") as td:
            repo = Path(td)
            (repo / "docs").mkdir()
            (repo / "docs" / "KNOWN_LIMITATIONS.md").write_text("# Known\n", encoding="utf-8")
            (repo / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.known_limitations_burndown_map.v1",
                        "rows": [
                            {
                                "limitation_id": "priority-1",
                                "priority_group": "current_priority",
                                "title": "Impact contracts",
                                "terminal_state": "deferred_with_owner",
                                "evidence": ["status prose without artifact path"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            tool.ROOT = repo
            try:
                payload = tool.render_known_limitations_burndown(ws)
            finally:
                tool.ROOT = old_root
        self.assertEqual(payload["status"], "blocked_named")
        row = payload["rows"][0]
        self.assertEqual(row["strict_status"], "blocked_named")
        self.assertEqual(row["blocker_category"], "open_impact_contract_or_family_execution")
        self.assertIn(
            {"check_id": "artifact-citation", "status": "blocker", "detail": "missing explicit artifact path"},
            row["closure_checklist"],
        )
        self.assertIn(
            {"check_id": "command-blockers", "status": "named", "detail": "impact-start-gates, impact-family-base, impact-family-non-base, impact-terminal-proof"},
            row["closure_checklist"],
        )
        self.assertEqual(
            row["strict_missing_fields"],
            ["owner_command", "artifact_path", "stop_condition"],
        )

    def test_known_limitations_burndown_strict_passes_complete_current_row(self):
        ws = self.make_ws()
        old_root = tool.ROOT
        with tempfile.TemporaryDirectory(prefix="automation_closure_burndown_ok_") as td:
            repo = Path(td)
            (repo / "docs").mkdir()
            (repo / "docs" / "KNOWN_LIMITATIONS.md").write_text("# Known\n", encoding="utf-8")
            (repo / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.known_limitations_burndown_map.v1",
                        "rows": [
                            {
                                "limitation_id": "priority-1",
                                "priority_group": "current_priority",
                                "title": "Impact contracts",
                                "terminal_state": "deferred_with_owner",
                                "next_command": "make impact-contract-check WS=<workspace> STRICT=1",
                                "evidence": ["tools/automation-closure.py"],
                                "stop_condition": "no bypass",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            tool.ROOT = repo
            try:
                payload = tool.render_known_limitations_burndown(ws)
            finally:
                tool.ROOT = old_root
        self.assertEqual(payload["status"], "ok")
        row = payload["rows"][0]
        self.assertEqual(row["strict_status"], "ok")
        self.assertEqual(row["blocker_category"], "open_impact_contract_or_family_execution")
        self.assertIn(
            {"check_id": "owner-command", "status": "pass", "detail": "make impact-contract-check WS=<workspace> STRICT=1"},
            row["closure_checklist"],
        )
        self.assertIn(
            {"check_id": "next-command-shape", "status": "pass", "detail": "make impact-contract-check WS=<workspace> STRICT=1"},
            row["closure_checklist"],
        )
        self.assertFalse(row["strict_missing_fields"])

    def test_known_limitations_burndown_reduces_severity_claim_discipline_only(self):
        ws = self.make_ws()
        old_root = tool.ROOT
        with tempfile.TemporaryDirectory(prefix="automation_closure_severity_reduced_") as td:
            repo = Path(td)
            (repo / "docs").mkdir()
            (repo / "tools" / "tests").mkdir(parents=True)
            (repo / "docs" / "KNOWN_LIMITATIONS.md").write_text("# Known\n", encoding="utf-8")
            (repo / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.known_limitations_burndown_map.v1",
                        "rows": [
                            {
                                "limitation_id": "cross-cut-severity-claim-discipline",
                                "priority_group": "cross_cut",
                                "title": "Severity claim discipline",
                                "terminal_state": "deferred_with_owner",
                                "evidence": ["tools/severity-claim-guard.py"],
                                "next_command": "make severity-claim-guard WS=<workspace>",
                                "stop_condition": "Manual drafts and non-Base engagements cannot bypass exact-impact severity derivation.",
                                "stop_condition_met": False,
                            },
                            {
                                "limitation_id": "cross-cut-impact-first-work-gating",
                                "priority_group": "cross_cut",
                                "title": "Impact-first work gating",
                                "terminal_state": "deferred_with_owner",
                                "evidence": ["Makefile target: impact-contract-check"],
                                "next_command": "make impact-contract-check WS=<workspace> STRICT=1",
                                "stop_condition": "No missing-proof candidate keeps selected impact or reportable severity.",
                                "stop_condition_met": False,
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (repo / "tools" / "severity-claim-guard.py").write_text(
                "\n".join(
                    [
                        "def _has_manual_exact_impact_flag(row):",
                        "    return row.get('exact_impact_row') or row.get('selected_impact_exact')",
                        "def load_workspace_payload(workspace):",
                        "    impact_contracts = workspace / '.auditooor' / 'impact_contracts.json'",
                        "    candidate_dir = workspace / 'critical_hunt' / 'candidates'",
                        "    return {'schema': 'auditooor.generic_severity_claim_guard_input.v1', 'listed_impact_proven': True}",
                    ]
                ),
                encoding="utf-8",
            )
            (repo / "tools" / "tests" / "test_severity_claim_guard.py").write_text(
                "\n".join(
                    [
                        "def test_generic_impact_contract_exact_flag_unproven_reportable_fails(): pass",
                        "def test_generic_impact_contract_proven_exact_reportable_passes(): pass",
                        "def test_generic_impact_contract_non_exact_reportable_fails(): pass",
                        "def test_generic_impact_contract_program_matrix_proven_reportable_passes(): pass",
                    ]
                ),
                encoding="utf-8",
            )
            (repo / "docs" / "TOOL_STATUS.md").write_text(
                "make severity-claim-guard falls back to .auditooor/impact_contracts.json "
                "and critical_hunt/candidates. Integrated into pre-submit as Check #32.\n",
                encoding="utf-8",
            )
            (repo / "tools" / "pre-submit-check.sh").write_text(
                "SEVERITY-CLAIM-GUARD tools/severity-claim-guard.py --workspace\n",
                encoding="utf-8",
            )
            tool.ROOT = repo
            try:
                payload = tool.render_known_limitations_burndown(ws)
            finally:
                tool.ROOT = old_root

        rows = {row["limitation_id"]: row for row in payload["rows"]}
        severity_row = rows["cross-cut-severity-claim-discipline"]
        self.assertEqual(severity_row["terminal_state"], "already_satisfied_with_citation")
        self.assertTrue(severity_row["stop_condition_met"])
        self.assertEqual(severity_row["reduction_status"], "reduced_generic_guard_present")
        self.assertEqual(severity_row["severity_claim_guard_generic_fallback"]["status"], "present")
        self.assertEqual(severity_row["terminal_state_before_evidence_detection"], "deferred_with_owner")
        impact_first_row = rows["cross-cut-impact-first-work-gating"]
        self.assertEqual(impact_first_row["terminal_state"], "deferred_with_owner")
        self.assertFalse(impact_first_row["stop_condition_met"])
        self.assertNotIn("severity_claim_guard_generic_fallback", impact_first_row)

    def test_known_limitations_burndown_reduces_impact_first_five_paths_only(self):
        ws = self.make_ws()
        old_root = tool.ROOT
        with tempfile.TemporaryDirectory(prefix="automation_closure_impact_first_reduced_") as td:
            repo = Path(td)
            (repo / "docs").mkdir()
            (repo / "tools").mkdir()
            (repo / "docs" / "KNOWN_LIMITATIONS.md").write_text("# Known\n", encoding="utf-8")
            (repo / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.known_limitations_burndown_map.v1",
                        "rows": [
                            {
                                "limitation_id": "priority-1",
                                "priority_group": "current_priority",
                                "title": "Impact-contract gating before work starts",
                                "terminal_state": "deferred_with_owner",
                                "evidence": ["tools/automation-closure.py"],
                                "next_command": "make impact-contract-check WS=<workspace> STRICT=1",
                                "stop_condition": "No candidate-generation to direct-submit path can skip impact-contract validation.",
                                "stop_condition_met": False,
                            },
                            {
                                "limitation_id": "cross-cut-impact-first-work-gating",
                                "priority_group": "cross_cut",
                                "title": "Impact-first work gating",
                                "terminal_state": "deferred_with_owner",
                                "evidence": ["Makefile target: impact-contract-check"],
                                "next_command": "make impact-contract-check WS=<workspace> STRICT=1",
                                "stop_condition": "No missing-proof candidate keeps selected impact or reportable severity.",
                                "stop_condition_met": False,
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (repo / "tools" / "critical-hunt.py").write_text(
                "def _load_exact_impact_contracts(): pass\nimpact_contracts.json\n"
                "missing_exact_impact_contract\nadvisory_missing_exact_impact_contract\n",
                encoding="utf-8",
            )
            (repo / "tools" / "paste-ready-generator.py").write_text(
                "def _impact_contract_refusal_reasons(): pass\nvalidate_impact_contract_text\n"
                "matching workspace impact_contract proof is missing\nlisted_impact_proven\n",
                encoding="utf-8",
            )
            (repo / "tools" / "submission-packager.py").write_text(
                "def _impact_mapping_packager_refusal(): pass\nbuild_impact_mapping_manifest\n"
                "Program Impact Mapping promotion contract refused packaging\npackager_should_refuse\n"
                "proof_artifact\nrequired_for_high_plus\nready_verdict\n",
                encoding="utf-8",
            )
            (repo / "tools" / "swarm-orchestrator.py").write_text(
                "def mining_brief_impact_contract_gate(): pass\n"
                "dispatch_blocked_missing_impact_contract\nREFUSING dispatch\nblocked_missing_impact_contract\n",
                encoding="utf-8",
            )
            (repo / "tools" / "mining-brief-generator.py").write_text(
                "def ranked_row_requires_impact_contract(row): pass\n"
                "def impact_contract_id_from_row(row): pass\n"
                "impact_contract_required\nblocked_missing_impact_contract\n"
                "VERDICT=blocked_missing_impact_contract\n",
                encoding="utf-8",
            )
            (repo / "tools" / "poc-scaffold.py").write_text(
                "def require_locked_impact_contract(): pass\nblocked_missing_impact_contract\n"
                "listed_impact_proven=true\nexact_impact_row\n",
                encoding="utf-8",
            )
            (repo / "tools" / "auto-draft-generator.py").write_text(
                "def require_locked_impact_contract(): pass\n"
                "auto-draft-generator requires\nbefore writing drafts or PoC scaffolds\n"
                "listed_impact_proven=true\n",
                encoding="utf-8",
            )
            (repo / "tools" / "harness-scaffold-emitter.py").write_text(
                "def require_locked_impact_contract(): pass\nblocked_missing_impact_contract\n"
                "listed_impact_proven=true\nattempt_manifest\n",
                encoding="utf-8",
            )
            (repo / "tools" / "submission-factory.py").write_text(
                "def impact_contract_refusal(): pass\nvalidate_impact_contract_text\n"
                "impact_contract_invalid:listed_impact_not_proven\n"
                "severity_claim_not_backed_by_selected_impact_tier\n"
                "proof_artifact_missing\nproof_artifact_not_found\n"
                "selected_impact_not_exact_listed_sentence\n",
                encoding="utf-8",
            )
            (repo / "tools" / "deep-counterexample-replay-scaffold.py").write_text(
                "def locked_impact_contract(): pass\n"
                "deep replay scaffolds require record.impact_contract_id\n"
                "listed_impact_proven=true\nDo not promote until the Forge replay executes\n",
                encoding="utf-8",
            )
            (repo / "tools" / "promote-typed-candidate.py").write_text(
                "def _impact_contract_report(): pass\n"
                "impact_contract_required\nprogram_impact_mapping_unresolved\nimpact_unresolved\n",
                encoding="utf-8",
            )
            (repo / "tools" / "source-mining-campaign.py").write_text(
                "submission_posture\nNOT_SUBMIT_READY\nimpact_contract_required\n"
                "source_mining_generated_hypothesis\nGENERATED_HYPOTHESIS\n"
                "def build_outcome_routing_manifest(): pass\nprovider_rows\n"
                "input_only_local_verification_required\nllm_corpus_mining_is_proof\n"
                "outcome_calibrated_routing.json\n"
                "dispatch-preflight.py\n--template source-extract\n--template adversarial-kill\n"
                "Never auto-promote a candidate\n"
                "provider=\"kimi\"\ntask_type=\"source-extract\"\n_record_packet_done\n"
                "kimi_candidates.json\nKEEP_FOR_LOCAL_VERIFICATION\n"
                "provider=\"minimax\"\ntask_type=\"adversarial-kill\"\n_record_packet_done\n"
                "minimax_challenges.json\nrejected.json\n",
                encoding="utf-8",
            )
            (repo / "tools" / "dispatch-preflight.py").write_text(
                "MANDATORY_TASK_TYPES\nsource-extract\nadversarial-kill\n"
                "BYPASS_DISPATCH_PREFLIGHT_REASON\nAUDITOOOR_DISPATCH_PREFLIGHT_OK\n",
                encoding="utf-8",
            )
            (repo / "tools" / "llm-dispatch.py").write_text(
                "dispatch-preflight-required\nAUDITOOOR_DISPATCH_PREFLIGHT_OK\n"
                "BYPASS_DISPATCH_PREFLIGHT_REASON\n",
                encoding="utf-8",
            )
            (repo / "tools" / "semantic-graph.py").write_text(
                "def evidence_edges_from_body(): pass\n"
                "def build_multi_hop_paths(): pass\n"
                "impact_family_for_path\nmapped_stages\nsource_reader_coverage\n"
                "route semantic path to exact-impact candidate or mark non-detectorizable\n",
                encoding="utf-8",
            )
            (repo / "tools" / "semantic-detector-worklist.py").write_text(
                "SCHEMA_VERSION = \"auditooor.semantic_detector_worklist.v1\"\n"
                "semantic_relation_detector_rewrite\nsemantic_multihop_detector_rewrite\n"
                "submission_posture\": \"NOT_SUBMIT_READY\"\n"
                "impact_contract_required\": True\npromotion_allowed\": False\n"
                "none_source_shape_only\n",
                encoding="utf-8",
            )
            (repo / "tools" / "chimera-scaffold.py").write_text(
                "def _require_locked_impact_contract(): pass\nblocked_missing_impact_contract\n"
                "listed_impact_proven=true\nsubmit_ready\n",
                encoding="utf-8",
            )
            (repo / "tools" / "chimera-ledger-scaffold.py").write_text(
                "blocked_missing_impact_contract\nimpact_contract_required\nimpact_contract_id\n",
                encoding="utf-8",
            )
            (repo / "tools" / "recon-log-bridge.py").write_text(
                "def _locked_impact_contract(): pass\n"
                "--forge-test-out requires --impact-contract-id\nimpact_contract_blocker\n"
                "blocked_missing_impact_contract\n",
                encoding="utf-8",
            )
            (repo / "tools" / "corpus-detectorization-inventory.py").write_text(
                "ReCon/deep-counterexample\nsource-mining survivors\n"
                "submission_posture=\"NOT_SUBMIT_READY\"\nimpact_contract_required=true\n"
                "source-mining-harness-task\n",
                encoding="utf-8",
            )
            (repo / "docs" / "TOOL_STATUS.md").write_text(
                "make critical-hunt WS=...\ntools/poc-scaffold.py --plan-json\n"
                "locked to a proved exact impact contract\nmake docs-check\n",
                encoding="utf-8",
            )
            (repo / "docs" / "WORKFLOW.md").write_text(
                "selected source-mining briefs that inherited `blocked_missing_impact_contract`\n",
                encoding="utf-8",
            )
            tool.ROOT = repo
            try:
                payload = tool.render_known_limitations_burndown(ws)
            finally:
                tool.ROOT = old_root

        rows = {row["limitation_id"]: row for row in payload["rows"]}
        for limitation_id in ("priority-1", "cross-cut-impact-first-work-gating"):
            row = rows[limitation_id]
            self.assertEqual(row["terminal_state"], "progress_reduced_with_remaining_paths")
            self.assertFalse(row["stop_condition_met"])
            self.assertEqual(row["reduction_status"], "reduced_detected_paths_not_closed")
            self.assertEqual(row["impact_first_work_gate_reduction"]["status"], "present")
            self.assertEqual(
                row["covered_paths_after_560"],
                [
                    "critical-hunt",
                    "paste-ready",
                    "submission-packager",
                    "swarm-dispatch",
                    "mining-brief",
                    "poc-scaffold-plan-json",
                    "auto-draft-generator",
                    "harness-scaffold-emitter",
                    "submission-factory",
                    "deep-counterexample-replay-scaffold",
                    "detector-promotion",
                    "source-mining-survivor",
                    "source-mining-provider-routing",
                    "source-mining-provider-preflight",
                    "source-mining-kimi-source-extract-advisory",
                    "source-mining-minimax-adversarial-kill-advisory",
                    "semantic-graph-typed-multihop",
                    "semantic-detector-worklist",
                    "submission-factory-proof-artifact-tier",
                    "submission-packager-proof-artifact-tier",
                    "chimera-scaffold",
                    "chimera-ledger-scaffold",
                    "recon-log-bridge",
                    "corpus-detectorization",
                    "docs-validation",
                ],
            )
            self.assertNotIn("detector-promotion", row["remaining_unproven_paths_after_560"])
            self.assertIn("generic-harness-planning", row["remaining_unproven_paths_after_560"])

    def test_known_limitations_burndown_does_not_reduce_impact_first_when_path_missing(self):
        ws = self.make_ws()
        old_root = tool.ROOT
        with tempfile.TemporaryDirectory(prefix="automation_closure_impact_first_missing_") as td:
            repo = Path(td)
            (repo / "docs").mkdir()
            (repo / "tools").mkdir()
            (repo / "docs" / "KNOWN_LIMITATIONS.md").write_text("# Known\n", encoding="utf-8")
            (repo / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.known_limitations_burndown_map.v1",
                        "rows": [
                            {
                                "limitation_id": "cross-cut-impact-first-work-gating",
                                "priority_group": "cross_cut",
                                "title": "Impact-first work gating",
                                "terminal_state": "deferred_with_owner",
                                "evidence": ["Makefile target: impact-contract-check"],
                                "next_command": "make impact-contract-check WS=<workspace> STRICT=1",
                                "stop_condition": "No missing-proof candidate keeps selected impact or reportable severity.",
                                "stop_condition_met": False,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (repo / "tools" / "critical-hunt.py").write_text(
                "def _load_exact_impact_contracts(): pass\nimpact_contracts.json\n"
                "missing_exact_impact_contract\nadvisory_missing_exact_impact_contract\n",
                encoding="utf-8",
            )
            tool.ROOT = repo
            try:
                payload = tool.render_known_limitations_burndown(ws)
            finally:
                tool.ROOT = old_root

        row = payload["rows"][0]
        self.assertEqual(row["terminal_state"], "deferred_with_owner")
        self.assertFalse(row["stop_condition_met"])
        self.assertEqual(row["impact_first_work_gate_reduction"]["status"], "missing")
        self.assertIn(
            "paste_ready_exact_impact_contract_refusal",
            row["impact_first_work_gate_reduction"]["missing_checks"],
        )

    def test_known_limitations_burndown_cli_strict_uses_row_level_status(self):
        ws = self.make_ws()
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--workspace",
                str(ws),
                "--mode",
                "known-limitations-burndown",
                "--strict",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_tool_coverage_tracks_full_pr560_command_surface(self):
        ws = self.make_ws()
        payload = tool.render_tool_coverage_inventory(ws)
        rows = {row["make_target"]: row for row in payload["rows"]}
        for target in (
            "base-lessons-inventory",
            "corpus-mining-inventory",
            "corpus-detectorization-inventory",
            "impact-contract-check",
            "agent-recall",
            "impact-analysis-queue",
            "harness-task-queue",
            "source-proof-record",
            "pr560-next-actions",
            "pr560-local-progress",
        ):
            self.assertIn(target, rows)
        self.assertEqual(rows["base-lessons-inventory"]["status"], "present")
        self.assertEqual(rows["corpus-mining-inventory"]["status"], "present")
        self.assertEqual(rows["corpus-detectorization-inventory"]["status"], "present")
        self.assertIn(rows["harness-task-queue"]["status"], {"present", "missing"})
        self.assertIn(rows["source-proof-record"]["status"], {"present", "missing"})

    def test_repo_baseline_inventories(self):
        ws = self.make_ws()
        old_root = tool.ROOT
        with tempfile.TemporaryDirectory(prefix="automation_closure_repo_") as td:
            repo = Path(td)
            (repo / "docs").mkdir()
            (repo / "docs" / "CLAUDE_BASE_CRITICAL_WAVE2_EXECUTION_PLAN_2026-04-30.md").write_text(
                "wave 2", encoding="utf-8"
            )
            (repo / "reference" / "corpora").mkdir(parents=True)
            (repo / "reference" / "corpora" / "swival.json").write_text("{}", encoding="utf-8")
            tool.ROOT = repo
            try:
                lessons = tool.render_base_lessons_inventory(ws)
                corpus = tool.render_corpus_mining_inventory(ws)
            finally:
                tool.ROOT = old_root
            self.assertEqual(lessons["schema"], "auditooor.pr560.base_lessons_inventory.v1")
            self.assertEqual(corpus["schema"], "auditooor.pr560.corpus_mining_inventory.v1")
            self.assertEqual(lessons["generated_at"], "stable")
            self.assertEqual(corpus["repo"], "<repo>")
            self.assertTrue(any(str(row["artifact"]).startswith("<repo>/") for row in lessons["rows"]))
            self.assertTrue(
                any(
                    str(path).startswith("<repo>/")
                    for row in corpus["rows"]
                    for path in row.get("source_artifacts", [])
                )
            )
            self.assertTrue((repo / ".auditooor" / "base_lessons_inventory.json").is_file())
            self.assertTrue((repo / ".auditooor" / "corpus_mining_inventory.json").is_file())

    def test_repo_inventory_cli_without_workspace(self):
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--mode",
                "corpus-mining-inventory",
                "--json",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertEqual(data["schema"], "auditooor.pr560.corpus_mining_inventory.v1")


if __name__ == "__main__":
    unittest.main()
