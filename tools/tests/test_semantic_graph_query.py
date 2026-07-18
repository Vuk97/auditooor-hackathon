from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
QUERY = ROOT / "tools" / "semantic-graph-query.py"


def _write_artifacts(ws: Path) -> Path:
    aud = ws / ".auditooor"
    aud.mkdir()
    (aud / "semantic_graph.json").write_text(
        json.dumps(
            {
                "schema_version": "auditooor.semantic_graph.v1",
                "relation_edges": [
                    {
                        "file": "src/Portal.sol",
                        "line": 11,
                        "source_contract": "Portal",
                        "source_function": "finalizeWithdrawal",
                        "kind": "verifier-adapter-call",
                        "receiver": "verifier",
                        "receiver_source": "state-variable",
                        "target": "ProofVerifier",
                        "target_type": "ProofVerifier",
                        "method": "verifyProof",
                        "evidence": "verifier.verifyProof(proof, outputRoot)",
                    },
                    {
                        "file": "src/Portal.sol",
                        "line": 18,
                        "source_contract": "Portal",
                        "source_function": "registerRoute",
                        "kind": "proxy-deploy",
                        "receiver": "TransparentUpgradeableProxy",
                        "receiver_source": "new-expression",
                        "target": "TransparentUpgradeableProxy",
                        "target_type": "TransparentUpgradeableProxy",
                        "method": "constructor",
                        "evidence": "new TransparentUpgradeableProxy(impl)",
                    },
                ],
                "multi_hop_paths": [
                    {
                        "path_id": "SG-MH-001",
                        "impact_family": "bridge_finalization",
                        "source_component": "Portal.finalizeWithdrawal",
                        "sink_component": "Bridge.finalizeWithdrawal",
                        "mapped_stages": [
                            "caller",
                            "parser",
                            "state_root",
                            "validation",
                            "proof_dispute_bridge_finalization",
                        ],
                        "missing_stages": [],
                        "evidence_edges": ["Portal.finalizeWithdrawal -> verifier.verifyProof"],
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    worklist = aud / "semantic_detector_worklist.json"
    worklist.write_text(
        json.dumps(
            {
                "schema": "auditooor.semantic_detector_worklist.v1",
                "tasks": [
                    {
                        "task_id": "SDW-REL-001",
                        "source_id": "Portal.finalizeWithdrawal:verifier-adapter-call:11",
                        "candidate_detector_family": "verifier_relation",
                        "severity": "none",
                        "submission_posture": "NOT_SUBMIT_READY",
                        "impact_contract_required": True,
                        "action_lane": "detector_rewrite_candidate",
                        "detectorization_readiness": "candidate_static_predicate_needs_fixtures",
                        "detector_query_bridge": {
                            "backend": "semantic_graph_query",
                            "advisory_only": True,
                            "coverage_claim": "none_source_shape_only",
                            "source_collection": "relation_edges",
                            "query_shape": "verifier_adapter_relation",
                            "match_fields": {
                                "kind": "verifier-adapter-call",
                                "receiver_source": "state-variable",
                                "target_type": "ProofVerifier",
                                "method": "verifyProof",
                                "receiver": "verifier",
                            },
                            "must_match_any": [
                                {"kind": "verifier-adapter-call"},
                                {"target_or_method_regex": "(?i)(verif|proof)"},
                            ],
                            "required_output_fields": [
                                "file",
                                "line",
                                "source_contract",
                                "source_function",
                                "kind",
                                "receiver",
                                "target_type",
                                "method",
                                "evidence",
                            ],
                        },
                    },
                    {
                        "task_id": "SDW-MH-001",
                        "source_id": "SG-MH-001",
                        "candidate_detector_family": "bridge_finalization",
                        "severity": "none",
                        "submission_posture": "NOT_SUBMIT_READY",
                        "impact_contract_required": True,
                        "action_lane": "fixture_first_source_invariant",
                        "detectorization_readiness": "not_ready_fixture_or_invariant_first",
                        "detector_query_bridge": {
                            "backend": "semantic_graph_query",
                            "advisory_only": True,
                            "coverage_claim": "none_source_shape_only",
                            "source_collection": "multi_hop_paths",
                            "query_shape": "bridge_or_proof_finalization_path",
                            "match_fields": {
                                "impact_family": "bridge_finalization",
                                "mapped_stages": [
                                    "caller",
                                    "validation",
                                    "proof_dispute_bridge_finalization",
                                ],
                                "source_component": "Portal.finalizeWithdrawal",
                                "sink_component": "Bridge.finalizeWithdrawal",
                            },
                            "required_stages": ["caller", "validation"],
                            "required_output_fields": [
                                "path_id",
                                "impact_family",
                                "source_component",
                                "sink_component",
                                "mapped_stages",
                                "missing_stages",
                                "evidence_edges",
                            ],
                        },
                    },
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return worklist


def _write_impact_worklist(ws: Path) -> Path:
    path = ws / ".auditooor" / "impact_family_worklists.json"
    path.write_text(
        json.dumps(
            {
                "schema": "auditooor.pr560.impact_family_worklists.v1",
                "worklists": [
                    {
                        "impact_id": "impact-bridge-finalization",
                        "impact_family": "bridge_finalization",
                        "source_review_handoff": {
                            "schema": "auditooor.pr560.impact_source_review_handoff.v1",
                            "routes": [
                                {
                                    "route_id": "impact-bridge-finalization-semantic-query-001",
                                    "route_kind": "semantic_graph_query",
                                    "component_id": "SG-MH-001",
                                    "submission_posture": "NOT_SUBMIT_READY",
                                    "submit_ready": False,
                                    "semantic_graph_query": {
                                        "backend": "semantic_graph_query",
                                        "advisory_only": True,
                                        "coverage_claim": "none_source_shape_only",
                                        "source_collection": "multi_hop_paths",
                                        "query_shape": "impact_worklist_multihop_path",
                                        "match_fields": {
                                            "path_id": "SG-MH-001",
                                            "impact_family": "bridge_finalization",
                                            "source_component": "Portal.finalizeWithdrawal",
                                        },
                                        "required_output_fields": [
                                            "path_id",
                                            "impact_family",
                                            "source_component",
                                            "sink_component",
                                            "mapped_stages",
                                            "missing_stages",
                                            "evidence_edges",
                                        ],
                                    },
                                }
                            ],
                        },
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return path


class SemanticGraphQueryTest(unittest.TestCase):
    def test_executes_worklist_query_specs_as_advisory_matches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            worklist = _write_artifacts(ws)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(QUERY),
                    "--workspace",
                    str(ws),
                    "--worklist",
                    str(worklist),
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads((ws / ".auditooor" / "semantic_graph_query_results.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.semantic_graph_query_results.v1")
            self.assertEqual(payload["query_count"], 2)
            self.assertEqual(payload["matched_row_count"], 2)
            self.assertEqual(payload["severity"], "none")
            self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
            self.assertTrue(payload["impact_contract_required"])
            self.assertFalse(payload["promotion_allowed"])
            self.assertTrue(all(result["severity"] == "none" for result in payload["results"]))
            self.assertTrue(all(result["submission_posture"] == "NOT_SUBMIT_READY" for result in payload["results"]))
            self.assertTrue(all(result["impact_contract_required"] for result in payload["results"]))
            self.assertEqual(payload["query_accounting"]["matched_query_count"], 2)
            self.assertEqual(payload["query_accounting"]["zero_match_query_count"], 0)
            self.assertIn("detector_rewrite_candidate", payload["query_accounting"]["query_count_by_action_lane"])
            self.assertIn("fixture_first_source_invariant", payload["query_accounting"]["query_count_by_action_lane"])
            by_task = {result["task_id"]: result for result in payload["results"]}
            self.assertEqual(by_task["SDW-REL-001"]["matches"][0]["method"], "verifyProof")
            self.assertEqual(by_task["SDW-REL-001"]["action_lane"], "detector_rewrite_candidate")
            self.assertEqual(by_task["SDW-MH-001"]["matches"][0]["path_id"], "SG-MH-001")
            self.assertEqual(by_task["SDW-MH-001"]["action_lane"], "fixture_first_source_invariant")
            self.assertFalse(by_task["SDW-MH-001"]["matches"][0]["promotion_allowed"])
            md = (ws / ".auditooor" / "semantic_graph_query_results.md").read_text(encoding="utf-8")
            self.assertIn("These rows are not findings", md)

    def test_task_filter_runs_only_selected_query(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_artifacts(ws)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(QUERY),
                    "--workspace",
                    str(ws),
                    "--task-id",
                    "SDW-MH-001",
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual([result["task_id"] for result in payload["results"]], ["SDW-MH-001"])
            self.assertEqual(payload["matched_row_count"], 1)

    def test_executes_impact_worklist_handoff_query_specs_as_advisory_matches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_artifacts(ws)
            impact_worklist = _write_impact_worklist(ws)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(QUERY),
                    "--workspace",
                    str(ws),
                    "--impact-worklist",
                    str(impact_worklist),
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["source_mode"], "impact_family_worklist")
            self.assertEqual(payload["impact_worklist_row_count"], 1)
            self.assertEqual(payload["query_count"], 1)
            self.assertEqual(payload["matched_row_count"], 1)
            result = payload["results"][0]
            self.assertEqual(result["task_id"], "impact-bridge-finalization-semantic-query-001")
            self.assertEqual(result["impact_id"], "impact-bridge-finalization")
            self.assertEqual(result["route_kind"], "semantic_graph_query")
            self.assertEqual(result["submission_posture"], "NOT_SUBMIT_READY")
            self.assertFalse(result["promotion_allowed"])

    def test_impact_worklist_mode_skips_unsupported_handoff_specs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_artifacts(ws)
            impact_worklist = _write_impact_worklist(ws)
            payload = json.loads(impact_worklist.read_text(encoding="utf-8"))
            payload["worklists"][0]["source_review_handoff"]["routes"].append(
                {
                    "route_id": "impact-bridge-finalization-semantic-query-unsupported",
                    "route_kind": "semantic_graph_query",
                    "semantic_graph_query": {
                        "backend": "semantic_graph_query",
                        "source_collection": "entrypoints",
                        "query_shape": "unsupported_entrypoint_shape",
                    },
                }
            )
            impact_worklist.write_text(json.dumps(payload), encoding="utf-8")

            proc = subprocess.run(
                [
                    sys.executable,
                    str(QUERY),
                    "--workspace",
                    str(ws),
                    "--impact-worklist",
                    str(impact_worklist),
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            result_payload = json.loads(proc.stdout)
            self.assertEqual(result_payload["query_count"], 1)
            self.assertEqual(result_payload["error_count"], 0)
            self.assertEqual(
                result_payload["results"][0]["task_id"],
                "impact-bridge-finalization-semantic-query-001",
            )

    def test_missing_graph_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            proc = subprocess.run(
                [sys.executable, str(QUERY), "--workspace", str(ws)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("missing JSON artifact", proc.stderr)


if __name__ == "__main__":
    unittest.main()
