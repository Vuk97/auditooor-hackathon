from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "semantic-detector-adjudication.py"


def _write_inputs(ws: Path) -> None:
    aud = ws / ".auditooor"
    aud.mkdir()
    (aud / "semantic_detector_worklist.json").write_text(
        json.dumps(
            {
                "schema": "auditooor.semantic_detector_worklist.v1",
                "coverage_claim": "none_source_shape_only",
                "advisory_only": True,
                "promotion_allowed": False,
                "tasks": [
                    {
                        "task_id": "SDW-REL-001",
                        "candidate_detector_family": "verifier_relation",
                        "submission_posture": "NOT_SUBMIT_READY",
                        "severity": "none",
                        "impact_contract_required": True,
                        "action_lane": "detector_rewrite_candidate",
                        "detectorization_readiness": "candidate_static_predicate_needs_fixtures",
                        "detector_query_bridge": {
                            "backend": "semantic_graph_query",
                            "query_shape": "verifier_adapter_relation",
                            "fixture_tags": ["verifier", "proof"],
                        },
                    },
                    {
                        "task_id": "SDW-MH-001",
                        "candidate_detector_family": "bridge_finalization",
                        "impact_family": "bridge_finalization",
                        "submission_posture": "NOT_SUBMIT_READY",
                        "severity": "none",
                        "impact_contract_required": True,
                        "action_lane": "fixture_first_source_invariant",
                        "detectorization_readiness": "not_ready_fixture_or_invariant_first",
                        "detector_query_bridge": {
                            "backend": "semantic_graph_query",
                            "query_shape": "bridge_or_proof_finalization_path",
                            "fixture_tags": ["bridge", "proof", "finalization"],
                        },
                    },
                    {
                        "task_id": "SDW-REL-002",
                        "candidate_detector_family": "generic_typed_relation",
                        "submission_posture": "NOT_SUBMIT_READY",
                        "severity": "none",
                        "impact_contract_required": True,
                        "action_lane": "detector_rewrite_candidate",
                        "detectorization_readiness": "candidate_static_predicate_needs_fixtures",
                        "detector_query_bridge": {
                            "backend": "semantic_graph_query",
                            "query_shape": "generic_typed_relation",
                            "fixture_tags": ["relation"],
                        },
                    },
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (aud / "semantic_graph_query_results.json").write_text(
        json.dumps(
            {
                "schema": "auditooor.semantic_graph_query_results.v1",
                "workspace": str(ws),
                "source_mode": "semantic_detector_worklist",
                "source_artifact": str(aud / "semantic_detector_worklist.json"),
                "query_count": 4,
                "matched_row_count": 3,
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
                        "task_id": "SDW-REL-001",
                        "route_id": "SDW-REL-001",
                        "candidate_detector_family": "verifier_relation",
                        "query_shape": "verifier_adapter_relation",
                        "source_collection": "relation_edges",
                        "query_status": "executed",
                        "match_count": 1,
                        "truncated": False,
                        "severity": "none",
                        "selected_impact": "",
                        "submission_posture": "NOT_SUBMIT_READY",
                        "impact_contract_required": True,
                        "action_lane": "detector_rewrite_candidate",
                        "matches": [
                            {
                                "file": "src/Portal.sol",
                                "line": 11,
                                "source_contract": "Portal",
                                "source_function": "finalizeWithdrawal",
                                "kind": "verifier-adapter-call",
                                "receiver": "verifier",
                                "target_type": "ProofVerifier",
                                "method": "verifyProof",
                            }
                        ],
                    },
                    {
                        "task_id": "SDW-MH-001",
                        "route_id": "SDW-MH-001",
                        "candidate_detector_family": "bridge_finalization",
                        "impact_family": "bridge_finalization",
                        "query_shape": "bridge_or_proof_finalization_path",
                        "source_collection": "multi_hop_paths",
                        "query_status": "executed",
                        "match_count": 1,
                        "truncated": False,
                        "severity": "none",
                        "selected_impact": "",
                        "submission_posture": "NOT_SUBMIT_READY",
                        "impact_contract_required": True,
                        "action_lane": "fixture_first_source_invariant",
                        "matches": [
                            {
                                "path_id": "SG-MH-001",
                                "source_component": "Portal.finalizeWithdrawal",
                                "sink_component": "Bridge.finalizeWithdrawal",
                            }
                        ],
                    },
                    {
                        "task_id": "SDW-REL-002",
                        "route_id": "SDW-REL-002",
                        "candidate_detector_family": "generic_typed_relation",
                        "query_shape": "generic_typed_relation",
                        "source_collection": "relation_edges",
                        "query_status": "executed",
                        "match_count": 1,
                        "truncated": False,
                        "severity": "none",
                        "selected_impact": "",
                        "submission_posture": "NOT_SUBMIT_READY",
                        "impact_contract_required": True,
                        "action_lane": "detector_rewrite_candidate",
                        "matches": [{"file": "src/Generic.sol", "line": 7}],
                    },
                    {
                        "task_id": "SDW-REL-003",
                        "route_id": "SDW-REL-003",
                        "candidate_detector_family": "registry_relation",
                        "query_shape": "registry_write_relation",
                        "source_collection": "relation_edges",
                        "query_status": "executed",
                        "match_count": 0,
                        "truncated": False,
                        "severity": "none",
                        "selected_impact": "",
                        "submission_posture": "NOT_SUBMIT_READY",
                        "impact_contract_required": True,
                        "action_lane": "detector_rewrite_candidate",
                        "matches": [],
                    },
                    {
                        "task_id": "SDW-REL-001",
                        "route_id": "SDW-REL-001-retry",
                        "candidate_detector_family": "verifier_relation",
                        "query_shape": "verifier_adapter_relation",
                        "source_collection": "relation_edges",
                        "query_status": "blocked_missing_graph",
                        "match_count": 1,
                        "truncated": False,
                        "severity": "none",
                        "selected_impact": "",
                        "submission_posture": "NOT_SUBMIT_READY",
                        "impact_contract_required": True,
                        "action_lane": "detector_rewrite_candidate",
                        "matches": [{"file": "src/Blocked.sol", "line": 5}],
                    },
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )


class SemanticDetectorAdjudicationTest(unittest.TestCase):
    def test_adjudicates_query_results_into_briefs_fixtures_and_non_detectorizable_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_inputs(ws)
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws), "--print-json"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads((ws / ".auditooor" / "semantic_detector_adjudication.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.semantic_detector_adjudication.v1")
            self.assertEqual(payload["detector_rewrite_brief_count"], 1)
            self.assertEqual(payload["fixture_requirement_count"], 2)
            self.assertEqual(payload["non_detectorizable_count"], 4)
            self.assertGreaterEqual(payload["action_item_count"], 6)
            self.assertTrue(payload["source_shape_limitations"])
            self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
            self.assertEqual(payload["severity"], "none")
            self.assertEqual(payload["selected_impact"], "")
            self.assertFalse(payload["promotion_allowed"])
            self.assertTrue(payload["impact_contract_required"])
            self.assertFalse(payload["readiness"]["ready_for_submission"])
            self.assertEqual(payload["readiness"]["ready_for_detector_rewrite_count"], 1)
            self.assertIn("query_status_blocked-missing-graph", payload["adjudication_summary"]["non_detectorizable_reason_counts"])
            self.assertTrue(payload["next_commands"])

            brief = payload["detector_rewrite_briefs"][0]
            self.assertEqual(brief["adjudication"], "detector_rewrite_brief")
            self.assertEqual(brief["task_id"], "SDW-REL-001")
            self.assertEqual(brief["sample"]["method"], "verifyProof")
            self.assertEqual(brief["submission_posture"], "NOT_SUBMIT_READY")
            self.assertEqual(brief["severity"], "none")
            self.assertIn("vulnerable fixture missing", brief["promotion_blockers"])
            self.assertIn("make semantic-detector-adjudication WS=", brief["next_command"])
            self.assertIn("smoke_command", brief)
            self.assertIn("fixture_plan", brief)
            self.assertEqual(brief["terminal_decision_required"], "detectorizable_with_vulnerable_and_clean_fixtures")
            self.assertEqual(brief["next_action_type"], "detector_rewrite_with_paired_fixtures")
            self.assertIn("run detector smoke and capture output", brief["local_checklist"])

            fixture_ids = {row["fixture_id"] for row in payload["fixture_requirements"]}
            self.assertEqual(fixture_ids, {"SDA-FIX-001", "SDA-FIX-002"})
            fixture = payload["fixture_requirements"][0]
            self.assertEqual(len(fixture["fixture_artifact_requirements"]), 3)
            self.assertIn("positive_fixture", {row["kind"] for row in fixture["fixture_artifact_requirements"]})
            mh_fixture = next(row for row in payload["fixture_requirements"] if row["task_id"] == "SDW-MH-001")
            self.assertEqual(mh_fixture["terminal_decision_required"], "fixture_first_before_detector_rewrite")
            reasons = {row["reason"] for row in payload["non_detectorizable_rows"]}
            self.assertIn("zero_match_query_result", reasons)
            self.assertIn("source_shape_too_generic_for_detector_rewrite", reasons)
            self.assertIn("multi_hop_path_requires_fixture_or_invariant_before_detector_rewrite", reasons)
            self.assertIn("query_status_blocked-missing-graph", reasons)
            source_only = next(row for row in payload["non_detectorizable_rows"] if row["reason"] == "zero_match_query_result")
            self.assertIn("make source-proof-task-queue WS=", source_only["next_command"])
            self.assertTrue(source_only["source_review_id"].startswith("SDA-SRC-"))
            self.assertEqual(source_only["terminal_decision_required"], "source_review_or_invariant_only")
            self.assertTrue(all(item["submit_ready"] is False for item in payload["action_items"]))

            md = (ws / ".auditooor" / "semantic_detector_adjudication.md").read_text(encoding="utf-8")
            self.assertIn("Semantic Detector Adjudication", md)
            self.assertIn("not findings", md)
            self.assertIn("Source-Shape Limitations", md)
            self.assertIn("Non-Detectorizable Reason Counts", md)

    def test_missing_query_results_is_named_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir()
            (ws / ".auditooor" / "semantic_detector_worklist.json").write_text('{"tasks": []}\n', encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("missing semantic query results", proc.stderr)


if __name__ == "__main__":
    unittest.main()
