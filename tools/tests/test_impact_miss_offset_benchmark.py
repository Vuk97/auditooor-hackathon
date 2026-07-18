#!/usr/bin/env python3
"""Tests for the Impact-Miss Offset withheld-known benchmark."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "impact-miss-offset-benchmark.py"


class ImpactMissOffsetBenchmarkTests(unittest.TestCase):
    def test_generates_workspace_neutral_384_item_cross_tier_benchmark(self) -> None:
        with tempfile.TemporaryDirectory(prefix="imo_benchmark_") as tmp:
            ws = Path(tmp)
            out = ws / "benchmark.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--out-json",
                    str(out),
                    "--demo-fixture",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.pr560.impact_miss_offset_benchmark.v1")
            self.assertEqual(payload["summary"]["item_count"], 384)
            self.assertEqual(payload["summary"]["route_family_count"], 12)
            self.assertEqual(
                payload["summary"]["tier_counts"],
                {"Critical": 96, "High": 96, "Low": 96, "Medium": 96},
            )
            self.assertTrue(all(row["withheld_known"] for row in payload["items"]))
            self.assertTrue(all(row["evidence_class"] == "generated_hypothesis" for row in payload["items"]))
            self.assertTrue(all(row["expected"]["submission_posture"] == "NOT_SUBMIT_READY" for row in payload["items"]))
            self.assertTrue(all(row["pass_fail_criteria"] for row in payload["items"]))
            fixture = Path(payload["demo_fixture"]["source"])
            self.assertTrue(fixture.is_file())
            self.assertIn("DemoVault", fixture.read_text(encoding="utf-8"))

    def test_scores_predictions_by_route_artifact_and_posture(self) -> None:
        with tempfile.TemporaryDirectory(prefix="imo_score_") as tmp:
            ws = Path(tmp)
            baseline = ws / "baseline.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--limit",
                    "192",
                    "--out-json",
                    str(baseline),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            base = json.loads(baseline.read_text(encoding="utf-8"))
            predictions = [
                {
                    "benchmark_id": row["benchmark_id"],
                    "route_family": row["expected"]["route_family"],
                    "artifacts": [row["expected"]["required_artifacts"][0]],
                    "submission_posture": "NOT_SUBMIT_READY",
                }
                for row in base["items"]
            ]
            pred_path = ws / "predictions.json"
            pred_path.write_text(json.dumps({"predictions": predictions}), encoding="utf-8")
            scored = ws / "scored.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--limit",
                    "192",
                    "--predictions",
                    str(pred_path),
                    "--out-json",
                    str(scored),
                    "--strict",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(scored.read_text(encoding="utf-8"))
            self.assertEqual(payload["score"]["status"], "pass")
            self.assertEqual(payload["score"]["passed"], 192)
            self.assertEqual(payload["score"]["accuracy"], 1.0)

    def test_strict_fails_bad_predictions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="imo_bad_") as tmp:
            ws = Path(tmp)
            pred_path = ws / "predictions.json"
            pred_path.write_text(
                json.dumps({"predictions": [{"benchmark_id": "imo-critical-asset-custody-01", "route_family": "wrong"}]}),
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--predictions",
                    str(pred_path),
                    "--strict",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)

    def test_derives_advisory_predictions_from_workspace_outputs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="imo_derive_") as tmp:
            ws = Path(tmp)
            auditooor = ws / ".auditooor"
            auditooor.mkdir()
            (auditooor / "scanner_autonomy_plan.json").write_text(
                json.dumps(
                    {
                        "schema": "test",
                        "submission_posture": "NOT_SUBMIT_READY",
                        "promotion_allowed": False,
                        "tasks": [
                            {
                                "task_id": "SAE-001",
                                "submission_posture": "NOT_SUBMIT_READY",
                                "promotion_allowed": False,
                                "reason": "vault withdraw fund balance route needs impact contract",
                            },
                            {
                                "task_id": "SAE-002",
                                "submission_posture": "NOT_SUBMIT_READY",
                                "promotion_allowed": False,
                                "reason": "bridge message finalize root route needs production proof",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            out = ws / "scored.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--limit",
                    "192",
                    "--derive-predictions",
                    "--out-json",
                    str(out),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(out.read_text(encoding="utf-8"))
            pred_path = Path(payload["predictions_path"])
            self.assertTrue(pred_path.is_file())
            predictions = json.loads(pred_path.read_text(encoding="utf-8"))
            self.assertEqual(predictions["submission_posture"], "NOT_SUBMIT_READY")
            self.assertEqual(predictions["evidence_class"], "generated_hypothesis")
            self.assertTrue(all(row["evidence_class"] == "generated_hypothesis" for row in predictions["predictions"]))
            self.assertFalse(predictions["promotion_allowed"])
            self.assertGreaterEqual(predictions["source_accounting"]["source_row_count"], 2)
            self.assertIn("scanner_autonomy_plan", predictions["source_accounting"]["source_counts"])
            self.assertIn(payload["score"]["status"], {"pass", "fail"})
            self.assertEqual(payload["score"]["prediction_count"], 192)

    def test_derived_predictions_keep_next_artifact_for_unsupported_route_family(self) -> None:
        with tempfile.TemporaryDirectory(prefix="imo_unsupported_") as tmp:
            ws = Path(tmp)
            auditooor = ws / ".auditooor"
            auditooor.mkdir()
            (auditooor / "scanner_autonomy_plan.json").write_text(
                json.dumps(
                    {
                        "tasks": [
                            {
                                "task_id": "SAE-001",
                                "submission_posture": "NOT_SUBMIT_READY",
                                "promotion_allowed": False,
                                "reason": "vault withdraw fund balance route needs impact contract",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            out = ws / "scored.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--limit",
                    "192",
                    "--derive-predictions",
                    "--out-json",
                    str(out),
                    "--strict",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(out.read_text(encoding="utf-8"))
            predictions = json.loads(Path(payload["predictions_path"]).read_text(encoding="utf-8"))
            resource_rows = [
                row for row in predictions["predictions"] if row["benchmark_id"].startswith("imo-critical-resource-consumption")
            ]
            self.assertEqual(len(resource_rows), 4)
            self.assertTrue(all(row["artifacts"] == ["impact_contract"] for row in resource_rows))
            self.assertTrue(all(row["route_support_status"] == "unsupported_by_workspace_outputs" for row in resource_rows))
            self.assertTrue(all(row["terminal_blockers"] for row in resource_rows))
            self.assertEqual(payload["score"]["failed"], 0)

    def test_emits_192_harness_blockers_without_proof_claims(self) -> None:
        with tempfile.TemporaryDirectory(prefix="imo_harness_blockers_") as tmp:
            ws = Path(tmp)
            out = ws / "benchmark.json"
            blockers = ws / "blockers.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--limit",
                    "192",
                    "--emit-harness-blockers",
                    "--harness-blockers-json",
                    str(blockers),
                    "--out-json",
                    str(out),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(out.read_text(encoding="utf-8"))
            queue = json.loads(blockers.read_text(encoding="utf-8"))
            self.assertEqual(queue["schema"], "auditooor.pr560.impact_miss_harness_blocker_queue.v1")
            self.assertEqual(queue["evidence_class"], "scaffolded_unverified")
            self.assertEqual(queue["item_count"], 192)
            self.assertEqual(len(queue["rows"]), 192)
            self.assertFalse(queue["promotion_allowed"])
            self.assertFalse(queue["submit_ready"])
            self.assertEqual(payload["harness_blockers"]["path"], str(blockers))
            self.assertTrue(all(row["submission_posture"] == "NOT_SUBMIT_READY" for row in queue["rows"]))
            self.assertTrue(all(row["evidence_class"] == "scaffolded_unverified" for row in queue["rows"]))
            self.assertTrue(all(row["missing_artifacts"] for row in queue["rows"]))
            self.assertTrue(
                all("RESULT=needs_human IMPACT=unknown" in " ".join(row["runnable_next_commands"]) for row in queue["rows"])
            )
            self.assertFalse(any("RESULT=proved" in " ".join(row["runnable_next_commands"]) for row in queue["rows"]))
            dlt_rows = [row for row in queue["rows"] if row["asset_category"] == "Blockchain/DLT"]
            self.assertTrue(dlt_rows)
            self.assertTrue(all(row["runtime_semantic_dependency"]["required"] for row in dlt_rows))
            self.assertTrue(
                all(
                    row["runtime_semantic_dependency"]["status"] == "required_not_collected"
                    for row in dlt_rows
                )
            )
            self.assertEqual(queue["summary"]["rows_requiring_runtime_semantics"], len(dlt_rows))
            self.assertIn("consensus_client", queue["summary"]["runtime_expected_family_counts"])
            self.assertTrue(
                all("make rust-runtime-semantic-blockers" in row["runtime_semantic_dependency"]["next_command"] for row in dlt_rows)
            )
            smart_contract_rows = [row for row in queue["rows"] if row["asset_category"] == "Smart Contract"]
            self.assertTrue(smart_contract_rows)
            self.assertTrue(all(row["runtime_semantic_dependency"] == {} for row in smart_contract_rows))
            brief = ws / ".auditooor" / "impact_miss_harness_briefs" / "imo-critical-asset-custody-01.md"
            self.assertTrue(brief.is_file())
            self.assertIn("Proof Boundary", brief.read_text(encoding="utf-8"))

    def test_dlt_harness_blockers_are_runtime_family_aware_when_artifact_exists(self) -> None:
        with tempfile.TemporaryDirectory(prefix="imo_runtime_family_") as tmp:
            ws = Path(tmp)
            auditooor = ws / ".auditooor"
            auditooor.mkdir()
            (auditooor / "rust_runtime_semantic_blockers.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.rust_runtime_semantic_blockers.v1",
                        "runtime_component_family_counts": {
                            "runtime_resource": 2,
                            "execution_client": 1,
                        },
                        "runtime_readiness_gates": [
                            {
                                "runtime_component_family": "runtime_resource",
                                "status": "observed_but_unproved",
                            },
                            {
                                "runtime_component_family": "consensus_client",
                                "status": "missing_workspace_evidence",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            blockers = ws / "blockers.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--limit",
                    "192",
                    "--emit-harness-blockers",
                    "--harness-blockers-json",
                    str(blockers),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            queue = json.loads(blockers.read_text(encoding="utf-8"))
            resource_rows = [
                row for row in queue["rows"]
                if row["route_family"] == "resource_consumption"
            ]
            consensus_rows = [
                row for row in queue["rows"]
                if row["route_family"] == "consensus_safety"
            ]
            self.assertTrue(resource_rows)
            self.assertTrue(consensus_rows)
            self.assertTrue(
                all(
                    row["runtime_semantic_dependency"]["status"] == "present_expected_family_unproved"
                    for row in resource_rows
                )
            )
            self.assertTrue(
                all(
                    row["runtime_semantic_dependency"]["status"] == "present_missing_expected_runtime_family"
                    for row in consensus_rows
                )
            )
            self.assertEqual(
                resource_rows[0]["runtime_semantic_dependency"]["runtime_readiness_gate_status"],
                "observed_but_unproved",
            )
            self.assertIn(
                "present_expected_family_unproved",
                queue["summary"]["runtime_dependency_status_counts"],
            )
            self.assertIn(
                "present_missing_expected_runtime_family",
                queue["summary"]["runtime_dependency_status_counts"],
            )


if __name__ == "__main__":
    unittest.main()
