#!/usr/bin/env python3
"""Tests for Runtime/DLT evidence validator terminal non-proof rows."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "tools" / "runtime-dlt-evidence-validator.py"


class RuntimeDltEvidenceValidatorTests(unittest.TestCase):
    def _run_validator(self, ws: Path, out: Path) -> dict[str, object]:
        proc = subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                "--workspace",
                str(ws),
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
        return json.loads(out.read_text(encoding="utf-8"))

    def test_loop5_killed_evidence_and_preflight_queue_become_non_proof_rows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime_dlt_validator_") as tmp:
            ws = Path(tmp)
            (ws / ".auditooor" / "loop5_preflight").mkdir(parents=True)
            (ws / "agent_outputs").mkdir()
            (ws / "agent_outputs" / "killed.md").write_text("killed\n", encoding="utf-8")
            summary = {
                "schema": "auditooor.loop5.runtime_dlt_evidence_summary.v1",
                "evidence_records": [
                    {
                        "id": "loop4-span-batch",
                        "lane": "span-batch decode bomb",
                        "posture": "killed_below_resource_threshold",
                        "basis": "Measured below threshold.",
                        "primary_artifacts": ["agent_outputs/killed.md"],
                    }
                ],
            }
            (ws / ".auditooor" / "loop5_runtime_dlt_evidence_summary.json").write_text(
                json.dumps(summary), encoding="utf-8"
            )
            queue = {
                "rows": [
                    {
                        "benchmark_id": "imo-critical-consensus-safety-01",
                        "task_id": "impact-miss-imo-critical-consensus-safety-01",
                        "tier": "Critical",
                        "route_family": "consensus_safety",
                        "status": "blocked_missing_artifacts",
                        "missing_artifacts": ["consensus_replay_or_model"],
                        "runtime_semantic_dependency": {
                            "status": "present_missing_expected_runtime_family"
                        },
                    },
                    {
                        "benchmark_id": "imo-critical-asset-custody-01",
                        "route_family": "asset_custody",
                        "status": "blocked_missing_artifacts",
                    },
                ]
            }
            (ws / ".auditooor" / "loop5_preflight" / "impact_miss_harness_blocker_queue.json").write_text(
                json.dumps(queue), encoding="utf-8"
            )
            out = ws / ".auditooor" / "validator.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATOR),
                    "--workspace",
                    str(ws),
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
            self.assertEqual(
                payload["schema"],
                "auditooor.pr560.runtime_dlt_execution_evidence_validator.v3",
            )
            self.assertTrue(payload["queue_path"].endswith("loop5_preflight/impact_miss_harness_blocker_queue.json"))
            self.assertEqual(payload["dlt_row_count"], 2)
            self.assertEqual(payload["terminal_not_reportable_count"], 1)
            self.assertEqual(payload["proved_exploit_impact_count"], 0)
            self.assertEqual(payload["mapped_runtime_proof_count"], 0)
            self.assertFalse(payload["promotion_allowed"])
            self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
            terminal = next(row for row in payload["rows"] if row["id"] == "loop4-span-batch")
            self.assertEqual(terminal["status"], "terminal_not_reportable")
            self.assertEqual(terminal["impact_assertion"], "not_demonstrated")
            self.assertEqual(terminal["artifact_status"], {"present": 1, "total": 1})

    def test_record_blocked_runtime_evidence_maps_impact_without_promotion(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime_dlt_record_") as tmp:
            ws = Path(tmp)
            (ws / "evidence").mkdir()
            (ws / "critical_hunt" / "wave5_impact_class_search").mkdir(parents=True)
            (ws / "evidence" / "blocked.md").write_text("missing engine-tree fixture\n", encoding="utf-8")
            matrix = {
                "rows": [
                    {
                        "row_id": 2,
                        "impact_text_verbatim": "Unintended permanent chain split requiring hard fork.",
                        "rubric_anchor": "SEVERITY.md:79 (Blockchain/DLT Critical, BDL-C2)",
                        "status": "gap_with_lane",
                        "proof_required": "multi-client differential replay",
                    }
                ]
            }
            (ws / "critical_hunt" / "wave5_impact_class_search" / "impact_class_matrix.json").write_text(
                json.dumps(matrix), encoding="utf-8"
            )
            out = ws / ".auditooor" / "validator.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATOR),
                    "--workspace",
                    str(ws),
                    "--out-json",
                    str(out),
                    "--record-id",
                    "fn7-engine-tree-blocker",
                    "--record-status",
                    "blocked",
                    "--candidate",
                    "FN7",
                    "--route-family",
                    "consensus_safety",
                    "--impact-class",
                    "2",
                    "--impact-assertion",
                    "unknown",
                    "--proof-source",
                    "manual_triage",
                    "--artifact",
                    "evidence/blocked.md",
                    "--notes",
                    "Needs engine-tree integration fixture; mock provider proof is not enough.",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertFalse(payload["promotion_allowed"])
            self.assertEqual(payload["summary"]["impact_class_counts"], {"2": 1})
            row = next(row for row in payload["rows"] if row["id"] == "fn7-engine-tree-blocker")
            self.assertEqual(row["mapped_impact"]["severity"], "Critical")
            self.assertEqual(row["proof_class"], "blocked_runtime_candidate")
            self.assertEqual(row["promotion_blockers"], [])

    def test_proved_mock_record_is_rejected_before_append(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime_dlt_mock_proved_") as tmp:
            ws = Path(tmp)
            (ws / "evidence").mkdir()
            (ws / "critical_hunt" / "wave5_impact_class_search").mkdir(parents=True)
            (ws / "evidence" / "mock.log").write_text("mock passed\n", encoding="utf-8")
            matrix = {
                "rows": [
                    {
                        "row_id": 2,
                        "impact_text_verbatim": "Unintended permanent chain split requiring hard fork.",
                        "rubric_anchor": "SEVERITY.md:79 (Blockchain/DLT Critical, BDL-C2)",
                    }
                ]
            }
            (ws / "critical_hunt" / "wave5_impact_class_search" / "impact_class_matrix.json").write_text(
                json.dumps(matrix), encoding="utf-8"
            )
            records = ws / ".auditooor" / "runtime_dlt_evidence_records.jsonl"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATOR),
                    "--workspace",
                    str(ws),
                    "--record-id",
                    "mock-proof",
                    "--record-status",
                    "proved",
                    "--route-family",
                    "consensus_safety",
                    "--impact-class",
                    "2",
                    "--impact-assertion",
                    "exploit_impact",
                    "--proof-source",
                    "mock_harness",
                    "--artifact",
                    "evidence/mock.log",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("mock_unit_static_or_scanner_evidence_cannot_promote", proc.stderr)
            self.assertFalse(records.exists())

    def test_strict_poc_execution_manifest_counts_for_runtime_promotion(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime_dlt_strict_manifest_") as tmp:
            ws = Path(tmp)
            candidate = "imo-critical-consensus-safety-01"
            write_path = ws / "poc_execution" / candidate / "execution_manifest.json"
            write_path.parent.mkdir(parents=True)
            write_path.write_text(
                json.dumps(
                    {
                        "candidate_id": candidate,
                        "final_result": "proved",
                        "impact_assertion": "exploit_impact",
                        "evidence_class": "executed_with_manifest",
                        "commands_attempted": [{"command": "cargo test runtime_proof", "status": "pass", "exit_code": "0"}],
                    }
                ),
                encoding="utf-8",
            )
            out = ws / ".auditooor" / "validator.json"
            payload = self._run_validator(ws, out)

        self.assertEqual(payload["proved_exploit_impact_count"], 1)
        self.assertTrue(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "SUBMIT_READY")

    def test_loose_poc_execution_manifest_does_not_count_for_runtime_promotion(self) -> None:
        loose_manifests = {
            "missing-evidence-class": {
                "final_result": "proved",
                "impact_assertion": "exploit_impact",
                "commands_attempted": [{"command": "cargo test runtime_proof", "status": "pass", "exit_code": 0}],
            },
            "legacy-string-command": {
                "final_result": "proved",
                "impact_assertion": "exploit_impact",
                "evidence_class": "executed_with_manifest",
                "commands_attempted": ["cargo test runtime_proof"],
            },
            "missing-command-text": {
                "final_result": "proved",
                "impact_assertion": "exploit_impact",
                "evidence_class": "executed_with_manifest",
                "commands_attempted": [{"command": "", "status": "pass", "exit_code": 0}],
            },
            "failed-command": {
                "final_result": "proved",
                "impact_assertion": "exploit_impact",
                "evidence_class": "executed_with_manifest",
                "commands_attempted": [{"command": "cargo test runtime_proof", "status": "fail", "exit_code": 1}],
            },
            "bool-exit-code": {
                "final_result": "proved",
                "impact_assertion": "exploit_impact",
                "evidence_class": "executed_with_manifest",
                "commands_attempted": [{"command": "cargo test runtime_proof", "status": "pass", "exit_code": True}],
            },
        }
        for label, manifest in loose_manifests.items():
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory(prefix=f"runtime_dlt_loose_{label}_") as tmp:
                    ws = Path(tmp)
                    candidate = "imo-critical-consensus-safety-01"
                    write_path = ws / "poc_execution" / candidate / "execution_manifest.json"
                    write_path.parent.mkdir(parents=True)
                    write_path.write_text(json.dumps(manifest), encoding="utf-8")
                    out = ws / ".auditooor" / "validator.json"
                    payload = self._run_validator(ws, out)

                self.assertEqual(payload["proved_exploit_impact_count"], 0)
                self.assertFalse(payload["promotion_allowed"])
                self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")


if __name__ == "__main__":
    unittest.main()
