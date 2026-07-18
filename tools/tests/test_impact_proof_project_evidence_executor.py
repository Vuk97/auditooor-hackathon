from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "impact-proof-project-evidence-executor.py"


class ImpactProofProjectEvidenceExecutorTests(unittest.TestCase):
    def run_executor(self, workspace: Path) -> dict[str, Any]:
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--workspace", str(workspace)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return json.loads(
            (workspace / ".auditooor" / "impact_proof_project_evidence_executor_eo.json").read_text(
                encoding="utf-8"
            )
        )

    def write_source_ref(self, workspace: Path) -> str:
        source = workspace / "src" / "Verifier.sol"
        source.parent.mkdir(parents=True)
        source.write_text("contract Verifier {}\n", encoding="utf-8")
        return "workspace:src/Verifier.sol:1"

    def write_strict_manifest(self, workspace: Path, candidate: str) -> Path:
        manifest = workspace / "poc_execution" / candidate / "execution_manifest.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(
            json.dumps(
                {
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": [{"command": "forge test", "status": "pass", "exit_code": 0}],
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return manifest

    def write_inputs(
        self,
        workspace: Path,
        *,
        candidate: str = "imo-low-proof-verification-01",
        source_refs: list[str] | None = None,
        manifest_path: Path | None = None,
        listed_impact_proven: bool = True,
        backfill_extra: dict[str, Any] | None = None,
        execution_extra: dict[str, Any] | None = None,
    ) -> None:
        aud = workspace / ".auditooor"
        aud.mkdir(parents=True, exist_ok=True)
        backfill_row: dict[str, Any] = {
            "candidate_id": candidate,
            "requirement_id": "IPR-001",
            "tier": "Low",
            "route_family": "proof_verification",
            "listed_impact_proven": listed_impact_proven,
            "terminal_blockers": [],
            "source_proofs": [],
        }
        if source_refs is not None:
            backfill_row["source_proofs"] = [
                {
                    "project_source_citation_count": len(source_refs),
                    "source_refs": source_refs,
                }
            ]
        if backfill_extra:
            backfill_row.update(backfill_extra)

        execution_row: dict[str, Any] = {
            "candidate_id": candidate,
            "requirement_id": "IPR-001",
            "tier": "Low",
            "route_family": "proof_verification",
            "listed_impact_proven": listed_impact_proven,
            "terminal_blockers": [],
            "local_artifacts": {"artifact_refs": []},
        }
        if manifest_path is not None:
            execution_row["execution_manifest"] = {"path": str(manifest_path)}
            execution_row["local_artifacts"]["artifact_refs"].append(
                {
                    "artifact": "poc_execution_manifest",
                    "exists": True,
                    "path": str(manifest_path),
                    "required": True,
                }
            )
        if execution_extra:
            execution_row.update(execution_extra)

        (aud / "impact_proof_source_citation_backfill.json").write_text(
            json.dumps({"rows": [backfill_row]}) + "\n",
            encoding="utf-8",
        )
        (aud / "impact_proof_requirement_execution.json").write_text(
            json.dumps({"rows": [execution_row]}) + "\n",
            encoding="utf-8",
        )

    def test_ready_pass_requires_current_source_refs_and_strict_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ippe_ready_") as tmp:
            ws = Path(tmp)
            candidate = "imo-low-proof-verification-01"
            source_ref = self.write_source_ref(ws)
            manifest = self.write_strict_manifest(ws, candidate)
            self.write_inputs(ws, candidate=candidate, source_refs=[source_ref], manifest_path=manifest)

            payload = self.run_executor(ws)
            self.assertEqual(payload["summary"]["closure_candidate_count"], 1)
            self.assertEqual(payload["summary"]["proof_ready_rows"], 1)
            row = payload["rows"][0]
            self.assertEqual(row["decision"], "closure_candidate_requires_scope_oos_review")
            self.assertTrue(row["proof_ready"])
            self.assertTrue(row["executable"])
            self.assertEqual(row["terminal_blockers"], [])
            self.assertEqual(row["non_executable_reasons"], [])
            self.assertEqual(row["proof_completeness"]["current_workspace_source_refs"], [source_ref])
            self.assertEqual(row["execution_manifest"]["passing_command_count"], 1)
            self.assertFalse(row["promotion_allowed"])

    def test_missing_source_refs_blocks_ready_with_typed_reason(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ippe_missing_source_") as tmp:
            ws = Path(tmp)
            candidate = "imo-low-proof-verification-01"
            manifest = self.write_strict_manifest(ws, candidate)
            self.write_inputs(ws, candidate=candidate, source_refs=None, manifest_path=manifest)

            payload = self.run_executor(ws)
            self.assertEqual(payload["summary"]["closure_candidate_count"], 0)
            row = payload["rows"][0]
            self.assertFalse(row["proof_ready"])
            self.assertFalse(row["executable"])
            self.assertIn("missing_current_workspace_source_refs", row["non_executable_reasons"])
            self.assertIn("missing_current_workspace_source_refs", row["terminal_blockers"])

    def test_stale_workspace_source_refs_block_ready_with_typed_reason(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ippe_stale_source_") as tmp:
            ws = Path(tmp)
            candidate = "imo-low-proof-verification-01"
            manifest = self.write_strict_manifest(ws, candidate)
            stale_ref = "workspace:src/Missing.sol:1"
            self.write_inputs(ws, candidate=candidate, source_refs=[stale_ref], manifest_path=manifest)

            payload = self.run_executor(ws)
            self.assertEqual(payload["summary"]["closure_candidate_count"], 0)
            row = payload["rows"][0]
            self.assertFalse(row["proof_ready"])
            self.assertIn("stale_workspace_source_ref", row["non_executable_reasons"])
            self.assertIn("stale_workspace_source_ref", row["terminal_blockers"])
            self.assertEqual(row["proof_completeness"]["stale_workspace_source_refs"], [stale_ref])

    def test_missing_proof_evidence_blocks_ready_with_typed_reason(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ippe_missing_proof_") as tmp:
            ws = Path(tmp)
            source_ref = self.write_source_ref(ws)
            self.write_inputs(ws, source_refs=[source_ref], manifest_path=None)

            payload = self.run_executor(ws)
            self.assertEqual(payload["summary"]["closure_candidate_count"], 0)
            row = payload["rows"][0]
            self.assertEqual(row["decision"], "source_citation_resolved_execution_unproved")
            self.assertFalse(row["proof_ready"])
            self.assertFalse(row["executable"])
            self.assertIn("missing_concrete_proof_evidence", row["non_executable_reasons"])
            self.assertIn("missing_concrete_proof_evidence", row["terminal_blockers"])
            self.assertIn("missing_proved_poc_execution_manifest", row["terminal_blockers"])

    def test_blocker_and_advisory_markers_prevent_ready_and_propagate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ippe_blocker_") as tmp:
            ws = Path(tmp)
            candidate = "imo-low-proof-verification-01"
            source_ref = self.write_source_ref(ws)
            manifest = self.write_strict_manifest(ws, candidate)
            self.write_inputs(
                ws,
                candidate=candidate,
                source_refs=[source_ref],
                manifest_path=manifest,
                backfill_extra={"terminal_blockers": ["operator_blocked"], "advisory_only": True},
            )

            payload = self.run_executor(ws)
            self.assertEqual(payload["summary"]["closure_candidate_count"], 0)
            row = payload["rows"][0]
            self.assertEqual(row["decision"], "project_evidence_blocked_by_markers")
            self.assertFalse(row["proof_ready"])
            self.assertFalse(row["executable"])
            self.assertIn("blocker_or_advisory_marker_present", row["non_executable_reasons"])
            self.assertIn("blocker_or_advisory_marker_present", row["terminal_blockers"])
            self.assertIn("operator_blocked", row["terminal_blockers"])
            self.assertIn("advisory_only_requirement", row["terminal_blockers"])

    def test_materialized_proof_path_reduces_missing_path_without_promoting(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ippe_path_") as tmp:
            ws = Path(tmp)
            candidate = "imo-critical-bridge-finalization-01"
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            proof = aud / "live_proof" / f"{candidate}.json"
            proof.parent.mkdir(parents=True)
            proof.write_text(json.dumps({"status": "not_collected"}) + "\n", encoding="utf-8")
            self.write_inputs(
                ws,
                candidate=candidate,
                source_refs=None,
                manifest_path=None,
                listed_impact_proven=False,
                backfill_extra={
                    "tier": "Critical",
                    "route_family": "bridge_finalization",
                    "terminal_blockers": ["missing_project_specific_proof_path"],
                },
                execution_extra={
                    "tier": "Critical",
                    "route_family": "bridge_finalization",
                    "terminal_blockers": ["missing_execution_or_source_proof"],
                    "local_artifacts": {
                        "artifact_refs": [
                            {
                                "artifact": "paired_live_or_fork_proof",
                                "exists": True,
                                "path": str(proof),
                                "required": True,
                            }
                        ]
                    },
                },
            )

            payload = self.run_executor(ws)
            self.assertEqual(payload["summary"]["proof_path_materialized_count"], 1)
            row = payload["rows"][0]
            self.assertEqual(row["decision"], "proof_path_materialized_requires_source_and_execution")
            self.assertNotIn("missing_project_specific_proof_path", row["terminal_blockers"])
            self.assertNotIn("missing_execution_or_source_proof", row["terminal_blockers"])
            self.assertIn("proof_path_materialized_but_not_executed", row["terminal_blockers"])
            self.assertIn("source_review_required_for_materialized_path", row["terminal_blockers"])
            self.assertFalse(row["proof_ready"])
            self.assertFalse(row["promotion_allowed"])

    def test_loose_execution_manifest_keeps_proved_execution_unproved(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ippe_loose_") as tmp:
            ws = Path(tmp)
            candidate = "imo-low-proof-verification-01"
            source_ref = self.write_source_ref(ws)
            manifest = ws / "poc_execution" / candidate / "execution_manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(
                json.dumps(
                    {
                        "final_result": "proved",
                        "impact_assertion": "exploit_impact",
                        "evidence_class": "executed_with_manifest",
                        "commands_attempted": [],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            self.write_inputs(ws, candidate=candidate, source_refs=[source_ref], manifest_path=manifest)

            payload = self.run_executor(ws)
            self.assertEqual(payload["summary"]["closure_candidate_count"], 0)
            row = payload["rows"][0]
            self.assertEqual(row["decision"], "source_citation_resolved_execution_unproved")
            self.assertFalse(row["execution_manifest"]["proved_impact"])
            self.assertIn("missing_proved_poc_execution_manifest", row["terminal_blockers"])
            self.assertIn("execution_manifest_commands_attempted", row["terminal_blockers"])


if __name__ == "__main__":
    unittest.main()
