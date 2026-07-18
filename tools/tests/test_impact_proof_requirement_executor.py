from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "impact-proof-requirement-executor.py"


class ImpactProofRequirementExecutorTests(unittest.TestCase):
    def run_executor(self, ws: Path) -> dict:
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--workspace", str(ws)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return json.loads((ws / ".auditooor" / "impact_proof_requirement_execution.json").read_text(encoding="utf-8"))

    def write_strict_manifest(self, ws: Path, candidate: str) -> Path:
        exec_dir = ws / "poc_execution" / candidate
        exec_dir.mkdir(parents=True)
        manifest_path = exec_dir / "execution_manifest.json"
        manifest_path.write_text(
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
        return manifest_path

    def write_source_ref(self, ws: Path) -> str:
        source_path = ws / "src" / "Contract.sol"
        source_path.parent.mkdir(parents=True)
        source_path.write_text("contract Contract {}\n", encoding="utf-8")
        return f"{source_path}:1"

    def test_resolves_execution_source_and_missing_proof_blockers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ipre_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            rows = [
                {
                    "candidate_id": "imo-high-access-control-01",
                    "requirement_id": "IPR-001",
                    "tier": "High",
                    "route_family": "access_control",
                    "asset_category": "Smart Contract",
                    "exact_impact_row": True,
                    "listed_impact_proven": False,
                    "terminal_blockers": ["listed_impact_not_proven"],
                    "source_proofs": [
                        {
                            "path": str(ws / "source_proofs" / "imo-high-access-control-01-source-proof" / "source_proof.json"),
                            "valid_source_citation_count": 0,
                        }
                    ],
                    "execution_manifest": {
                        "path": str(ws / "poc_execution" / "imo-high-access-control-01" / "execution_manifest.json")
                    },
                },
                {
                    "candidate_id": "imo-medium-asset-custody-02",
                    "requirement_id": "IPR-002",
                    "tier": "Medium",
                    "route_family": "asset_custody",
                    "asset_category": "Smart Contract",
                    "exact_impact_row": True,
                    "listed_impact_proven": False,
                    "terminal_blockers": ["missing_execution_or_source_proof"],
                    "source_proofs": [],
                    "execution_manifest": {},
                },
            ]
            (aud / "impact_proof_requirement_manifests.json").write_text(
                json.dumps({"rows": rows}) + "\n",
                encoding="utf-8",
            )
            (aud / "impact_miss_harness_blocker_queue.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "benchmark_id": "imo-high-access-control-01",
                                "harness_family": "source_bound_forge_harness",
                                "runnable_next_commands": ["make poc-execution-record WS=<workspace>"],
                            }
                        ]
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (aud / "impact_miss_harness_blocker_execution.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "benchmark_id": "imo-high-access-control-01",
                                "artifact_paths": [str(ws / "poc-tests" / "imo-high-access-control-01" / "run_harness.sh")],
                            }
                        ]
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            exec_dir = ws / "poc_execution" / "imo-high-access-control-01"
            exec_dir.mkdir(parents=True)
            (exec_dir / "execution_manifest.json").write_text(
                json.dumps(
                    {
                        "final_result": "blocked_path",
                        "impact_assertion": "not_demonstrated",
                        "commands_attempted": [{"command": "forge test", "status": "fail", "exit_code": 1}],
                        "evidence_class": "executed_with_manifest",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            proc = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws)],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads((aud / "impact_proof_requirement_execution.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.pr560.impact_proof_requirement_execution.v1")
            self.assertEqual(payload["summary"]["requirement_count"], 2)
            self.assertEqual(payload["summary"]["closure_candidate_count"], 0)
            by_candidate = {row["candidate_id"]: row for row in payload["rows"]}
            first = by_candidate["imo-high-access-control-01"]
            self.assertEqual(first["decision"], "terminal_blocker_execution_manifest_unproved")
            self.assertIn("execution_manifest_blocked_path", first["terminal_blockers"])
            self.assertIn("impact_assertion_not_demonstrated", first["terminal_blockers"])
            self.assertIn("source_proof_missing_project_source_citation", first["terminal_blockers"])
            self.assertTrue(Path(first["resolution_manifest_path"]).is_file())
            second = by_candidate["imo-medium-asset-custody-02"]
            self.assertEqual(second["decision"], "terminal_blocker_missing_project_specific_proof")
            self.assertIn("missing_poc_execution_manifest", second["terminal_blockers"])
            self.assertIn("make poc-execution-record", second["next_local_commands"][1])

    def test_closure_candidate_still_requires_scope_review(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ipre_candidate_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            candidate = "imo-low-proof-verification-01"
            manifest_path = self.write_strict_manifest(ws, candidate)
            source_ref = self.write_source_ref(ws)
            (aud / "impact_proof_requirement_manifests.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "candidate_id": candidate,
                                "requirement_id": "IPR-001",
                                "tier": "Low",
                                "route_family": "proof_verification",
                                "asset_category": "Blockchain/DLT",
                                "exact_impact_row": True,
                                "listed_impact_proven": True,
                                "terminal_blockers": [],
                                "source_refs": [source_ref],
                                "execution_manifest": {"path": str(manifest_path)},
                            }
                        ]
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            payload = self.run_executor(ws)
            self.assertEqual(payload["summary"]["closure_candidate_count"], 1)
            row = payload["rows"][0]
            self.assertEqual(row["decision"], "closure_candidate_requires_scope_oos_review")
            self.assertTrue(row["executable"])
            self.assertTrue(row["proof_complete"])
            self.assertEqual(row["non_executable_reasons"], [])
            self.assertFalse(row["promotion_allowed"])
            self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")

    def test_missing_source_refs_blocks_executable_requirement(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ipre_missing_source_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            candidate = "imo-low-proof-verification-01"
            manifest_path = self.write_strict_manifest(ws, candidate)
            (aud / "impact_proof_requirement_manifests.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "candidate_id": candidate,
                                "requirement_id": "IPR-001",
                                "tier": "Low",
                                "route_family": "proof_verification",
                                "asset_category": "Blockchain/DLT",
                                "exact_impact_row": True,
                                "listed_impact_proven": True,
                                "terminal_blockers": [],
                                "execution_manifest": {"path": str(manifest_path)},
                            }
                        ]
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            payload = self.run_executor(ws)
            row = payload["rows"][0]
            self.assertEqual(payload["summary"]["closure_candidate_count"], 0)
            self.assertFalse(row["executable"])
            self.assertFalse(row["proof_complete"])
            self.assertIn("missing_current_workspace_source_refs", row["non_executable_reasons"])
            self.assertIn("missing_current_workspace_source_refs", row["terminal_blockers"])

    def test_stale_workspace_source_refs_block_executable_requirement(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ipre_stale_source_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            candidate = "imo-low-proof-verification-01"
            manifest_path = self.write_strict_manifest(ws, candidate)
            stale_ref = ws / "src" / "Missing.sol"
            (aud / "impact_proof_requirement_manifests.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "candidate_id": candidate,
                                "requirement_id": "IPR-001",
                                "tier": "Low",
                                "route_family": "proof_verification",
                                "asset_category": "Blockchain/DLT",
                                "exact_impact_row": True,
                                "listed_impact_proven": True,
                                "terminal_blockers": [],
                                "source_refs": [f"{stale_ref}:1"],
                                "execution_manifest": {"path": str(manifest_path)},
                            }
                        ]
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            payload = self.run_executor(ws)
            row = payload["rows"][0]
            self.assertEqual(payload["summary"]["closure_candidate_count"], 0)
            self.assertFalse(row["executable"])
            self.assertFalse(row["proof_complete"])
            self.assertIn("stale_workspace_source_ref", row["non_executable_reasons"])
            self.assertIn("stale_workspace_source_ref", row["terminal_blockers"])

    def test_missing_proof_evidence_blocks_executable_requirement(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ipre_missing_proof_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            candidate = "imo-low-proof-verification-01"
            source_ref = self.write_source_ref(ws)
            exec_dir = ws / "poc_execution" / candidate
            exec_dir.mkdir(parents=True)
            manifest_path = exec_dir / "execution_manifest.json"
            manifest_path.write_text(
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
            (aud / "impact_proof_requirement_manifests.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "candidate_id": candidate,
                                "requirement_id": "IPR-001",
                                "tier": "Low",
                                "route_family": "proof_verification",
                                "asset_category": "Blockchain/DLT",
                                "exact_impact_row": True,
                                "listed_impact_proven": True,
                                "terminal_blockers": [],
                                "source_refs": [source_ref],
                                "execution_manifest": {"path": str(manifest_path)},
                            }
                        ]
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            payload = self.run_executor(ws)
            row = payload["rows"][0]
            self.assertEqual(payload["summary"]["closure_candidate_count"], 0)
            self.assertFalse(row["executable"])
            self.assertFalse(row["proof_complete"])
            self.assertIn("missing_concrete_proof_evidence", row["non_executable_reasons"])
            self.assertIn("execution_manifest_missing_commands_attempted", row["terminal_blockers"])

    def test_blocker_and_advisory_markers_propagate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ipre_blocker_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            candidate = "imo-low-proof-verification-01"
            manifest_path = self.write_strict_manifest(ws, candidate)
            source_ref = self.write_source_ref(ws)
            (aud / "impact_proof_requirement_manifests.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "candidate_id": candidate,
                                "requirement_id": "IPR-001",
                                "tier": "Low",
                                "route_family": "proof_verification",
                                "asset_category": "Blockchain/DLT",
                                "exact_impact_row": True,
                                "listed_impact_proven": True,
                                "terminal_blockers": ["operator_blocked"],
                                "advisory_only": True,
                                "source_refs": [source_ref],
                                "execution_manifest": {"path": str(manifest_path)},
                            }
                        ]
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            payload = self.run_executor(ws)
            row = payload["rows"][0]
            self.assertEqual(payload["summary"]["closure_candidate_count"], 0)
            self.assertFalse(row["executable"])
            self.assertFalse(row["proof_complete"])
            self.assertIn("blocker_or_advisory_marker_present", row["non_executable_reasons"])
            self.assertIn("operator_blocked", row["terminal_blockers"])
            self.assertIn("advisory_only_requirement", row["terminal_blockers"])

    def test_claimed_proved_manifest_without_strict_execution_evidence_is_blocked(self) -> None:
        variants = [
            (
                "wrong-class",
                {
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "evidence_class": "generated_hypothesis",
                    "commands_attempted": [{"command": "forge test", "status": "pass", "exit_code": 0}],
                },
                "execution_manifest_evidence_class_executed_with_manifest",
            ),
            (
                "recorded-without-execution",
                {
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": [
                        {"command": "forge test", "status": "recorded_without_execution", "exit_code": None}
                    ],
                },
                "execution_manifest_commands_attempted_pass_exit_0",
            ),
            (
                "failed",
                {
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": [{"command": "forge test", "status": "fail", "exit_code": 1}],
                },
                "execution_manifest_commands_attempted_pass_exit_0",
            ),
            (
                "unstructured",
                {
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": ["forge test"],
                },
                "execution_manifest_commands_attempted_pass_exit_0",
            ),
            (
                "empty-command",
                {
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": [{"command": "   ", "status": "pass", "exit_code": 0}],
                },
                "execution_manifest_commands_attempted_pass_exit_0",
            ),
            (
                "bool-exit-code",
                {
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": [{"command": "forge test", "status": "pass", "exit_code": False}],
                },
                "execution_manifest_commands_attempted_pass_exit_0",
            ),
        ]
        for label, manifest, blocker in variants:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory(prefix=f"ipre_{label}_") as tmp:
                    ws = Path(tmp)
                    aud = ws / ".auditooor"
                    aud.mkdir(parents=True)
                    candidate = "imo-low-proof-verification-01"
                    exec_dir = ws / "poc_execution" / candidate
                    exec_dir.mkdir(parents=True)
                    manifest_path = exec_dir / "execution_manifest.json"
                    manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
                    (aud / "impact_proof_requirement_manifests.json").write_text(
                        json.dumps(
                            {
                                "rows": [
                                    {
                                        "candidate_id": candidate,
                                        "requirement_id": "IPR-001",
                                        "tier": "Low",
                                        "route_family": "proof_verification",
                                        "asset_category": "Blockchain/DLT",
                                        "exact_impact_row": True,
                                        "listed_impact_proven": True,
                                        "terminal_blockers": [],
                                        "execution_manifest": {"path": str(manifest_path)},
                                    }
                                ]
                            }
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                    proc = subprocess.run(
                        [sys.executable, str(TOOL), "--workspace", str(ws)],
                        cwd=ROOT,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                    payload = json.loads((aud / "impact_proof_requirement_execution.json").read_text(encoding="utf-8"))
                    self.assertEqual(payload["summary"]["closure_candidate_count"], 0)
                    row = payload["rows"][0]
                    self.assertEqual(row["decision"], "terminal_blocker_execution_manifest_unproved")
                    self.assertIn(blocker, row["terminal_blockers"])


if __name__ == "__main__":
    unittest.main()
