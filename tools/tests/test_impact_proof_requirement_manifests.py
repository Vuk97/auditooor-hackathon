from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "impact-proof-requirement-manifests.py"


class ImpactProofRequirementManifestTests(unittest.TestCase):
    def run_tool(self, ws: Path) -> dict:
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--workspace",
                str(ws),
                "--min-items",
                "1",
                "--max-items",
                "10",
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return json.loads((ws / ".auditooor" / "impact_proof_requirement_manifests.json").read_text(encoding="utf-8"))

    def write_source_ref(self, ws: Path) -> str:
        source_path = ws / "src" / "Contract.sol"
        source_path.parent.mkdir(parents=True)
        source_path.write_text("contract Contract {}\n", encoding="utf-8")
        return f"{source_path}:1"

    def write_strict_execution_manifest(self, ws: Path, candidate: str) -> Path:
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

    def write_impact_contract(self, aud: Path, candidate: str, **extra: object) -> None:
        contract = {
            "candidate_id": candidate,
            "impact_contract_id": f"impact-contract-{candidate}",
            "route_family": "proof_verification",
            "tier": "Low",
            "asset_category": "Blockchain/DLT",
            "selected_impact": "Low route requires local proof",
            "exact_impact_row": True,
            "listed_impact_proven": True,
        }
        contract.update(extra)
        (aud / "impact_contracts.json").write_text(json.dumps({"contracts": [contract]}) + "\n", encoding="utf-8")

    def test_ready_requirement_requires_current_source_refs_and_proof_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ipr_ready_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            candidate = "imo-low-proof-verification-01"
            source_ref = self.write_source_ref(ws)
            self.write_strict_execution_manifest(ws, candidate)
            self.write_impact_contract(aud, candidate, source_refs=[source_ref])

            payload = self.run_tool(ws)
            row = payload["rows"][0]
            self.assertEqual(row["requirement_status"], "ready_requires_scope_oos_review")
            self.assertTrue(row["proof_ready"])
            self.assertEqual(row["non_ready_reasons"], [])
            self.assertEqual(row["terminal_blockers"], [])
            self.assertEqual(row["proof_readiness"]["current_workspace_source_refs"], [source_ref])
            self.assertTrue(row["proof_readiness"]["has_concrete_proof_command"])

    def test_ready_requirement_missing_source_refs_stays_non_ready(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ipr_missing_source_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            candidate = "imo-low-proof-verification-01"
            self.write_strict_execution_manifest(ws, candidate)
            self.write_impact_contract(aud, candidate)

            payload = self.run_tool(ws)
            row = payload["rows"][0]
            self.assertEqual(row["requirement_status"], "non_ready_requirement_recorded")
            self.assertFalse(row["proof_ready"])
            self.assertIn("missing_current_workspace_source_refs", row["non_ready_reasons"])
            self.assertIn("missing_current_workspace_source_refs", row["terminal_blockers"])

    def test_ready_requirement_stale_workspace_refs_stays_non_ready(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ipr_stale_source_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            candidate = "imo-low-proof-verification-01"
            self.write_strict_execution_manifest(ws, candidate)
            self.write_impact_contract(aud, candidate, source_refs=[f"{ws / 'src' / 'Missing.sol'}:1"])

            payload = self.run_tool(ws)
            row = payload["rows"][0]
            self.assertEqual(row["requirement_status"], "non_ready_requirement_recorded")
            self.assertFalse(row["proof_ready"])
            self.assertIn("stale_workspace_source_ref", row["non_ready_reasons"])
            self.assertIn("stale_workspace_source_ref", row["terminal_blockers"])
            self.assertEqual(row["proof_readiness"]["stale_workspace_source_refs"], [f"{ws / 'src' / 'Missing.sol'}:1"])

    def test_ready_requirement_missing_proof_evidence_stays_non_ready(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ipr_missing_proof_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            candidate = "imo-low-proof-verification-01"
            source_ref = self.write_source_ref(ws)
            self.write_impact_contract(aud, candidate, source_refs=[source_ref])

            payload = self.run_tool(ws)
            row = payload["rows"][0]
            self.assertEqual(row["requirement_status"], "non_ready_requirement_recorded")
            self.assertFalse(row["proof_ready"])
            self.assertIn("missing_concrete_proof_evidence", row["non_ready_reasons"])
            self.assertIn("missing_concrete_proof_evidence", row["terminal_blockers"])

    def test_ready_requirement_blockers_and_advisory_markers_propagate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ipr_blocker_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            candidate = "imo-low-proof-verification-01"
            source_ref = self.write_source_ref(ws)
            self.write_strict_execution_manifest(ws, candidate)
            self.write_impact_contract(
                aud,
                candidate,
                source_refs=[source_ref],
                terminal_blockers=["operator_blocked"],
                advisory_only=True,
            )

            payload = self.run_tool(ws)
            row = payload["rows"][0]
            self.assertEqual(row["requirement_status"], "non_ready_requirement_recorded")
            self.assertFalse(row["proof_ready"])
            self.assertIn("blocker_or_advisory_marker_present", row["non_ready_reasons"])
            self.assertIn("operator_blocked", row["terminal_blockers"])
            self.assertIn("advisory_only_requirement", row["terminal_blockers"])

    def test_emits_per_contract_requirements_and_terminal_blockers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ipr_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            contracts = []
            for idx in range(1, 4):
                candidate = f"imo-high-access-control-{idx:02d}"
                contracts.append(
                    {
                        "candidate_id": candidate,
                        "impact_contract_id": f"impact-contract-{candidate}",
                        "route_family": "access_control",
                        "tier": "High",
                        "asset_category": "Smart Contract",
                        "selected_impact": "High benchmark route requires local proof",
                        "exact_impact_row": True,
                        "listed_impact_proven": False,
                    }
                )
            (aud / "impact_contracts.json").write_text(json.dumps({"contracts": contracts}) + "\n", encoding="utf-8")
            (aud / "impact_miss_harness_blocker_queue.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "benchmark_id": "imo-high-access-control-01",
                                "required_artifacts": [
                                    {"artifact": "impact_contract", "path": str(aud / "impact_contracts.json"), "exists": True, "required": True},
                                    {"artifact": "source_proof", "path": str(ws / "source_proofs" / "imo-high-access-control-01-source-proof" / "source_proof.json"), "exists": True, "required": True},
                                ],
                            }
                        ]
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (aud / "source_proof_impact_bridge.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "candidate_id": "imo-high-access-control-01",
                                "status": "attached_exact_contract_unproved",
                                "terminal_blockers": ["listed_impact_not_proven"],
                            }
                        ]
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            proof_dir = ws / "source_proofs" / "imo-high-access-control-01-source-proof"
            proof_dir.mkdir(parents=True)
            (proof_dir / "source_proof.json").write_text(
                json.dumps(
                    {
                        "candidate_id": "imo-high-access-control-01-source-proof",
                        "final_verdict": "blocked_missing_project_source_citation",
                        "valid_source_citation_count": 0,
                        "impact_contract_linked": True,
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
                        "commands_attempted": [{"command": "false"}],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--min-items",
                    "1",
                    "--max-items",
                    "10",
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads((aud / "impact_proof_requirement_manifests.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.pr560.impact_proof_requirement_manifests.v1")
            self.assertEqual(payload["summary"]["requirement_count"], 3)
            self.assertFalse(payload["promotion_allowed"])
            by_candidate = {row["candidate_id"]: row for row in payload["rows"]}
            row = by_candidate["imo-high-access-control-01"]
            self.assertEqual(row["requirement_status"], "terminal_execution_blocker_recorded")
            self.assertIn("execution_manifest_blocked_path", row["terminal_blockers"])
            self.assertIn("impact_assertion_not_demonstrated", row["terminal_blockers"])
            self.assertIn("source_proof_blocked_missing_project_source_citation", row["terminal_blockers"])
            self.assertTrue(Path(row["requirement_manifest_path"]).is_file())
            missing = by_candidate["imo-high-access-control-02"]
            self.assertEqual(missing["requirement_status"], "requires_project_specific_impact_proof")
            self.assertIn("missing_execution_or_source_proof", missing["terminal_blockers"])

    def test_item_target_miss_is_hard_blocker(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ipr_empty_") as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir()
            (ws / ".auditooor" / "impact_contracts.json").write_text(json.dumps({"contracts": []}) + "\n", encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--min-items",
                    "300",
                    "--max-items",
                    "500",
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)

    def test_claimed_proved_manifest_without_strict_execution_evidence_is_blocked(self) -> None:
        variants = [
            (
                "missing-evidence-class",
                {
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "commands_attempted": [{"command": "forge test", "exit_code": 0}],
                },
                ["execution_manifest_evidence_class_executed_with_manifest", "execution_manifest_commands_attempted_pass_exit_0"],
            ),
            (
                "failed-command",
                {
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": [{"command": "forge test", "status": "fail", "exit_code": 1}],
                },
                ["execution_manifest_commands_attempted_pass_exit_0"],
            ),
            (
                "unstructured-command",
                {
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": ["forge test"],
                },
                ["execution_manifest_commands_attempted_pass_exit_0"],
            ),
            (
                "empty-command",
                {
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": [{"command": "   ", "status": "pass", "exit_code": 0}],
                },
                ["execution_manifest_commands_attempted_pass_exit_0"],
            ),
            (
                "bool-exit-code",
                {
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": [{"command": "forge test", "status": "pass", "exit_code": False}],
                },
                ["execution_manifest_commands_attempted_pass_exit_0"],
            ),
        ]
        for label, manifest, expected_blockers in variants:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory(prefix=f"ipr_{label}_") as tmp:
                    ws = Path(tmp)
                    aud = ws / ".auditooor"
                    aud.mkdir(parents=True)
                    candidate = "imo-high-access-control-01"
                    (aud / "impact_contracts.json").write_text(
                        json.dumps(
                            {
                                "contracts": [
                                    {
                                        "candidate_id": candidate,
                                        "impact_contract_id": f"impact-contract-{candidate}",
                                        "route_family": "access_control",
                                        "tier": "High",
                                        "asset_category": "Smart Contract",
                                        "selected_impact": "High benchmark route requires local proof",
                                        "exact_impact_row": True,
                                        "listed_impact_proven": False,
                                    }
                                ]
                            }
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                    exec_dir = ws / "poc_execution" / candidate
                    exec_dir.mkdir(parents=True)
                    (exec_dir / "execution_manifest.json").write_text(
                        json.dumps(manifest) + "\n",
                        encoding="utf-8",
                    )

                    proc = subprocess.run(
                        [sys.executable, str(TOOL), "--workspace", str(ws), "--min-items", "1", "--max-items", "10"],
                        cwd=ROOT,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                    payload = json.loads((aud / "impact_proof_requirement_manifests.json").read_text(encoding="utf-8"))
                    row = payload["rows"][0]
                    self.assertEqual(row["requirement_status"], "terminal_execution_blocker_recorded")
                    for blocker in expected_blockers:
                        self.assertIn(blocker, row["terminal_blockers"])
                    self.assertEqual(row["execution_manifest"]["passing_command_count"], 0)

    def test_strict_proved_manifest_requires_human_listed_impact_attestation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ipr_strict_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            candidate = "imo-high-access-control-01"
            (aud / "impact_contracts.json").write_text(
                json.dumps(
                    {
                        "contracts": [
                            {
                                "candidate_id": candidate,
                                "impact_contract_id": f"impact-contract-{candidate}",
                                "route_family": "access_control",
                                "tier": "High",
                                "asset_category": "Smart Contract",
                                "selected_impact": "High benchmark route requires local proof",
                                "exact_impact_row": True,
                                "listed_impact_proven": False,
                            }
                        ]
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            exec_dir = ws / "poc_execution" / candidate
            exec_dir.mkdir(parents=True)
            (exec_dir / "execution_manifest.json").write_text(
                json.dumps(
                    {
                        "final_result": "proved",
                        "impact_assertion": "exploit_impact",
                        "evidence_class": "executed_with_manifest",
                        "commands_attempted": [{"command": "forge test", "status": "pass", "exit_code": "0"}],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            proc = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws), "--min-items", "1", "--max-items", "10"],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads((aud / "impact_proof_requirement_manifests.json").read_text(encoding="utf-8"))
            row = payload["rows"][0]
            self.assertEqual(row["requirement_status"], "terminal_requires_human_listed_impact_attestation")
            self.assertEqual(row["execution_manifest"]["passing_command_count"], 1)
            self.assertIn("listed_impact_not_proven", row["terminal_blockers"])


if __name__ == "__main__":
    unittest.main()
