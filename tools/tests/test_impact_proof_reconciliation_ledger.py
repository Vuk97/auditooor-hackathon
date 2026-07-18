from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "impact-proof-reconciliation-ledger.py"


class ImpactProofReconciliationLedgerTests(unittest.TestCase):
    def _run_ledger(self, ws: Path) -> dict[str, object]:
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--workspace",
                str(ws),
                "--out-json",
                "custom/ledger.json",
                "--out-md",
                "custom/ledger.md",
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return json.loads((ws / "custom" / "ledger.json").read_text(encoding="utf-8"))

    def test_empty_workspace_writes_workspace_local_not_submit_ready_ledger(self) -> None:
        with tempfile.TemporaryDirectory(prefix="impact_reconcile_") as tmp:
            ws = Path(tmp)
            payload = self._run_ledger(ws)
            self.assertFalse((ROOT / "custom" / "ledger.json").exists())
            self.assertEqual(payload["schema"], "auditooor.pr560.worker_fk.impact_proof_reconciliation_ledger.v1")
            self.assertEqual(payload["summary"]["reconciled_row_count"], 0)
            self.assertEqual(payload["summary"]["conservative_closure_candidate_count"], 0)
            self.assertFalse(payload["promotion_allowed"])
            self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
            self.assertTrue((ws / "custom" / "ledger.md").is_file())

    def _write_reconciled_candidate(
        self,
        ws: Path,
        manifest_payload: dict[str, object] | None,
        *,
        row_extra: dict[str, object] | None = None,
        source_ref: str | None = "src/Verifier.sol:1",
    ) -> None:
        candidate = "imo-high-proof-verification-01"
        aud = ws / ".auditooor"
        aud.mkdir(parents=True)
        if source_ref is not None and source_ref.startswith("src/Verifier.sol"):
            source_path = ws / "src" / "Verifier.sol"
            source_path.parent.mkdir(parents=True)
            source_path.write_text("contract Verifier {}\nfunction verify() {}\n", encoding="utf-8")
        row = {
            "candidate_id": candidate,
            "requirement_id": "IPR-001",
            "route_family": "proof_verification",
            "tier": "High",
            "listed_impact_proven": True,
            "project_source_citation_count": 1,
            "decision": "closure_candidate_requires_scope_oos_review",
            "terminal_blockers": [],
        }
        if source_ref is not None:
            row["source_refs"] = [source_ref]
        if row_extra:
            row.update(row_extra)
        (aud / "impact_proof_requirement_execution.json").write_text(
            json.dumps(
                {
                    "rows": [row]
                }
            )
            + "\n",
            encoding="utf-8",
        )
        if manifest_payload is None:
            return
        manifest = dict(manifest_payload)
        manifest.setdefault("candidate_id", candidate)
        manifest_path = ws / "poc_execution" / candidate / "execution_manifest.json"
        manifest_path.parent.mkdir(parents=True)
        manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")

    def test_strict_execution_manifest_counts_as_proved_for_reconciliation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="impact_reconcile_strict_") as tmp:
            ws = Path(tmp)
            self._write_reconciled_candidate(
                ws,
                {
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": [{"command": "forge test", "status": "pass", "exit_code": "0"}],
                },
            )

            payload = self._run_ledger(ws)

        self.assertEqual(payload["summary"]["conservative_closure_candidate_count"], 1)
        self.assertTrue(payload["promotion_allowed"])
        row = payload["conservative_closure_candidates"][0]
        self.assertTrue(row["proof_ready"])
        self.assertEqual(row["proof_readiness_reasons"], [])
        self.assertEqual(row["current_workspace_source_refs"], ["src/Verifier.sol:1"])
        self.assertTrue(row["has_proved_execution_manifest"])
        self.assertTrue(row["has_concrete_proof_or_harness_evidence"])
        self.assertEqual(row["execution_evidence"][0]["passing_command_count"], 1)
        self.assertEqual(payload["blocker_counts"]["rows_with_proved_execution_manifest"], 1)
        self.assertEqual(payload["blocker_counts"]["proof_ready_rows"], 1)
        self.assertEqual(
            payload["execution_manifest_inventory"]["strict_proved_exploit_impact_manifest_paths"],
            ["poc_execution/imo-high-proof-verification-01/execution_manifest.json"],
        )

    def test_invalid_bound_source_cannot_be_promoted_and_is_recorded_as_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory(prefix="impact_reconcile_invalid_bound_source_") as tmp:
            ws = Path(tmp)
            source_content = "contract Verifier {}\nfunction verify() {}\n"
            self._write_reconciled_candidate(
                ws,
                {
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": [{"command": "forge test", "status": "pass", "exit_code": 0}],
                    "bound_sources": [
                        {
                            "path": "src/Verifier.sol",
                            "sha256": "0" * 64,
                            "size": len(source_content.encode("utf-8")),
                        }
                    ],
                },
            )

            payload = self._run_ledger(ws)

        self.assertEqual(payload["summary"]["conservative_closure_candidate_count"], 0)
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["execution_manifest_inventory"]["strict_proved_exploit_impact_manifest_paths"], [])
        evidence = payload["terminalized_rows"][0]["execution_evidence"][0]
        self.assertFalse(evidence["proof_counted"])
        self.assertFalse(evidence["bound_source_validation"]["valid"])
        self.assertTrue(
            any(error.endswith("hash_mismatch") for error in evidence["bound_source_validation"]["errors"])
        )
        diagnostics = payload["diagnostics"]["bound_source_validation_errors"]
        self.assertTrue(diagnostics)
        self.assertTrue(any(error.endswith("hash_mismatch") for error in diagnostics[0]["errors"]))

    def test_empty_bound_sources_preserves_strict_proof_compatibility(self) -> None:
        with tempfile.TemporaryDirectory(prefix="impact_reconcile_empty_bound_sources_") as tmp:
            ws = Path(tmp)
            self._write_reconciled_candidate(
                ws,
                {
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": [{"command": "forge test", "status": "pass", "exit_code": 0}],
                    "bound_sources": [],
                },
            )

            payload = self._run_ledger(ws)

        self.assertTrue(payload["promotion_allowed"])
        self.assertEqual(payload["summary"]["conservative_closure_candidate_count"], 1)
        self.assertEqual(payload["diagnostics"]["bound_source_validation_errors"], [])

    def test_loose_execution_manifest_does_not_count_as_proved_for_reconciliation(self) -> None:
        loose_manifests = {
            "missing-evidence-class": {
                "final_result": "proved",
                "impact_assertion": "exploit_impact",
                "commands_attempted": [{"command": "forge test", "status": "pass", "exit_code": 0}],
            },
            "legacy-string-command": {
                "final_result": "proved",
                "impact_assertion": "exploit_impact",
                "evidence_class": "executed_with_manifest",
                "commands_attempted": ["forge test --match-test testExploitImpact"],
            },
            "failed-command": {
                "final_result": "proved",
                "impact_assertion": "exploit_impact",
                "evidence_class": "executed_with_manifest",
                "commands_attempted": [{"command": "forge test", "status": "fail", "exit_code": 1}],
            },
            "bool-exit-code": {
                "final_result": "proved",
                "impact_assertion": "exploit_impact",
                "evidence_class": "executed_with_manifest",
                "commands_attempted": [{"command": "forge test", "status": "pass", "exit_code": True}],
            },
            "empty-command-pass-zero": {
                "final_result": "proved",
                "impact_assertion": "exploit_impact",
                "evidence_class": "executed_with_manifest",
                "commands_attempted": [{"command": "", "status": "pass", "exit_code": 0}],
            },
        }
        for label, manifest in loose_manifests.items():
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory(prefix=f"impact_reconcile_loose_{label}_") as tmp:
                    ws = Path(tmp)
                    self._write_reconciled_candidate(ws, manifest)

                    payload = self._run_ledger(ws)

                self.assertEqual(payload["summary"]["conservative_closure_candidate_count"], 0)
                self.assertFalse(payload["promotion_allowed"])
                self.assertEqual(payload["blocker_counts"]["rows_with_proved_execution_manifest"], 0)
                self.assertEqual(payload["blocker_counts"]["missing_proved_execution_rows"], 1)
                row = payload["terminalized_rows"][0]
                self.assertFalse(row["has_proved_execution_manifest"])
                self.assertFalse(row["proof_ready"])
                self.assertIn("missing_proved_execution_manifest", row["proof_readiness_reasons"])
                self.assertEqual(payload["execution_manifest_inventory"]["strict_proved_exploit_impact_manifest_paths"], [])

    def test_summary_only_command_counters_do_not_count_as_proved_for_reconciliation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="impact_reconcile_summary_only_") as tmp:
            ws = Path(tmp)
            candidate = "imo-high-proof-verification-01"
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            source_path = ws / "src" / "Verifier.sol"
            source_path.parent.mkdir(parents=True)
            source_path.write_text("contract Verifier {}\n", encoding="utf-8")
            (aud / "impact_proof_requirement_execution.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "candidate_id": candidate,
                                "requirement_id": "IPR-001",
                                "route_family": "proof_verification",
                                "tier": "High",
                                "listed_impact_proven": True,
                                "project_source_citation_count": 1,
                                "decision": "closure_candidate_requires_scope_oos_review",
                                "terminal_blockers": [],
                                "source_refs": ["src/Verifier.sol:1"],
                                "execution_manifest": {
                                    "path": f"poc_execution/{candidate}/execution_manifest.json",
                                    "final_result": "proved",
                                    "impact_assertion": "exploit_impact",
                                    "evidence_class": "executed_with_manifest",
                                    "commands_attempted_count": 1,
                                    "structured_command_count": 1,
                                    "passing_command_count": 1,
                                },
                            }
                        ]
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = self._run_ledger(ws)

        self.assertEqual(payload["summary"]["conservative_closure_candidate_count"], 0)
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["blocker_counts"]["rows_with_proved_execution_manifest"], 0)
        row = payload["terminalized_rows"][0]
        self.assertFalse(row["has_proved_execution_manifest"])
        self.assertEqual(row["execution_evidence"][0]["commands_attempted_count"], 1)
        self.assertFalse(row["execution_evidence"][0]["proof_counted"])
        self.assertIn("missing_proved_execution_manifest", row["proof_readiness_reasons"])

    def test_source_ref_counts_without_current_refs_are_not_ready(self) -> None:
        with tempfile.TemporaryDirectory(prefix="impact_reconcile_no_refs_") as tmp:
            ws = Path(tmp)
            self._write_reconciled_candidate(
                ws,
                {
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": [{"command": "forge test", "status": "pass", "exit_code": 0}],
                },
                source_ref=None,
            )

            payload = self._run_ledger(ws)

        self.assertEqual(payload["summary"]["conservative_closure_candidate_count"], 0)
        self.assertEqual(payload["summary"]["non_ready_row_count"], 1)
        row = payload["non_ready_rows"][0]
        self.assertIn("missing_current_workspace_source_refs", row["proof_readiness_reasons"])
        self.assertEqual(payload["proof_readiness_reason_counts"]["missing_current_workspace_source_refs"], 1)

    def test_stale_source_ref_is_typed_non_ready_reason(self) -> None:
        with tempfile.TemporaryDirectory(prefix="impact_reconcile_stale_ref_") as tmp:
            ws = Path(tmp)
            self._write_reconciled_candidate(
                ws,
                {
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": [{"command": "forge test", "status": "pass", "exit_code": 0}],
                },
                source_ref="src/Missing.sol:1",
            )

            payload = self._run_ledger(ws)

        row = payload["non_ready_rows"][0]
        self.assertFalse(row["proof_ready"])
        self.assertIn("stale_workspace_source_ref", row["proof_readiness_reasons"])
        self.assertIn("missing_current_workspace_source_refs", row["proof_readiness_reasons"])
        self.assertEqual(row["stale_workspace_source_refs"], ["src/Missing.sol:1"])

    def test_missing_concrete_proof_evidence_is_typed_non_ready_reason(self) -> None:
        with tempfile.TemporaryDirectory(prefix="impact_reconcile_no_proof_") as tmp:
            ws = Path(tmp)
            self._write_reconciled_candidate(ws, None)

            payload = self._run_ledger(ws)

        row = payload["non_ready_rows"][0]
        self.assertFalse(row["proof_ready"])
        self.assertIn("missing_concrete_proof_evidence", row["proof_readiness_reasons"])
        self.assertIn("missing_proved_execution_manifest", row["proof_readiness_reasons"])
        self.assertFalse(row["has_concrete_proof_or_harness_evidence"])

    def test_blocker_and_advisory_markers_are_typed_non_ready_reasons(self) -> None:
        manifest = {
            "final_result": "proved",
            "impact_assertion": "exploit_impact",
            "evidence_class": "executed_with_manifest",
            "commands_attempted": [{"command": "forge test", "status": "pass", "exit_code": 0}],
        }
        cases = {
            "blocker": ({"terminal_blockers": ["scope_blocked"]}, "blocker_present"),
            "advisory": ({"advisory_only": True}, "advisory_only"),
        }
        for label, (row_extra, reason) in cases.items():
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory(prefix=f"impact_reconcile_{label}_") as tmp:
                    ws = Path(tmp)
                    self._write_reconciled_candidate(ws, manifest, row_extra=row_extra)

                    payload = self._run_ledger(ws)

                self.assertEqual(payload["summary"]["conservative_closure_candidate_count"], 0)
                row = payload["non_ready_rows"][0]
                self.assertIn(reason, row["proof_readiness_reasons"])
                self.assertEqual(payload["proof_readiness_reason_counts"][reason], 1)


if __name__ == "__main__":
    unittest.main()
