from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "field-validation-report.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("field_validation_report_test", TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["field_validation_report_test"] = mod
    spec.loader.exec_module(mod)
    return mod


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


class FieldValidationReportTests(unittest.TestCase):
    def test_empty_workspace_emits_unknowns_without_positive_claims(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "sample-ws"
            ws.mkdir()
            outcomes = Path(td) / "missing-outcomes.jsonl"
            report = mod.build_report(ws, outcomes_path=outcomes)

        self.assertEqual(report["schema"], "auditooor.field_validation_report.v1")
        self.assertEqual(report["readiness"]["status"], "unknown_no_evaluable_signals")
        self.assertEqual(report["readiness"]["ready_sections"], 0)
        self.assertEqual(len(report["explicit_unknowns"]), 3)
        rendered = json.dumps(report, sort_keys=True).lower()
        self.assertNotIn("paid", rendered)
        self.assertNotIn("accepted", rendered)
        self.assertTrue(report["claims_boundary"]["no_reward_assertion"])
        self.assertTrue(report["claims_boundary"]["no_positive_terminal_assertion"])
        groups = report["signal_groups"]
        self.assertEqual(
            groups["conversion_proof_execution"]["missing_artifacts"][0]["expected_paths"],
            [".auditooor/exploit_queue.json"],
        )
        self.assertIn(
            "make exploit-queue",
            "\n".join(groups["conversion_proof_execution"]["next_commands"]),
        )
        self.assertIn(
            "poc_execution/<candidate-id>/execution_manifest.json",
            json.dumps(report["readiness"]["field_loop_next_steps"]),
        )
        self.assertIn("submissions/SUBMISSIONS.md", json.dumps(groups["triage_survival_outcome"]["missing_artifacts"]))

    def test_full_signal_workspace_is_ready_for_evaluation(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "alpha"
            ws.mkdir()
            campaign = "camp-a"

            _write_json(
                ws / ".auditooor" / "provider_fanout" / campaign / "local_verification_queue.json",
                {
                    "local_grep_tasks": [
                        {
                            "route": "local_source_review",
                            "minimum_followup_check": "rg confirms guard path",
                        }
                    ],
                    "killed_rows": [
                        {
                            "route": "killed_by_minimax",
                            "terminal_state_options": ["kill_confirmed"],
                        }
                    ],
                },
            )
            _write_json(
                ws / ".auditooor" / "provider_fanout" / campaign / "runs" / "001" / "fanout_closeout.json",
                {
                    "rows": [
                        {
                            "status": "verified_no_action",
                            "local_verification_required": True,
                        }
                    ]
                },
            )
            _write_json(
                ws / "poc_execution" / "candidate-1" / "execution_manifest.json",
                {
                    "candidate_id": "candidate-1",
                    "evidence_class": "executed_with_manifest",
                    "final_result": "disproved",
                    "commands_attempted": [{"status": "pass", "command": "true"}],
                },
            )
            _write_json(
                ws / ".auditooor" / "exploit_queue.json",
                {"queue": [{"lead_id": "lead-1", "quality_gate_status": "blocked"}]},
            )
            outcomes = root / "outcomes.jsonl"
            _write_jsonl(
                outcomes,
                [
                    {
                        "workspace": "alpha",
                        "outcome": "rejected",
                        "finding_id": "A-1",
                    },
                    {
                        "workspace": "other",
                        "outcome": "rejected",
                        "finding_id": "B-1",
                    },
                ],
            )

            report = mod.build_report(ws, campaign_id=campaign, outcomes_path=outcomes)

        self.assertEqual(report["readiness"]["status"], "field_validation_ready_for_evaluation")
        self.assertEqual(report["readiness"]["ready_sections"], 3)
        groups = report["signal_groups"]
        self.assertEqual(groups["pre_filing_accuracy"]["status"], "ready_for_evaluation")
        self.assertEqual(groups["conversion_proof_execution"]["counts"]["executed_manifest_count"], 1)
        self.assertEqual(groups["triage_survival_outcome"]["counts"]["ledger_rows_matched"], 1)
        self.assertEqual(
            groups["triage_survival_outcome"]["counts"]["outcome_bucket_counts"],
            {"non_positive_terminal": 1},
        )
        self.assertEqual(report["explicit_unknowns"], [])
        rendered = json.dumps(report, sort_keys=True).lower()
        self.assertNotIn("paid", rendered)
        self.assertNotIn("accepted", rendered)

    def test_blocked_conversion_rows_surface_actionable_gaps_without_counting_as_proof(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "nuva"
            ws.mkdir()
            _write_json(
                ws / ".auditooor" / "high_impact_execution_bridge.json",
                {
                    "rows": [
                        {
                            "row_id": "EQ-001-SC",
                            "bridge_status": "blocked_missing_impact_contract",
                            "poc_execution_record_status": "blocked",
                            "poc_execution_record_blocked_reason": "missing_exact_impact_contract",
                            "impact_contract_command": f"make impact-contract-check WS={ws} ROW=EQ-001-SC",
                            "impact_contract_skeleton_command": (
                                f"make high-impact-impact-contract-skeletons WS={ws} ROW=EQ-001-SC"
                            ),
                            "impact_contract_skeleton_path": str(
                                ws / ".auditooor" / "high_impact_impact_contract_skeletons" / "skeletons" / "eq-001-sc.json"
                            ),
                        }
                    ]
                },
            )
            _write_json(
                ws / ".auditooor" / "harness_execution_queue_from_exploit_queue.json",
                {
                    "rows": [
                        {
                            "row_id": "EQ-001",
                            "status": "blocked_missing_inputs",
                            "blockers": ["missing_command", "missing_gating_test"],
                            "missing_inputs": ["harness_command", "gating_test", "impact_contract_id"],
                            "expected_next_action": "add one exact local harness command",
                        }
                    ]
                },
            )
            _write_json(
                ws / "poc_execution" / "eq-003" / "cosmos_production_harness_exec.json",
                {
                    "schema": "auditooor.cosmos_production_harness_exec.v1",
                    "candidate_id": "EQ-003",
                    "execution": {"attempted": False, "status": "blocked_preflight"},
                    "preflight": {"execution_allowed": False},
                    "runtime_proof_claimed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                },
            )

            report = mod.build_report(ws, outcomes_path=Path(td) / "missing.jsonl")

        conversion = report["signal_groups"]["conversion_proof_execution"]
        self.assertEqual(conversion["status"], "artifact_present_no_signal")
        self.assertEqual(conversion["counts"]["execution_manifest_count"], 0)
        self.assertEqual(conversion["counts"]["executed_manifest_count"], 0)
        self.assertEqual(conversion["counts"]["actionable_gap_count"], 2)
        self.assertEqual(conversion["counts"]["non_counting_execution_context_count"], 1)
        missing_names = {row["artifact"] for row in conversion["missing_artifacts"]}
        self.assertEqual(missing_names, {"exploit queue", "executed PoC manifest"})
        first_gap = conversion["actionable_gaps"][0]
        self.assertEqual(first_gap["blocker"], "missing_exact_impact_contract")
        self.assertIn("impact-contract-check", "\n".join(first_gap["next_commands"]))
        self.assertFalse(first_gap["counts_as_proof"])
        context = conversion["non_counting_execution_context"][0]
        self.assertEqual(context["status"], "blocked_preflight")
        self.assertFalse(context["counts_as_proof"])

    def test_outcome_gap_points_to_real_submission_then_real_outcome(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "delta"
            ws.mkdir()
            outcomes = root / "outcomes.jsonl"
            _write_jsonl(outcomes, [])
            (ws / "submissions").mkdir()
            (ws / "submissions" / "SUBMISSIONS.md").write_text("# Submissions\n\n", encoding="utf-8")

            report = mod.build_report(ws, outcomes_path=outcomes)

        triage = report["signal_groups"]["triage_survival_outcome"]
        missing = next(row for row in triage["missing_artifacts"] if row["artifact"] == "workspace/campaign outcome row")
        commands = "\n".join(missing["next_commands"])
        self.assertIn("record-submission", commands)
        self.assertIn("URL=<real-platform-url>", commands)
        self.assertIn("ID=<real-platform-id>", commands)
        self.assertIn("STATE=<accepted|paid|duplicate|rejected|duplicate_of_accepted|duplicate_of_rejected|withdrawn>", commands)
        self.assertNotIn("STATE=<submitted|rejected|duplicate|oos|withdrawn>", commands)
        self.assertIn("after a real platform filing", missing["reason"])

    def test_submission_status_text_is_advisory_not_outcome_evidence(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "nuva"
            ws.mkdir()
            outcomes = root / "outcomes.jsonl"
            _write_jsonl(outcomes, [])
            (ws / "submissions").mkdir()
            (ws / "submissions" / "SUBMISSIONS.md").write_text(
                "# Submissions\n\n| ID | Status |\n|---|---|\n| C-1 | SUBMITTED pending triage |\n",
                encoding="utf-8",
            )

            report = mod.build_report(ws, outcomes_path=outcomes)

        triage = report["signal_groups"]["triage_survival_outcome"]
        self.assertEqual(triage["status"], "artifact_present_no_signal")
        self.assertEqual(triage["counts"]["ledger_rows_matched"], 0)
        self.assertEqual(triage["counts"]["submission_text_status_mentions"]["submitted"], 1)
        self.assertEqual(triage["counts"]["submission_text_status_mentions"]["pending"], 1)
        self.assertFalse(triage["counts"]["submission_text_status_mentions_counted_as_outcome_evidence"])
        self.assertIn(
            "outcome artifacts exist but no structured rows matched this workspace/campaign",
            triage["unknowns"],
        )

    def test_pending_filed_without_platform_id_is_pending_artifact_not_outcome_evidence(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "hyperbridge"
            ws.mkdir()
            outcomes = root / "outcomes.jsonl"
            _write_jsonl(outcomes, [])
            _write_jsonl(
                ws / "reference" / "pending_filed_without_platform_id.jsonl",
                [
                    {
                        "schema": "auditooor.pending_filed_without_platform_id.v1",
                        "workspace": "hyperbridge",
                        "local_id": "HB-LOCAL-1",
                        "report_id": "HB-LOCAL-1",
                        "platform": "cantina",
                        "title": "filed row lacks platform id",
                        "status": "artifact_present_pending",
                        "outcome": "pending_without_platform_id",
                        "counts_as_outcome_evidence": False,
                        "counts_as_submission_evidence": False,
                        "requires_platform_id_backfill": True,
                    }
                ],
            )

            report = mod.build_report(ws, outcomes_path=outcomes)

        triage = report["signal_groups"]["triage_survival_outcome"]
        self.assertEqual(triage["status"], "artifact_present_pending")
        self.assertEqual(triage["counts"]["ledger_rows_matched"], 0)
        self.assertEqual(triage["counts"]["pending_filed_without_platform_id_rows"], 1)
        self.assertFalse(triage["counts"]["pending_filed_without_platform_id_counted_as_outcome_evidence"])
        self.assertFalse(triage["counts"]["pending_filed_without_platform_id_counted_as_submission_evidence"])
        self.assertIn("reference/pending_filed_without_platform_id.jsonl", triage["source_artifacts"])
        self.assertIn("pending filed-without-platform-id tracker present", " ".join(triage["signals"]))
        self.assertIn("do not count as outcome evidence", " ".join(triage["unknowns"]))
        self.assertNotEqual(report["readiness"]["status"], "field_validation_ready_for_evaluation")

    def test_cli_writes_json_and_markdown(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "beta"
            ws.mkdir()
            out = root / "report.json"
            md = root / "report.md"
            rc = mod.main(
                [
                    "--workspace",
                    str(ws),
                    "--outcomes",
                    str(root / "missing.jsonl"),
                    "--out",
                    str(out),
                    "--md-out",
                    str(md),
                ]
            )

            self.assertEqual(rc, 0)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.field_validation_report.v1")
            text = md.read_text(encoding="utf-8")
            self.assertIn("Field Validation Report", text)
            self.assertIn("Explicit Unknowns", text)
            self.assertIn("Missing artifacts", text)
            self.assertIn("Field Loop Next Steps", text)

    def test_cli_strict_fails_until_field_validation_is_ready(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "gamma"
            ws.mkdir()
            rc = mod.main(
                [
                    "--workspace",
                    str(ws),
                    "--outcomes",
                    str(root / "missing.jsonl"),
                    "--strict",
                ]
            )

        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
