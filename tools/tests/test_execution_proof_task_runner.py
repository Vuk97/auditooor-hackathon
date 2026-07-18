from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "execution-proof-task-runner.py"


def _import():
    spec = importlib.util.spec_from_file_location("execution_proof_task_runner_test", str(TOOL))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _queue(root: Path) -> Path:
    source_ref = _source_ref(root)
    path = root / ".auditooor" / "execution_proof_task_queue.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "status": "open_execution_proof_tasks",
                "rows": [
                    {
                        "task_id": "p0-1-01-inventory-harness-plan",
                        "limitation_id": "P0-1",
                        "proof_kind": "harness_plan_inventory",
                        "next_command": "make harness-task-queue WS=<workspace> JSON=1",
                        "acceptance_gate": "queue row names candidate data",
                        "source_refs": [source_ref],
                    },
                    {
                        "task_id": "p0-1-05-execute-solidity-a",
                        "limitation_id": "P0-1",
                        "proof_kind": "forge_execution",
                        "next_command": "forge test --match-path <generated-test> -vvv",
                        "acceptance_gate": "operator records stdout/stderr",
                    },
                    {
                        "task_id": "p0-1-07-record-manifest-a",
                        "limitation_id": "P0-1",
                        "proof_kind": "execution_manifest_gate",
                        "next_command": "make poc-execution-record WS=<workspace> BRIEF=<brief> CMD='<forge command>' RESULT=proved IMPACT=exploit_impact",
                        "acceptance_gate": "manifest proves exact impact",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def _source_ref(root: Path) -> str:
    source = root / "src" / "Candidate.sol"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("contract Candidate {}\n", encoding="utf-8")
    return "src/Candidate.sol:1"


def _write_queue(root: Path, rows: list[dict[str, object]]) -> Path:
    path = root / ".auditooor" / "execution_proof_task_queue.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"rows": rows}), encoding="utf-8")
    return path


def _reason_codes(row: dict[str, object]) -> list[str]:
    return [
        str(reason.get("code") or "")
        for reason in row.get("strict_evidence_reasons", [])
        if isinstance(reason, dict)
    ]


class ExecutionProofTaskRunnerTests(unittest.TestCase):
    def test_manifest_classifies_safe_and_placeholder_bound_rows(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            queue = _queue(ws)
            payload = mod.build_manifest(queue, ws)

        self.assertEqual(payload["summary"]["task_count"], 3)
        self.assertEqual(payload["summary"]["auto_executable_count"], 1)
        self.assertEqual(payload["summary"]["needs_binding_count"], 2)
        rows = {row["task_id"]: row for row in payload["rows"]}
        self.assertEqual(rows["p0-1-01-inventory-harness-plan"]["readiness"], "safe_to_execute")
        self.assertIn(str(ws), rows["p0-1-01-inventory-harness-plan"]["runnable_command"])
        self.assertEqual(rows["p0-1-05-execute-solidity-a"]["unresolved_placeholders"], ["<generated-test>"])
        self.assertIn(
            "requires_real_forge_run_and_impact_assertions",
            rows["p0-1-05-execute-solidity-a"]["safety_blocks"],
        )
        self.assertIn(
            "proved_result_requires_manual_manifest_review",
            rows["p0-1-07-record-manifest-a"]["safety_blocks"],
        )
        self.assertIn("RESULT=needs_human", rows["p0-1-07-record-manifest-a"]["proof_recording_command_template"])
        self.assertFalse(payload["submit_ready"])

    def test_runnable_row_passes_with_current_source_refs_and_concrete_command(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            queue = _write_queue(
                ws,
                [
                    {
                        "task_id": "runnable-pass",
                        "proof_kind": "harness_plan_inventory",
                        "next_command": "printf ok",
                        "source_refs": [_source_ref(ws)],
                    }
                ],
            )
            payload = mod.build_manifest(queue, ws)

        row = payload["rows"][0]
        self.assertTrue(row["auto_execution_allowed"])
        self.assertEqual(row["readiness"], "safe_to_execute")
        self.assertEqual(row["strict_validation_status"], "pass")
        self.assertEqual(row["strict_evidence_reasons"], [])
        self.assertEqual(row["source_ref_status"]["status"], "current_workspace_source_refs_ready")

    def test_runnable_row_blocks_missing_source_refs_with_typed_reason(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            queue = _write_queue(
                ws,
                [
                    {
                        "task_id": "missing-source",
                        "proof_kind": "harness_plan_inventory",
                        "next_command": "printf ok",
                    }
                ],
            )
            payload = mod.build_manifest(queue, ws)

        row = payload["rows"][0]
        self.assertFalse(row["auto_execution_allowed"])
        self.assertEqual(row["strict_validation_status"], "blocked")
        self.assertIn("missing_source_refs", _reason_codes(row))
        self.assertIn("missing_source_refs", row["safety_blocks"])
        self.assertEqual(row["source_ref_status"]["status"], "missing_source_refs")

    def test_runnable_row_blocks_stale_workspace_source_refs(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            queue = _write_queue(
                ws,
                [
                    {
                        "task_id": "stale-source",
                        "proof_kind": "harness_plan_inventory",
                        "next_command": "printf ok",
                        "source_refs": ["src/Missing.sol:1"],
                    }
                ],
            )
            payload = mod.build_manifest(queue, ws)

        row = payload["rows"][0]
        self.assertFalse(row["auto_execution_allowed"])
        self.assertEqual(row["strict_validation_status"], "blocked")
        self.assertIn("stale_workspace_source_refs", _reason_codes(row))
        self.assertEqual(row["source_ref_status"]["status"], "stale_workspace_source_refs")
        self.assertEqual(row["source_ref_status"]["stale_refs"][0]["reason"], "source_ref_file_missing")

    def test_proof_complete_row_blocks_missing_proof_evidence(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            queue = _write_queue(
                ws,
                [
                    {
                        "task_id": "proof-complete-no-artifact",
                        "proof_kind": "execution_manifest_gate",
                        "next_command": "printf done",
                        "proof_complete": True,
                        "source_refs": [_source_ref(ws)],
                    }
                ],
            )
            payload = mod.build_manifest(queue, ws)

        row = payload["rows"][0]
        self.assertEqual(row["strict_validation_status"], "blocked")
        self.assertIn("missing_proof_evidence", _reason_codes(row))
        self.assertEqual(row["proof_evidence_status"]["strict_proved_artifact_count"], 0)

    def test_runnable_row_propagates_blocker_and_advisory_markers(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            queue = _write_queue(
                ws,
                [
                    {
                        "task_id": "blocked-marker",
                        "proof_kind": "harness_plan_inventory",
                        "next_command": "printf ok",
                        "source_refs": [_source_ref(ws)],
                        "advisory_only": True,
                        "blockers": ["fixture actor missing"],
                    }
                ],
            )
            payload = mod.build_manifest(queue, ws)

        row = payload["rows"][0]
        self.assertFalse(row["auto_execution_allowed"])
        self.assertEqual(row["strict_validation_status"], "blocked")
        self.assertIn("blocker_or_advisory_marker", _reason_codes(row))
        marker_kinds = {marker["kind"] for marker in row["blocker_advisory_markers"]}
        self.assertEqual(marker_kinds, {"advisory_only", "blocker"})

    def test_markdown_keeps_proof_boundary_visible(self) -> None:
        mod = _import()
        payload = {
            "proof_boundary": "readiness only",
            "summary": {
                "task_count": 1,
                "auto_executable_count": 0,
                "executed_count": 0,
                "needs_binding_count": 1,
                "manual_validation_count": 0,
                "strict_evidence_required_count": 0,
                "strict_evidence_blocked_count": 0,
            },
            "rows": [
                {
                    "task_id": "task-1",
                    "proof_kind": "forge_execution",
                    "readiness": "needs_binding",
                    "safety_blocks": ["unresolved_placeholders"],
                    "runnable_command": "forge test --match-path <generated-test>",
                }
            ],
        }
        md = mod.render_markdown(payload)
        self.assertIn("Execution Proof Command Manifest", md)
        self.assertIn("final_result=proved", md)
        self.assertIn("impact_assertion=exploit_impact", md)

    def test_execute_safe_only_runs_placeholder_free_safe_validators(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            queue = ws / ".auditooor" / "execution_proof_task_queue.json"
            queue.parent.mkdir(parents=True)
            queue.write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "task_id": "safe",
                                "proof_kind": "harness_plan_inventory",
                                "next_command": "printf safe",
                                "source_refs": [_source_ref(ws)],
                            },
                            {
                                "task_id": "blocked",
                                "proof_kind": "forge_execution",
                                "next_command": "printf blocked <generated-test>",
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            payload = mod.build_manifest(queue, ws, execute_safe=True, out_dir=ws / ".auditooor")

            rows = {row["task_id"]: row for row in payload["rows"]}
            self.assertEqual(rows["safe"]["execution_attempt"]["status"], "pass")
            self.assertNotIn("execution_attempt", rows["blocked"])
            self.assertEqual(payload["summary"]["outcome_manifest_count"], 2)
            self.assertIn("outcome_manifest_path", rows["safe"])
            self.assertIn("outcome_manifest_path", rows["blocked"])
            blocked_outcome = json.loads(Path(rows["blocked"]["outcome_manifest_path"]).read_text(encoding="utf-8"))
            self.assertEqual(blocked_outcome["outcome"]["status"], "blocked_needs_binding")
            self.assertFalse(blocked_outcome["outcome"]["executed"])
            self.assertEqual(payload["summary"]["executed_count"], 1)

    def test_generate_bindings_reduces_blocked_outcomes_without_proof(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            queue = _queue(ws)
            payload = mod.build_manifest(queue, ws, execute_safe=True, generate_bindings=True, out_dir=ws / ".auditooor")

            self.assertEqual(payload["summary"]["binding_manifest_count"], 3)
            self.assertEqual(payload["summary"]["blocked_reduction_count"], 2)
            rows = {row["task_id"]: row for row in payload["rows"]}
            blocked = rows["p0-1-05-execute-solidity-a"]
            self.assertIn("binding_manifest_path", blocked)
            binding = json.loads(Path(blocked["binding_manifest_path"]).read_text(encoding="utf-8"))
            self.assertEqual(binding["reduction_status"], "binding_manifest_generated")
            self.assertTrue(Path(binding["brief_path"]).is_file())
            self.assertTrue(any("forge test --match-path" in cmd for cmd in binding["concrete_next_commands"]))
            self.assertTrue(any("RESULT=needs_human IMPACT=unknown" in cmd for cmd in binding["concrete_next_commands"]))
            self.assertFalse(any("RESULT=proved" in cmd for cmd in binding["concrete_next_commands"]))

            outcome = json.loads(Path(blocked["outcome_manifest_path"]).read_text(encoding="utf-8"))
            self.assertEqual(outcome["outcome"]["status"], "binding_manifest_generated")
            self.assertFalse(outcome["outcome"]["executed"])
            self.assertIn("binding_manifest_path", outcome["outcome"])


if __name__ == "__main__":
    unittest.main()
