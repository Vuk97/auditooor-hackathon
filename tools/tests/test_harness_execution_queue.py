#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "harness-execution-queue.py"


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("harness_execution_queue", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MOD = _load_module()
DEFAULT_HARNESS_PATH = "tools/harness-execution-queue.py"


def _build_queue(rows: list[dict], **kwargs: object) -> dict:
    workspace = kwargs.pop("workspace", ROOT)
    kwargs.setdefault("source_schema", MOD.MANIFEST_SCHEMA)
    kwargs.setdefault("source_path", TOOL)
    kwargs.setdefault("manifest_workspace", str(workspace))
    return MOD.build_execution_queue(rows, workspace=workspace, **kwargs)


def _runnable_contract(
    *,
    status: str = "ready_executable_binding",
    binding_scope: str = "harness",
    harness_command: str | None,
    gating_test: str | None,
    generated_test_path: str = DEFAULT_HARNESS_PATH,
    negative_controls: list[str] | None = None,
    blocked_reasons: list[str] | None = None,
) -> dict:
    contract = {
        "schema": MOD.EXECUTION_CONTRACT_SCHEMA,
        "claim": "runnable_harness",
        "runnable": True,
        "advisory_only": False,
        "fail_closed": True,
        "status_snapshot": status,
        "binding_scope": binding_scope,
        "required_for_runnable": [
            "harness_command",
            "gating_test",
            "target_entrypoint",
            "actor_setup",
            "fixture_source",
            "impact_contract_id",
            "generated_test_path",
        ],
        "satisfied_inputs": [
            "harness_command",
            "gating_test",
            "target_entrypoint",
            "actor_setup",
            "fixture_source",
            "impact_contract_id",
            "generated_test_path",
        ],
        "missing_inputs": [],
        "blockers": [],
        "commands": {
            "harness_command": harness_command,
            "gating_test": gating_test,
        },
        "generated_test_path": generated_test_path,
        "evidence_boundary": "exact local harness command plus bound target/setup/fixture/impact inputs",
    }
    if negative_controls is not None:
        contract["negative_controls"] = negative_controls
    if blocked_reasons is not None:
        contract["blocked_reasons"] = blocked_reasons
    return contract


class HarnessExecutionQueueTest(unittest.TestCase):
    def test_ready_rows_after_nonready_cap_are_retained(self) -> None:
        blocked_rows = [
            {
                "row_id": f"KLBQ-BLOCKED-{index}",
                "title": "Blocked diagnostic row",
                "status": "blocked_missing_inputs",
                "binding_scope": "harness",
                "missing_inputs": ["generated_test_path"],
                "blockers": ["missing_generated_test_path"],
            }
            for index in range(3)
        ]
        ready = {
            "row_id": "KLBQ-LATE-READY",
            "title": "Ready row after blocked prefix",
            "binding_scope": "harness",
            "harness_family": "forge_invariant",
            "status": "ready_executable_binding",
            "has_executable_harness_command": True,
            "harness_command": "forge test --match-contract Invariant_KLBQ_LATE_READY -vv",
            "gating_test": "python3 -m unittest tools.tests.test_harness_binding_manifest -v",
            "missing_inputs": [],
            "blockers": [],
            "execution_contract": _runnable_contract(
                harness_command="forge test --match-contract Invariant_KLBQ_LATE_READY -vv",
                gating_test="python3 -m unittest tools.tests.test_harness_binding_manifest -v",
            ),
        }
        queue = _build_queue(blocked_rows + [ready], max_rows=2)

        self.assertEqual(queue["input_row_count"], 4)
        self.assertEqual(queue["retained_ready_row_count"], 1)
        self.assertEqual(queue["ready_row_count"], 1)
        self.assertEqual(queue["ready_command_count"], 2)
        self.assertEqual(queue["retention_policy"], "all_ready_plus_bounded_nonready")
        self.assertIn("KLBQ-LATE-READY", {row["row_id"] for row in queue["rows"]})

    def test_ready_binding_emits_safe_local_commands_in_priority_order(self) -> None:
        queue = _build_queue(
            [
                {
                    "row_id": "KLBQ-READY",
                    "title": "Ready harness",
                    "binding_scope": "harness",
                    "harness_family": "forge_invariant",
                    "status": "ready_executable_binding",
                    "has_executable_harness_command": True,
                    "harness_command": "forge test --match-contract Invariant_KLBQ_READY -vv",
                    "gating_test": "python3 -m unittest tools.tests.test_harness_binding_manifest -v",
                    "missing_inputs": [],
                    "blockers": [],
                    "execution_contract": _runnable_contract(
                        harness_command="forge test --match-contract Invariant_KLBQ_READY -vv",
                        gating_test="python3 -m unittest tools.tests.test_harness_binding_manifest -v",
                    ),
                }
            ],
            workspace=ROOT,
            source_schema=MOD.MANIFEST_SCHEMA,
        )

        self.assertEqual(queue["ready_row_count"], 1)
        self.assertEqual(queue["advisory_row_count"], 0)
        self.assertEqual(queue["blocked_row_count"], 0)
        self.assertEqual(queue["ready_command_count"], 2)
        self.assertEqual(queue["command_row_count"], 2)
        self.assertTrue(queue["source_backing"]["source_backed"])
        self.assertEqual(queue["next_action_priority"]["row_id"], "KLBQ-READY")
        self.assertEqual([row["command_kind"] for row in queue["ready_commands"]], ["gating_test", "harness_command"])
        self.assertEqual([row["command_status"] for row in queue["command_rows"]], ["ready_now", "ready_now"])
        self.assertEqual(queue["counts_by_contract_claim"], {"runnable_harness": 1})
        self.assertTrue(all(row["harness_paths"] for row in queue["ready_commands"]))
        self.assertTrue(all(row["dry_run"] for row in queue["ready_commands"]))
        self.assertTrue(all(not row["would_execute"] for row in queue["ready_commands"]))

    def test_stale_workspace_binding_remains_non_executable(self) -> None:
        queue = _build_queue(
            [
                {
                    "row_id": "KLBQ-STALE",
                    "title": "Stale harness",
                    "binding_scope": "harness",
                    "harness_family": "python_fixture",
                    "status": "ready_executable_binding",
                    "has_executable_harness_command": True,
                    "harness_command": "python3 -c 'print(\"stale harness\")'",
                    "gating_test": "python3 -c 'print(\"stale gate\")'",
                    "missing_inputs": [],
                    "blockers": [],
                    "execution_contract": _runnable_contract(
                        harness_command="python3 -c 'print(\"stale harness\")'",
                        gating_test="python3 -c 'print(\"stale gate\")'",
                    ),
                }
            ],
            workspace=ROOT,
            manifest_workspace="/tmp/stale-audit-workspace",
        )

        self.assertEqual(queue["ready_command_count"], 0)
        self.assertEqual(queue["blocked_row_count"], 1)
        self.assertEqual(queue["rows"][0]["status"], "blocked_execution_prerequisites")
        self.assertIn("manifest_workspace_mismatch", queue["blocked_commands"][0]["blockers"])
        self.assertIn("manifest_workspace", queue["blocked_commands"][0]["missing_inputs"])
        self.assertEqual(
            queue["blocked_commands"][0]["expected_next_action"],
            "regenerate the binding manifest for the current workspace",
        )

    def test_ready_harness_without_execution_contract_fails_closed(self) -> None:
        queue = _build_queue(
            [
                {
                    "row_id": "KLBQ-AMBIGUOUS",
                    "title": "Ready status without contract",
                    "binding_scope": "harness",
                    "harness_family": "forge_invariant",
                    "status": "ready_executable_binding",
                    "has_executable_harness_command": True,
                    "harness_command": "forge test --match-contract Invariant_KLBQ_AMBIGUOUS -vv",
                    "gating_test": "python3 -m unittest tools.tests.test_harness_binding_manifest -v",
                    "missing_inputs": [],
                    "blockers": [],
                }
            ],
            workspace=ROOT,
            source_schema=MOD.MANIFEST_SCHEMA,
        )

        self.assertEqual(queue["ready_command_count"], 0)
        self.assertEqual(queue["blocked_row_count"], 1)
        blocked = queue["blocked_commands"][0]
        self.assertEqual(blocked["status"], "blocked_ambiguous_execution_contract")
        self.assertIn("missing_execution_contract", blocked["blockers"])
        self.assertIn("execution_contract", blocked["missing_inputs"])

    def test_advisory_contract_does_not_enter_ready_commands(self) -> None:
        command = "python3 -m unittest tools.tests.test_harness_binding_manifest -v"
        queue = _build_queue(
            [
                {
                    "row_id": "KLBQ-STATUS",
                    "title": "Status refresh only",
                    "binding_scope": "status_refresh",
                    "harness_family": None,
                    "status": "ready_executable_binding",
                    "has_executable_harness_command": True,
                    "harness_command": command,
                    "gating_test": command,
                    "missing_inputs": [],
                    "blockers": [],
                    "execution_contract": {
                        "schema": MOD.EXECUTION_CONTRACT_SCHEMA,
                        "claim": "advisory_only",
                        "runnable": False,
                        "advisory_only": True,
                        "fail_closed": True,
                        "status_snapshot": "ready_executable_binding",
                        "binding_scope": "status_refresh",
                        "required_for_runnable": ["local_verification_command"],
                        "satisfied_inputs": ["local_verification_command"],
                        "missing_inputs": [],
                        "blockers": [],
                        "commands": {"harness_command": command, "gating_test": command},
                        "evidence_boundary": "not runnable harness evidence",
                    },
                }
            ],
            workspace=ROOT,
            source_schema=MOD.MANIFEST_SCHEMA,
        )

        self.assertEqual(queue["ready_command_count"], 0)
        self.assertEqual(queue["advisory_row_count"], 1)
        self.assertEqual(queue["advisory_command_count"], 1)
        self.assertEqual(queue["advisory_commands"][0]["command_status"], "advisory_only")

    def test_status_refresh_runnable_claim_fails_closed(self) -> None:
        command = "python3 -m unittest tools.tests.test_harness_scaffold_emitter tools.tests.test_harness_binding_manifest tools.tests.test_known_limitations_harness_memory_status -v"
        queue = _build_queue(
            [
                {
                    "row_id": "KLBQ-004",
                    "title": "Harness plan status refresh",
                    "binding_scope": "status_refresh",
                    "harness_family": None,
                    "status": "ready_executable_binding",
                    "has_executable_harness_command": True,
                    "harness_command": command,
                    "gating_test": command,
                    "verification_status": "passed",
                    "local_status_packet": "reports/harness_binding_manifest_status_2026-05-05.json",
                    "local_evidence": [
                        "tools/harness-scaffold-emitter.py",
                        "tools/harness-binding-manifest.py",
                        "reports/harness_binding_manifest_status_2026-05-05.json",
                    ],
                    "verification_commands": [command],
                    "proof_boundary": "Status refresh only; not exploit proof.",
                    "missing_inputs": [],
                    "blockers": [],
                    "execution_contract": _runnable_contract(
                        status="ready_executable_binding",
                        binding_scope="status_refresh",
                        harness_command=command,
                        gating_test=command,
                    ),
                }
            ],
            workspace=ROOT,
            source_schema=MOD.MANIFEST_SCHEMA,
        )

        self.assertEqual(queue["ready_row_count"], 0)
        self.assertEqual(queue["ready_command_count"], 0)
        self.assertEqual(queue["blocked_row_count"], 1)
        self.assertEqual(queue["counts_by_contract_claim"], {"runnable_harness": 1})
        self.assertIn("reports/harness_binding_manifest_status_2026-05-05.json", queue["rows"][0]["expected_artifacts"])
        self.assertEqual(queue["rows"][0]["proof_boundary"], "Status refresh only; not exploit proof.")
        self.assertEqual(queue["blocked_commands"][0]["status"], "blocked_ambiguous_execution_contract")
        self.assertIn("runnable_contract_requires_harness_scope", queue["blocked_commands"][0]["blockers"])

    def test_blocked_missing_inputs_reports_explicit_reason_without_synthesizing_commands(self) -> None:
        queue = _build_queue(
            [
                {
                    "row_id": "KLBQ-BLOCKED",
                    "title": "Missing bindings",
                    "binding_scope": "harness",
                    "harness_family": "forge_invariant",
                    "status": "blocked_missing_inputs",
                    "has_executable_harness_command": True,
                    "harness_command": "forge test --match-contract Invariant_KLBQ_BLOCKED -vv",
                    "gating_test": None,
                    "missing_inputs": ["gating_test", "fixture_source"],
                    "blockers": [],
                }
            ],
            workspace=ROOT,
            source_schema=MOD.MANIFEST_SCHEMA,
        )

        self.assertEqual(queue["ready_command_count"], 0)
        self.assertEqual(queue["blocked_command_count"], 1)
        self.assertEqual(queue["command_row_count"], 1)
        blocked = queue["blocked_commands"][0]
        self.assertEqual(blocked["priority"], 20)
        self.assertEqual(blocked["expected_next_action"], "add one exact local gating command")
        self.assertEqual(blocked["missing_inputs"], ["gating_test", "fixture_source"])
        self.assertTrue(blocked["can_run_local_prereq_now"])
        self.assertEqual(blocked["safe_local_prereq_commands"][0]["command_status"], "blocked_row_prereq")

    def test_blocked_reason_prevents_ready_execution_and_propagates(self) -> None:
        queue = _build_queue(
            [
                {
                    "row_id": "KLBQ-BLOCKED-REASON",
                    "title": "Blocked by proof gate",
                    "binding_scope": "harness",
                    "harness_family": "python_fixture",
                    "status": "ready_executable_binding",
                    "has_executable_harness_command": True,
                    "harness_command": "python3 -c 'print(\"blocked reason harness\")'",
                    "gating_test": "python3 -c 'print(\"blocked reason gate\")'",
                    "missing_inputs": [],
                    "blockers": [],
                    "blocked_reason": "negative control has not passed yet",
                    "negative_controls": ["test_negative_control_rejects_clean_path"],
                    "execution_contract": _runnable_contract(
                        harness_command="python3 -c 'print(\"blocked reason harness\")'",
                        gating_test="python3 -c 'print(\"blocked reason gate\")'",
                        negative_controls=["test_negative_control_rejects_clean_path"],
                    ),
                }
            ],
            workspace=ROOT,
        )

        self.assertEqual(queue["ready_command_count"], 0)
        self.assertEqual(queue["blocked_row_count"], 1)
        blocked = queue["blocked_commands"][0]
        self.assertEqual(blocked["status"], "blocked_ambiguous_execution_contract")
        self.assertIn("runnable_contract_has_blocked_reasons", blocked["blockers"])
        self.assertEqual(blocked["expected_next_action"], "clear the blocked_reason path before exposing executable commands")
        self.assertEqual(blocked["blocked_reasons"], ["negative control has not passed yet"])
        self.assertEqual(blocked["negative_controls"], ["test_negative_control_rejects_clean_path"])
        self.assertEqual(queue["rows"][0]["blocked_reasons"], ["negative control has not passed yet"])
        self.assertEqual(queue["rows"][0]["negative_controls"], ["test_negative_control_rejects_clean_path"])

    def test_disallowed_commands_remain_blocked(self) -> None:
        queue = _build_queue(
            [
                {
                    "row_id": "KLBQ-DISALLOWED",
                    "title": "Network attempt",
                    "binding_scope": "harness",
                    "harness_family": None,
                    "status": "blocked_disallowed_command",
                    "has_executable_harness_command": False,
                    "harness_command": "python3 tools/llm-dispatch.py --prompt-file plan.txt",
                    "gating_test": "curl https://example.com/run-check",
                    "missing_inputs": ["harness_command", "gating_test"],
                    "blockers": ["disallowed_llm_dispatch", "network_access_not_allowed"],
                }
            ],
            workspace=ROOT,
            source_schema=MOD.MANIFEST_SCHEMA,
        )

        blocked = queue["blocked_commands"][0]
        self.assertEqual(blocked["priority"], 90)
        self.assertEqual(blocked["expected_next_action"], "replace llm-dispatch usage with an offline local command")
        self.assertEqual(queue["ready_command_count"], 0)
        self.assertEqual(queue["command_row_count"], 0)

    def test_prereq_filter_rejects_prose_contaminated_local_command(self) -> None:
        queue = _build_queue(
            [
                {
                    "row_id": "KLBQ-PROSE",
                    "title": "Mixed command and prose",
                    "binding_scope": "harness",
                    "harness_family": None,
                    "status": "blocked_missing_inputs",
                    "has_executable_harness_command": False,
                    "harness_command": None,
                    "gating_test": "make harness-failure-memory-validate && make harness-failure-memory-test plus event-to-aggregate fixture tests",
                    "missing_inputs": ["harness_command"],
                    "blockers": ["missing_command"],
                }
            ],
            workspace=ROOT,
            source_schema=MOD.MANIFEST_SCHEMA,
        )

        blocked = queue["blocked_commands"][0]
        self.assertFalse(blocked["can_run_local_prereq_now"])
        self.assertEqual(blocked["safe_local_prereq_commands"], [])
        self.assertEqual(queue["command_row_count"], 0)

    def test_pipe_and_redirection_commands_fail_closed(self) -> None:
        queue = _build_queue(
            [
                {
                    "row_id": "KLBQ-SHELL-TOKEN",
                    "title": "Shell token command",
                    "binding_scope": "harness",
                    "harness_family": None,
                    "status": "blocked_missing_inputs",
                    "has_executable_harness_command": False,
                    "harness_command": None,
                    "gating_test": "python3 -m unittest tools.tests.test_harness_binding_manifest -v | tee /tmp/gate.log",
                    "missing_inputs": ["harness_command"],
                    "blockers": ["missing_command"],
                }
            ],
            workspace=ROOT,
            source_schema=MOD.MANIFEST_SCHEMA,
        )

        assessed = MOD.assess_local_command("python3 -m json.tool reports/harness_execution_queue_2026-05-05.json > /tmp/out.json")
        self.assertFalse(assessed["safe"])
        self.assertIn("unsupported_shell_token:>", assessed["blockers"])
        blocked = queue["blocked_commands"][0]
        self.assertFalse(blocked["can_run_local_prereq_now"])
        self.assertEqual(blocked["safe_local_prereq_commands"], [])
        self.assertEqual(queue["command_row_count"], 0)

        quoted = MOD.assess_local_command("python3 -c 'print(\"a>b\")'")
        self.assertTrue(quoted["safe"])
        inline_shell = MOD.assess_local_command("bash -c 'echo ok | tee /tmp/gate.log'")
        self.assertFalse(inline_shell["safe"])
        self.assertIn("unsupported_shell_inline_command", inline_shell["blockers"])

    def test_status_packet_fallback_emits_blocked_probe_row(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "status.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": MOD.STATUS_SCHEMA,
                        "klbq_004": {
                            "state_delta": "binding-manifest layer now exists",
                            "local_queue_probe": {
                                "row_id": "KLBQ-004",
                                "status": "blocked_vague_plan",
                                "has_executable_harness_command": False,
                                "blockers": ["missing_command", "vague_command"],
                                "missing_inputs": ["harness_command", "gating_test"],
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )

            source_schema, workspace, rows = MOD.load_binding_rows(path)
            queue = _build_queue(rows, workspace=ROOT, source_schema=source_schema, source_path=path)

        self.assertEqual(source_schema, MOD.STATUS_SCHEMA)
        self.assertIsNone(workspace)
        self.assertEqual(queue["row_count"], 1)
        self.assertEqual(queue["next_action_priority"]["priority"], 60)
        self.assertEqual(queue["blocked_commands"][0]["row_id"], "KLBQ-004")

    def test_execute_ready_commands_runs_only_ready_safe_rows(self) -> None:
        queue = _build_queue(
            [
                {
                    "row_id": "KLBQ-READY",
                    "title": "Ready harness",
                    "binding_scope": "harness",
                    "harness_family": "python_fixture",
                    "status": "ready_executable_binding",
                    "has_executable_harness_command": True,
                    "harness_command": "python3 -c 'print(\"harness ok\")'",
                    "gating_test": "python3 -c 'print(\"gate ok\")'",
                    "missing_inputs": [],
                    "blockers": [],
                    "execution_contract": _runnable_contract(
                        harness_command="python3 -c 'print(\"harness ok\")'",
                        gating_test="python3 -c 'print(\"gate ok\")'",
                    ),
                },
                {
                    "row_id": "KLBQ-BLOCKED",
                    "title": "Blocked harness",
                    "binding_scope": "harness",
                    "harness_family": "python_fixture",
                    "status": "blocked_missing_inputs",
                    "has_executable_harness_command": False,
                    "harness_command": "python3 -c 'print(\"blocked should not run\")'",
                    "gating_test": None,
                    "missing_inputs": ["gating_test"],
                    "blockers": [],
                },
            ],
            workspace=ROOT,
            source_schema=MOD.MANIFEST_SCHEMA,
        )

        summary = MOD.execute_ready_commands(queue, max_execute=10, timeout_seconds=30)

        self.assertTrue(summary["executed"])
        self.assertTrue(summary["all_passed"])
        self.assertEqual(summary["selected_command_count"], 2)
        self.assertEqual(summary["status_counts"], {"passed": 2})
        self.assertEqual([row["row_id"] for row in summary["results"]], ["KLBQ-READY", "KLBQ-READY"])
        self.assertIn("gate ok", summary["results"][0]["segment_results"][0]["stdout_tail"])
        self.assertIn("harness ok", summary["results"][1]["segment_results"][0]["stdout_tail"])

    def test_execute_ready_commands_skips_duplicate_ready_rows_before_cap(self) -> None:
        queue = _build_queue(
            [
                {
                    "row_id": "KLBQ-DUP-A",
                    "title": "First ready harness",
                    "binding_scope": "harness",
                    "harness_family": "python_fixture",
                    "status": "ready_executable_binding",
                    "has_executable_harness_command": True,
                    "harness_command": "python3 -c 'print(\"same harness\")'",
                    "gating_test": "python3 -c 'print(\"shared gate\")'",
                    "missing_inputs": [],
                    "blockers": [],
                    "execution_contract": _runnable_contract(
                        harness_command="python3 -c 'print(\"same harness\")'",
                        gating_test="python3 -c 'print(\"shared gate\")'",
                    ),
                },
                {
                    "row_id": "KLBQ-DUP-B",
                    "title": "Duplicate ready harness",
                    "binding_scope": "harness",
                    "harness_family": "python_fixture",
                    "status": "ready_executable_binding",
                    "has_executable_harness_command": True,
                    "harness_command": "python3 -c 'print(\"same harness\")'",
                    "gating_test": "python3 -c 'print(\"shared gate\")'",
                    "missing_inputs": [],
                    "blockers": [],
                    "execution_contract": _runnable_contract(
                        harness_command="python3 -c 'print(\"same harness\")'",
                        gating_test="python3 -c 'print(\"shared gate\")'",
                    ),
                },
                {
                    "row_id": "KLBQ-UNIQUE",
                    "title": "Unique ready harness",
                    "binding_scope": "harness",
                    "harness_family": "python_fixture",
                    "status": "ready_executable_binding",
                    "has_executable_harness_command": True,
                    "harness_command": "python3 -c 'print(\"unique harness\")'",
                    "gating_test": None,
                    "missing_inputs": [],
                    "blockers": [],
                    "execution_contract": _runnable_contract(
                        harness_command="python3 -c 'print(\"unique harness\")'",
                        gating_test=None,
                    ),
                },
            ],
            workspace=ROOT,
            source_schema=MOD.MANIFEST_SCHEMA,
        )

        summary = MOD.execute_ready_commands(queue, max_execute=3, timeout_seconds=30)

        self.assertEqual(summary["candidate_command_count"], 5)
        self.assertEqual(summary["skipped_duplicate_command_count"], 2)
        self.assertEqual(summary["selected_command_count"], 3)
        self.assertEqual(summary["status_counts"], {"passed": 3})
        commands = [row["command"] for row in summary["results"]]
        self.assertEqual(commands.count("python3 -c 'print(\"same harness\")'"), 1)
        self.assertEqual(commands.count("python3 -c 'print(\"shared gate\")'"), 1)
        self.assertEqual(commands.count("python3 -c 'print(\"unique harness\")'"), 1)
        duplicate_rows = {row["row_id"] for row in summary["skipped_duplicate_commands"]}
        self.assertEqual(duplicate_rows, {"KLBQ-DUP-B"})
        self.assertTrue(
            all(row["duplicate_of"]["row_id"] == "KLBQ-DUP-A" for row in summary["skipped_duplicate_commands"])
        )

    def test_execute_ready_commands_records_failure(self) -> None:
        queue = _build_queue(
            [
                {
                    "row_id": "KLBQ-FAIL",
                    "title": "Failing harness",
                    "binding_scope": "harness",
                    "harness_family": "python_fixture",
                    "status": "ready_executable_binding",
                    "has_executable_harness_command": True,
                    "harness_command": "python3 -c 'raise SystemExit(7)'",
                    "gating_test": None,
                    "missing_inputs": [],
                    "blockers": [],
                    "execution_contract": _runnable_contract(
                        harness_command="python3 -c 'raise SystemExit(7)'",
                        gating_test=None,
                    ),
                }
            ],
            workspace=ROOT,
            source_schema=MOD.MANIFEST_SCHEMA,
        )

        summary = MOD.execute_ready_commands(queue, max_execute=10, timeout_seconds=30)

        self.assertFalse(summary["all_passed"])
        self.assertEqual(summary["status_counts"], {"failed": 1})
        self.assertEqual(summary["results"][0]["returncode"], 7)

    def test_execute_ready_commands_keeps_quoted_semicolon_inside_segment(self) -> None:
        queue = _build_queue(
            [
                {
                    "row_id": "KLBQ-QUOTED",
                    "title": "Quoted command",
                    "binding_scope": "harness",
                    "harness_family": "python_fixture",
                    "status": "ready_executable_binding",
                    "has_executable_harness_command": True,
                    "harness_command": "python3 -c 'print(\"harness;ok\")'",
                    "gating_test": None,
                    "missing_inputs": [],
                    "blockers": [],
                    "execution_contract": _runnable_contract(
                        harness_command="python3 -c 'print(\"harness;ok\")'",
                        gating_test=None,
                    ),
                }
            ],
            workspace=ROOT,
            source_schema=MOD.MANIFEST_SCHEMA,
        )

        summary = MOD.execute_ready_commands(queue, max_execute=10, timeout_seconds=30)

        self.assertTrue(summary["all_passed"])
        self.assertEqual(summary["results"][0]["segment_results"][0]["argv"], ["python3", "-c", 'print("harness;ok")'])
        self.assertIn("harness;ok", summary["results"][0]["segment_results"][0]["stdout_tail"])

    def test_main_execute_ready_can_fail_on_execution_failure(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "manifest.json"
            out = Path(td) / "queue.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": MOD.MANIFEST_SCHEMA,
                        "workspace": str(ROOT),
                        "rows": [
                            {
                                "row_id": "KLBQ-CLI",
                                "title": "Failing harness",
                                "binding_scope": "harness",
                                "harness_family": "python_fixture",
                                "status": "ready_executable_binding",
                                "has_executable_harness_command": True,
                                "harness_command": "python3 -c 'raise SystemExit(5)'",
                                "gating_test": None,
                                "missing_inputs": [],
                                "blockers": [],
                                "execution_contract": _runnable_contract(
                                    harness_command="python3 -c 'raise SystemExit(5)'",
                                    gating_test=None,
                                ),
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            rc = MOD.main(
                [
                    "--input",
                    str(path),
                    "--workspace",
                    str(ROOT),
                    "--out",
                    str(out),
                    "--execute-ready",
                    "--fail-on-execution-failure",
                ]
            )
            payload = json.loads(out.read_text(encoding="utf-8"))

        self.assertEqual(rc, 1)
        self.assertTrue(payload["execution_summary"]["executed"])
        self.assertEqual(payload["execution_summary"]["status_counts"], {"failed": 1})


if __name__ == "__main__":
    unittest.main()
