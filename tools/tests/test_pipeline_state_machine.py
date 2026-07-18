from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_WORKSPACE = ROOT / "tools"
MODULE_PATH = ROOT / "tools" / "pipeline-state-machine.py"
SPEC = importlib.util.spec_from_file_location("pipeline_state_machine", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
machine = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(machine)
receipt = machine._receipt

BASELINES = {
    "workspace_identity_sha256": "1" * 64,
    "source_snapshot_sha256": "2" * 64,
    "scope_sha256": "3" * 64,
    "severity_sha256": "4" * 64,
    "targets_sha256": "5" * 64,
    "program_rules_sha256": "6" * 64,
    "pipeline_tooling_sha256": "7" * 64,
}


def manifest(count: int = 69, *, mixed_order: bool = False, explicit_invalidates: bool = False) -> dict:
    steps = []
    for index in range(count):
        order_index = count - index - 1 if mixed_order else index
        produces = [f"artifact-{index:02d}"]
        consumes = [f"artifact-{index - 1:02d}"] if index else []
        steps.append(
            {
                "step_id": f"step-{index:02d}",
                "order_index": order_index,
                "run_sequence": index,
                "phase": "drive",
                "execution_target": ["python3", "tools/pipeline-manifest-validate.py", "--manifest", "{workspace}/manifest.json"],
                "applicability_probe": "always",
                "depends_on": [f"step-{index - 1:02d}"] if index else [],
                "consumes": consumes,
                "produces": produces,
                "validators": ["noop"],
                "invalidates": [f"step-{count - 1:02d}"] if explicit_invalidates and index == 0 else [],
                "terminal_output": index == count - 1,
                "required": True,
            }
        )
    graph = {
        "schema": "auditooor.pipeline_manifest.v2",
        "expected_step_count": count,
        "steps": steps,
        "execution_placeholders": [
            {"id": "workspace", "token": "{workspace}", "source": "executor.workspace_root"},
        ],
        "environment_passthrough": ["PIPELINE_FORCE"],
        "applicability_probes": [{"id": "always", "kind": "always"}],
        "validators": ["noop"],
        "reasoner_registry": [],
    }
    return refresh_manifest(graph)


def refresh_manifest(graph: dict) -> dict:
    steps = graph["steps"]
    consumers_by_artifact: dict[str, list[str]] = {}
    for step in steps:
        for artifact in step["consumes"]:
            consumers_by_artifact.setdefault(artifact, []).append(step["step_id"])
    graph["execution_target_registry"] = [
        {"step_id": step["step_id"], "argv": list(step["execution_target"])}
        for step in steps
    ]
    graph["artifact_contracts"] = sorted(
        [
            {
                "id": artifact,
                "path": f".auditooor/test/{artifact}.json",
                "kind": "file",
                "validators": ["noop"],
                "producer_step_ids": [step["step_id"]],
                "consumer_step_ids": sorted(consumers_by_artifact.get(artifact, [])),
                "terminal": not consumers_by_artifact.get(artifact, []),
            }
            for step in steps
            for artifact in step["produces"]
        ],
        key=lambda row: row["id"],
    )
    return graph


def build_receipt(
    state: dict,
    step: dict,
    token: str,
    *,
    status: str = "succeeded",
    upstream: list[str] | None = None,
    input_artifacts: list[dict] | None = None,
    output_artifacts: list[dict] | None = None,
    applicability: dict | None = None,
    applicability_error_diagnostics: list[str] | None = None,
) -> dict:
    index = step["run_sequence"]
    if applicability is None:
        if applicability_error_diagnostics is not None:
            applicability = {"probe_id": step["applicability_probe"], "canonical_inputs": {}, "result": True}
        else:
            applicability = machine._applicability.evaluate_probe(
                {"applicability_probes": [{"id": "always", "kind": "always"}]},
                "always",
                DEFAULT_WORKSPACE,
            )
    return receipt.build_receipt(
        run_id=state["run_id"],
        manifest_sha256=state["manifest_sha256"],
        workspace_identity_sha256=state["workspace_identity_sha256"],
        source_snapshot_sha256=state["source_snapshot_sha256"],
        scope_sha256=state["scope_sha256"],
        severity_sha256=state["severity_sha256"],
        targets_sha256=state["targets_sha256"],
        program_rules_sha256=state["program_rules_sha256"],
        pipeline_tooling_sha256=state["pipeline_tooling_sha256"],
        step_id=step["step_id"],
        order_index=step["order_index"],
        attempt=state["steps"][step["step_id"]]["attempt"],
        step_token=token,
        status=status,
        applicability_probe_id=applicability["probe_id"],
        applicability_inputs=applicability["canonical_inputs"],
        applicability_result=applicability["result"],
        applicability_error_diagnostics=applicability_error_diagnostics,
        argv=step["execution_target"],
        selected_environment={"LANG": "C"},
        started_at="2026-07-17T10:00:00+00:00",
        finished_at="2026-07-17T10:00:01+00:00",
        exit_code=1 if status == "failed" else 0,
        upstream_receipt_ids=upstream or [],
        input_artifacts=input_artifacts or [],
        output_artifacts=output_artifacts if output_artifacts is not None else ([] if status == "not_applicable" else [
            {
                "artifact_contract": f"artifact-{index:02d}",
                "path": f"output-{index:02d}.json",
                "sha256": f"{index % 10}" * 64,
                "size": index,
                "semantic_validator_results": [{"validator_id": "noop", "status": "succeeded"}],
            }
        ]),
        stdout_sha256="a" * 64,
        stderr_sha256="b" * 64,
        tool_versions={"pipeline": "2"},
        toolchain_versions={"python": "3"},
    )


def complete(state: dict, graph: dict, index: int, *, status: str = "succeeded") -> dict:
    step = next(item for item in graph["steps"] if item["run_sequence"] == index)
    token = machine.start_step(state, graph, step["step_id"])
    upstream = [state["steps"][dep]["current_receipt_id"] for dep in step["depends_on"]]
    inputs = [] if status == "not_applicable" else [
        row for dep in step["depends_on"] for row in state["steps"][dep]["current_output_artifacts"]
    ]
    result = build_receipt(state, step, token, status=status, upstream=upstream, input_artifacts=inputs)
    machine.accept_receipt(state, graph, result, workspace=DEFAULT_WORKSPACE)
    return result


class PipelineStateMachineTest(unittest.TestCase):
    def new_state(self, graph: dict | None = None) -> tuple[dict, dict]:
        graph = graph or manifest()
        return graph, machine.initialize_state(graph, run_id="run-fixture", **BASELINES)

    def assert_error(self, code: str, callback: object) -> None:
        with self.assertRaises(machine.StateMachineError) as raised:
            callback()
        self.assertIn(code, raised.exception.diagnostics)

    def test_synthetic_69_step_graph_cannot_skip_or_reorder(self) -> None:
        graph, state = self.new_state()
        self.assert_error("earlier_run_sequence_blocks", lambda: machine.start_step(state, graph, "step-68"))
        for index in range(69):
            complete(state, graph, index)
        self.assertTrue(machine.closeout(state, graph)["valid"])

    def test_execution_uses_run_sequence_not_order_index(self) -> None:
        graph, state = self.new_state(manifest(3, mixed_order=True))
        self.assert_error("earlier_run_sequence_blocks", lambda: machine.start_step(state, graph, "step-02"))
        complete(state, graph, 0)
        complete(state, graph, 1)
        complete(state, graph, 2)
        self.assertTrue(machine.closeout(state, graph)["valid"])

    def test_exact_predecessor_receipt_set_is_required(self) -> None:
        graph, state = self.new_state(manifest(2))
        first = complete(state, graph, 0)
        step = graph["steps"][1]
        token = machine.start_step(state, graph, step["step_id"])
        wrong = build_receipt(state, step, token, upstream=[])
        self.assert_error("receipt_dependency_receipts_mismatch", lambda: machine.accept_receipt(state, graph, wrong, workspace=DEFAULT_WORKSPACE))
        right = build_receipt(state, step, token, upstream=[first["receipt_id"]])
        right["input_artifacts"] = state["steps"]["step-00"]["current_output_artifacts"]
        right["receipt_id"] = receipt.receipt_id(right)
        right["self_hash"] = right["receipt_id"]
        machine.accept_receipt(state, graph, right, workspace=DEFAULT_WORKSPACE)

    def test_typed_artifact_joins_reject_stale_invented_and_missing_producer_outputs(self) -> None:
        graph, state = self.new_state(manifest(2))
        first = complete(state, graph, 0)
        step = graph["steps"][1]
        token = machine.start_step(state, graph, step["step_id"])
        stale_input = dict(state["steps"]["step-00"]["current_output_artifacts"][0])
        stale_input["sha256"] = "f" * 64
        stale = build_receipt(state, step, token, upstream=[first["receipt_id"]], input_artifacts=[stale_input])
        self.assert_error("receipt_input_artifact_not_current_producer_output", lambda: machine.accept_receipt(state, graph, stale, workspace=DEFAULT_WORKSPACE))
        invented_input = dict(state["steps"]["step-00"]["current_output_artifacts"][0])
        invented_input["artifact_contract"] = "artifact-invented"
        invented = build_receipt(state, step, token, upstream=[first["receipt_id"]], input_artifacts=[invented_input])
        self.assert_error("receipt_input_contract_set_mismatch", lambda: machine.accept_receipt(state, graph, invented, workspace=DEFAULT_WORKSPACE))

        graph, state = self.new_state(manifest(2))
        graph["applicability_probes"].append({"id": "python-only", "kind": "language_any", "languages": ["python"]})
        graph["steps"][0]["applicability_probe"] = "python-only"
        state = machine.initialize_state(graph, run_id="run-fixture", **BASELINES)
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / ".auditooor").mkdir()
            (workspace / "source.go").write_text("package source\n", encoding="utf-8")
            (workspace / ".auditooor" / "inscope_units.jsonl").write_text('{"file":"source.go","lang":"go"}\n', encoding="utf-8")
            first = graph["steps"][0]
            first_token = machine.start_step(state, graph, first["step_id"])
            first_applicability = machine._applicability.evaluate_probe(graph, "python-only", workspace)
            machine.accept_receipt(
                state,
                graph,
                build_receipt(state, first, first_token, status="not_applicable", applicability=first_applicability),
                workspace=workspace,
            )
            step = graph["steps"][1]
            token = machine.start_step(state, graph, step["step_id"])
            missing_producer = {
                "artifact_contract": "artifact-00",
                "path": "missing.json",
                "sha256": "e" * 64,
                "size": 0,
            }
            receipt_with_missing_producer = build_receipt(
                state,
                step,
                token,
                upstream=[state["steps"]["step-00"]["current_receipt_id"]],
                input_artifacts=[missing_producer],
            )
            self.assert_error("receipt_input_artifact_not_current_producer_output", lambda: machine.accept_receipt(state, graph, receipt_with_missing_producer, workspace=DEFAULT_WORKSPACE))

    def test_failed_receipt_may_have_partial_declared_outputs(self) -> None:
        graph = manifest(1)
        graph["steps"][0]["produces"] = ["artifact-00", "artifact-extra"]
        refresh_manifest(graph)
        _, state = self.new_state(graph)
        token = machine.start_step(state, graph, "step-00")
        failed = build_receipt(state, graph["steps"][0], token, status="failed")
        machine.accept_receipt(state, graph, failed, workspace=DEFAULT_WORKSPACE)
        self.assertEqual(state["steps"]["step-00"]["state"], "failed")
        self.assertEqual(len(state["steps"]["step-00"]["receipt_history"][0]["output_artifacts"]), 1)

    def test_forged_missing_and_stale_step_tokens_are_rejected(self) -> None:
        graph, state = self.new_state(manifest(1))
        step = graph["steps"][0]
        token = machine.start_step(state, graph, step["step_id"])
        forged = build_receipt(state, step, "f" * 64)
        self.assert_error("receipt_step_token_mismatch", lambda: machine.accept_receipt(state, graph, forged, workspace=DEFAULT_WORKSPACE))
        missing = build_receipt(state, step, token)
        missing.pop("step_token")
        self.assert_error("invalid_terminal_receipt", lambda: machine.accept_receipt(state, graph, missing, workspace=DEFAULT_WORKSPACE))
        valid = build_receipt(state, step, token)
        machine.accept_receipt(state, graph, valid, workspace=DEFAULT_WORKSPACE)
        machine.invalidate_step(state, graph, step["step_id"], reason="rerun")
        next_token = machine.start_step(state, graph, step["step_id"])
        stale = build_receipt(state, step, token)
        self.assert_error("receipt_step_token_mismatch", lambda: machine.accept_receipt(state, graph, stale, workspace=DEFAULT_WORKSPACE))
        machine.accept_receipt(state, graph, build_receipt(state, step, next_token), workspace=DEFAULT_WORKSPACE)

    def test_false_not_applicable_is_rejected_by_receipt_validator(self) -> None:
        graph, state = self.new_state(manifest(1))
        step = graph["steps"][0]
        token = machine.start_step(state, graph, step["step_id"])
        invalid = build_receipt(state, step, token, status="not_applicable")
        invalid["applicability"]["result"] = True
        invalid["applicability"]["hash"] = receipt.stable_hash(
            {"probe_id": "always", "canonical_inputs": invalid["applicability"]["canonical_inputs"], "result": True}
        )
        self.assert_error("invalid_terminal_receipt", lambda: machine.accept_receipt(state, graph, invalid, workspace=DEFAULT_WORKSPACE))

    def test_workspace_authority_rejects_forged_na_execution_other_probe_and_stale_inventory(self) -> None:
        def language_graph() -> dict:
            graph = manifest(1)
            graph["applicability_probes"] = [
                {"id": "go-only", "kind": "language_any", "languages": ["go"]},
                {"id": "js-only", "kind": "language_any", "languages": ["javascript"]},
            ]
            graph["steps"][0]["applicability_probe"] = "js-only"
            return graph

        def prepare(workspace: Path) -> tuple[dict, dict, dict, str]:
            graph = language_graph()
            state = machine.initialize_state(graph, run_id="run-fixture", **BASELINES)
            step = graph["steps"][0]
            token = machine.start_step(state, graph, step["step_id"])
            return graph, state, step, token

        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / ".auditooor").mkdir()
            (workspace / "app.js").write_text("source\n", encoding="utf-8")
            (workspace / "app.go").write_text("package app\n", encoding="utf-8")
            inventory = workspace / ".auditooor" / "inscope_units.jsonl"
            inventory.write_text('{"file":"app.js","lang":"js"}\n', encoding="utf-8")

            graph, state, step, token = prepare(workspace)
            expected = machine._applicability.evaluate_probe(graph, "js-only", workspace)
            forged_na = dict(expected)
            forged_na["result"] = False
            forged_na["hash"] = receipt.stable_hash({key: forged_na[key] for key in ("probe_id", "canonical_inputs", "result")})
            self.assert_error(
                "receipt_applicability_mismatch",
                lambda: machine.accept_receipt(
                    state,
                    graph,
                    build_receipt(state, step, token, status="not_applicable", applicability=forged_na),
                    workspace=workspace,
                ),
            )

            inventory.write_text('{"file":"app.go","lang":"go"}\n', encoding="utf-8")
            graph, state, step, token = prepare(workspace)
            inapplicable = machine._applicability.evaluate_probe(graph, "js-only", workspace)
            forged_execution = dict(inapplicable)
            forged_execution["result"] = True
            forged_execution["hash"] = receipt.stable_hash({key: forged_execution[key] for key in ("probe_id", "canonical_inputs", "result")})
            self.assert_error(
                "receipt_applicability_mismatch",
                lambda: machine.accept_receipt(
                    state,
                    graph,
                    build_receipt(state, step, token, applicability=forged_execution),
                    workspace=workspace,
                ),
            )

            other_probe = machine._applicability.evaluate_probe(graph, "go-only", workspace)
            self.assert_error(
                "receipt_applicability_probe_mismatch",
                lambda: machine.accept_receipt(
                    state,
                    graph,
                    build_receipt(state, step, token, applicability=other_probe),
                    workspace=workspace,
                ),
            )

            inventory.write_text('{"file":"app.js","lang":"javascript"}\n', encoding="utf-8")
            graph, state, step, token = prepare(workspace)
            stale = machine._applicability.evaluate_probe(graph, "js-only", workspace)
            stale_inventory_bytes = inventory.read_bytes()
            inventory.write_text('{"file":"app.js","lang":"javascript"}\n{"file":"app.js","lang":"js"}\n', encoding="utf-8")
            self.assert_error(
                "receipt_applicability_mismatch",
                lambda: machine.accept_receipt(
                    state,
                    graph,
                    build_receipt(state, step, token, applicability=stale),
                    workspace=workspace,
                ),
            )

            with tempfile.TemporaryDirectory() as copied_tmp:
                copied_workspace = Path(copied_tmp)
                (copied_workspace / ".auditooor").mkdir()
                (copied_workspace / "app.js").write_text("source\n", encoding="utf-8")
                copied_inventory = copied_workspace / ".auditooor" / "inscope_units.jsonl"
                copied_inventory.write_bytes(stale_inventory_bytes)
                graph, state, step, token = prepare(copied_workspace)
                copied_receipt = build_receipt(state, step, token, applicability=stale)
                self.assert_error(
                    "receipt_applicability_mismatch",
                    lambda: machine.accept_receipt(state, graph, copied_receipt, workspace=copied_workspace),
                )

            graph, state, step, token = prepare(workspace)
            valid = machine._applicability.evaluate_probe(graph, "js-only", workspace)
            inventory.write_text("malformed\n", encoding="utf-8")
            self.assert_error(
                "applicability_probe_error_requires_failed_receipt",
                lambda: machine.accept_receipt(
                    state,
                    graph,
                    build_receipt(state, step, token, applicability=valid),
                    workspace=workspace,
                ),
            )

    def test_failed_receipt_accepts_typed_applicability_probe_error_only_for_failed_status(self) -> None:
        graph = manifest(1)
        graph["applicability_probes"] = [{"id": "go-only", "kind": "language_any", "languages": ["go"]}]
        graph["steps"][0]["applicability_probe"] = "go-only"
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / ".auditooor").mkdir()
            (workspace / "app.go").write_text("package app\n", encoding="utf-8")
            inventory = workspace / ".auditooor" / "inscope_units.jsonl"
            inventory.write_text("malformed\n", encoding="utf-8")

            state = machine.initialize_state(graph, run_id="run-fixture", **BASELINES)
            step = graph["steps"][0]
            token = machine.start_step(state, graph, step["step_id"])
            failed = build_receipt(
                state,
                step,
                token,
                status="failed",
                applicability_error_diagnostics=["applicability_inventory_malformed_row:1"],
            )
            machine.accept_receipt(state, graph, failed, workspace=workspace)
            entry = state["steps"]["step-00"]
            self.assertEqual(entry["state"], "failed")
            self.assertIsNone(entry["current_receipt_id"])
            self.assertEqual(entry["receipt_history"][0]["status"], "failed")

            state = machine.initialize_state(graph, run_id="run-fixture", **BASELINES)
            token = machine.start_step(state, graph, step["step_id"])
            fabricated_na = build_receipt(
                state,
                step,
                token,
                status="not_applicable",
                applicability_error_diagnostics=["applicability_inventory_malformed_row:1"],
            )
            self.assert_error(
                "invalid_terminal_receipt",
                lambda: machine.accept_receipt(state, graph, fabricated_na, workspace=workspace),
            )

            state = machine.initialize_state(graph, run_id="run-fixture", **BASELINES)
            token = machine.start_step(state, graph, step["step_id"])
            success_with_error = build_receipt(
                state,
                step,
                token,
                applicability_error_diagnostics=["applicability_inventory_malformed_row:1"],
            )
            self.assert_error(
                "invalid_terminal_receipt",
                lambda: machine.accept_receipt(state, graph, success_with_error, workspace=workspace),
            )

    def test_failed_receipt_rejects_malformed_typed_applicability_probe_error(self) -> None:
        graph = manifest(1)
        graph["applicability_probes"] = [{"id": "go-only", "kind": "language_any", "languages": ["go"]}]
        graph["steps"][0]["applicability_probe"] = "go-only"
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / ".auditooor").mkdir()
            (workspace / "app.go").write_text("package app\n", encoding="utf-8")
            (workspace / ".auditooor" / "inscope_units.jsonl").write_text("malformed\n", encoding="utf-8")

            state = machine.initialize_state(graph, run_id="run-fixture", **BASELINES)
            step = graph["steps"][0]
            token = machine.start_step(state, graph, step["step_id"])
            invalid = build_receipt(
                state,
                step,
                token,
                status="failed",
                applicability_error_diagnostics=["applicability_inventory_malformed_row:1"],
            )
            invalid["applicability"]["evaluation_error"]["kind"] = "wrong"
            invalid["receipt_id"] = receipt.receipt_id(invalid)
            invalid["self_hash"] = invalid["receipt_id"]
            self.assert_error(
                "invalid_terminal_receipt",
                lambda: machine.accept_receipt(state, graph, invalid, workspace=workspace),
            )

    def test_failed_step_blocks_later_and_retry_increments_attempt(self) -> None:
        graph, state = self.new_state(manifest(2))
        complete(state, graph, 0, status="failed")
        self.assert_error("earlier_run_sequence_blocks", lambda: machine.start_step(state, graph, "step-01"))
        token = machine.start_step(state, graph, "step-00")
        self.assertEqual(state["steps"]["step-00"]["attempt"], 2)
        machine.accept_receipt(state, graph, build_receipt(state, graph["steps"][0], token), workspace=DEFAULT_WORKSPACE)
        complete(state, graph, 1)
        self.assertTrue(machine.closeout(state, graph)["valid"])

    def test_resume_rejects_each_baseline_mismatch_and_state_tampering(self) -> None:
        graph, state = self.new_state(manifest(1))
        for field, original in BASELINES.items():
            changed = dict(BASELINES)
            changed[field] = "f" * 64 if original != "f" * 64 else "e" * 64
            self.assert_error(f"{field}_mismatch", lambda changed=changed: machine.resume_state(state, graph, run_id="run-fixture", **changed))
        self.assert_error("run_id_mismatch", lambda: machine.resume_state(state, graph, run_id="other", **BASELINES))
        changed_manifest = manifest(1)
        changed_manifest["steps"][0]["execution_target"] = ["python3", "tools/pipeline-receipt.py"]
        refresh_manifest(changed_manifest)
        self.assert_error("manifest_sha256_mismatch", lambda: machine.resume_state(state, changed_manifest, run_id="run-fixture", **BASELINES))
        state["steps"]["step-00"]["attempt"] = 99
        ok, errors = machine.validate_state(state)
        self.assertFalse(ok)
        self.assertIn("state_self_hash_mismatch", errors)

        _, structurally_tampered = self.new_state(manifest(1))
        structurally_tampered["steps"]["step-00"]["state"] = "not-a-state"
        machine._seal(structurally_tampered)
        ok, errors = machine.validate_state(structurally_tampered)
        self.assertFalse(ok)
        self.assertIn("state_step_step-00_invalid_state", errors)

        _, malformed = self.new_state(manifest(1))
        malformed["steps"]["step-00"]["state"] = "running"
        malformed["steps"]["step-00"]["attempt"] = "bad"
        malformed["steps"]["step-00"]["active_token_sha256"] = "f" * 64
        machine._seal(malformed)
        ok, errors = machine.validate_state(malformed)
        self.assertFalse(ok)
        self.assertIn("state_step_step-00_invalid_attempt", errors)

    def test_invalidation_propagates_dependency_artifact_and_explicit_consumers(self) -> None:
        graph, state = self.new_state(manifest(4, explicit_invalidates=True))
        for index in range(4):
            complete(state, graph, index)
        invalidated = machine.reopen_step(state, graph, "step-00", reason="producer-output-changed")
        self.assertEqual(invalidated, ["step-00", "step-01", "step-02", "step-03"])
        for index in range(4):
            entry = state["steps"][f"step-{index:02d}"]
            self.assertEqual(entry["state"], "invalidated")
            self.assertIsNone(entry["current_receipt_id"])
            self.assertEqual(entry["current_output_artifacts"], [])
            self.assertGreaterEqual(len(entry["receipt_history"]), 1)
            self.assertGreaterEqual(len(entry["receipt_history"][0]["output_artifacts"]), 1)
        self.assertEqual(len(state["invalidation_history"]), 4)
        self.assertEqual(state["invalidation_history"][0]["source_step_id"], "step-00")
        self.assertEqual(state["invalidation_history"][0]["reason"], "producer-output-changed")
        self.assert_error("invalid_invalidation_reason", lambda: machine.invalidate_step(state, graph, "step-00", reason=""))

    def test_invalidation_clears_entire_later_run_suffix_even_without_graph_edges(self) -> None:
        graph = manifest(3)
        graph["steps"][1]["terminal_output"] = True
        graph["steps"][2]["depends_on"] = ["step-00"]
        graph["steps"][2]["consumes"] = ["artifact-00"]
        refresh_manifest(graph)
        _, state = self.new_state(graph)
        for index in range(3):
            complete(state, graph, index)
        invalidated = machine.invalidate_step(state, graph, "step-01", reason="earlier-step-rerun")
        self.assertEqual(invalidated, ["step-01", "step-02"])
        self.assertEqual(state["steps"]["step-00"]["state"], "succeeded")
        self.assertEqual(state["steps"]["step-01"]["state"], "invalidated")
        self.assertEqual(state["steps"]["step-02"]["state"], "invalidated")

    def test_closeout_requires_exact_current_69_successful_or_na_receipts(self) -> None:
        graph, state = self.new_state()
        for index in range(68):
            complete(state, graph, index)
        partial = machine.closeout(state, graph)
        self.assertFalse(partial["valid"])
        self.assertIn("closeout_receipt_count_mismatch", partial["diagnostics"])
        machine.invalidate_step(state, graph, "step-67", reason="failed-input")
        failed_token = machine.start_step(state, graph, "step-67")
        inputs = state["steps"]["step-66"]["current_output_artifacts"]
        machine.accept_receipt(state, graph, build_receipt(state, graph["steps"][67], failed_token, status="failed", upstream=[state["steps"]["step-66"]["current_receipt_id"]], input_artifacts=inputs), workspace=DEFAULT_WORKSPACE)
        self.assertFalse(machine.closeout(state, graph)["valid"])
        retry_token = machine.start_step(state, graph, "step-67")
        machine.accept_receipt(state, graph, build_receipt(state, graph["steps"][67], retry_token, upstream=[state["steps"]["step-66"]["current_receipt_id"]], input_artifacts=inputs), workspace=DEFAULT_WORKSPACE)
        complete(state, graph, 68)
        self.assertTrue(machine.closeout(state, graph)["valid"])
        machine.invalidate_step(state, graph, "step-68", reason="input-invalidated")
        self.assertFalse(machine.closeout(state, graph)["valid"])

        graph, state = self.new_state()
        for index in range(69):
            complete(state, graph, index)
        first_id = state["steps"]["step-00"]["current_receipt_id"]
        last = state["steps"]["step-68"]
        first_record = dict(state["steps"]["step-00"]["receipt_history"][0])
        last["receipt_history"].append(first_record)
        last["receipt_history"].sort(key=lambda item: (item["attempt"], item["receipt_id"]))
        last["current_receipt_id"] = first_id
        last["current_output_artifacts"] = first_record["output_artifacts"]
        last["output_fingerprint"] = first_record["output_fingerprint"]
        machine._seal(state)
        duplicate = machine.closeout(state, graph)
        self.assertFalse(duplicate["valid"])
        self.assertIn("closeout_duplicate_current_receipt", duplicate["diagnostics"])

    def test_cli_smoke_path(self) -> None:
        graph = manifest(1)
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            manifest_path = tmp_path / "manifest.json"
            state_path = tmp_path / "state.json"
            receipt_path = tmp_path / "receipt.json"
            manifest_path.write_text(json.dumps(graph), encoding="utf-8")
            command = ["python3", str(MODULE_PATH), "init", "--manifest", str(manifest_path), "--state", str(state_path), "--run-id", "cli-run"]
            for field, value in BASELINES.items():
                command.extend(["--" + field.replace("_", "-"), value])
            self.assertEqual(subprocess.run(command, capture_output=True, text=True).returncode, 0)
            started = subprocess.run(
                ["python3", str(MODULE_PATH), "start", "--manifest", str(manifest_path), "--state", str(state_path), "--step-id", "step-00"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(started.returncode, 0, started.stderr)
            token = started.stdout.strip()
            saved, errors = machine.read_state(state_path)
            self.assertEqual(errors, [])
            assert saved is not None
            receipt.write_receipt(receipt_path, build_receipt(saved, graph["steps"][0], token))
            accepted = subprocess.run(
                ["python3", str(MODULE_PATH), "accept", "--manifest", str(manifest_path), "--state", str(state_path), "--receipt", str(receipt_path), "--workspace", str(DEFAULT_WORKSPACE)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            closed = subprocess.run(
                ["python3", str(MODULE_PATH), "closeout", "--manifest", str(manifest_path), "--state", str(state_path)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(closed.returncode, 0, closed.stderr)
            graph["steps"][0]["execution_target"] = ["python3", "tools/mismatch.py"]
            manifest_path.write_text(json.dumps(graph), encoding="utf-8")
            mismatched_status = subprocess.run(
                ["python3", str(MODULE_PATH), "status", "--manifest", str(manifest_path), "--state", str(state_path)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(mismatched_status.returncode, 1)


if __name__ == "__main__":
    unittest.main()
