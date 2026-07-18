from __future__ import annotations

import importlib.util
import io
import json
import hashlib
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("pipeline_executor", ROOT / "tools" / "pipeline-executor.py")
assert SPEC is not None and SPEC.loader is not None
executor = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = executor
SPEC.loader.exec_module(executor)


def command(path: str, payload: str, exit_code: int = 0) -> list[str]:
    body = f"from pathlib import Path; Path(r'{path}').parent.mkdir(parents=True, exist_ok=True); Path(r'{path}').write_text({payload!r}); raise SystemExit({exit_code})"
    return [sys.executable, "-c", body]


def manifest(steps: list[dict], contracts: list[dict], probes: list[dict] | None = None) -> dict:
    return {
        "schema": "auditooor.pipeline_manifest.v2",
        "expected_step_count": len(steps),
        "steps": steps,
        "artifact_contracts": contracts,
        "applicability_probes": probes or [{"id": "always", "kind": "always"}],
        "validators": ["json"],
    }


def step(index: int, *, produces: list[str], consumes: list[str] | None = None, probe: str = "always", target: list[str] | None = None) -> dict:
    return {
        "step_id": f"step-{index}", "order_index": index, "run_sequence": index, "phase": "drive",
        "execution_target": target or [sys.executable, "-c", "pass"], "applicability_probe": probe,
        "depends_on": [f"step-{index - 1}"] if index else [], "consumes": consumes or [], "produces": produces,
        "validators": ["json"], "invalidates": [], "terminal_output": bool(produces), "required": True,
    }


class PipelineExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.validator_file = mock.patch.object(
            executor._validator,
            "validate_manifest_file",
            return_value={"valid": True, "diagnostics": []},
        )
        self.validator_memory = mock.patch.object(
            executor._machine._manifest_validator,
            "validate_manifest",
            return_value={"valid": True, "diagnostics": []},
        )
        self.validator_file.start()
        self.validator_memory.start()
        self.addCleanup(self.validator_file.stop)
        self.addCleanup(self.validator_memory.stop)

    def workspace(self) -> tempfile.TemporaryDirectory[str]:
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        (root / "src").mkdir()
        (root / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
        for name in ("SCOPE.md", "SEVERITY.md", "targets.tsv"):
            (root / name).write_text(name + "\n", encoding="utf-8")
        (root / ".auditooor").mkdir()
        (root / ".auditooor" / "program_rules.json").write_text("{}\n", encoding="utf-8")
        return tmp

    def write_manifest(self, root: Path, value: dict) -> Path:
        path = root / "manifest.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def state(self, root: Path) -> dict:
        return json.loads((root / ".auditooor" / "pipeline" / "state.json").read_text(encoding="utf-8"))

    def test_skip_records_not_applicable_without_running_command(self) -> None:
        with self.workspace() as directory:
            root = Path(directory)
            (root / ".auditooor" / "inscope_units.jsonl").write_text(json.dumps({"file": "src/app.py", "lang": "python"}) + "\n", encoding="utf-8")
            marker = root / "ran"
            graph = manifest([step(0, produces=[], probe="rust", target=command(str(marker), "ran"))], [], [{"id": "rust", "kind": "language_any", "languages": ["rust"]}])
            result = executor.run_step(manifest_path=self.write_manifest(root, graph), workspace=root, step_id="step-0")
            self.assertTrue(result["ok"], result)
            self.assertEqual(self.state(root)["steps"]["step-0"]["state"], "not_applicable")
            self.assertFalse(marker.exists())

    def test_applicability_error_is_persisted_as_failed_receipt(self) -> None:
        with self.workspace() as directory:
            root = Path(directory)
            graph = manifest(
                [step(0, produces=[], probe="rust")],
                [],
                [{"id": "rust", "kind": "language_any", "languages": ["rust"]}],
            )
            result = executor.run_step(manifest_path=self.write_manifest(root, graph), workspace=root, step_id="step-0")
            self.assertFalse(result["ok"])
            self.assertIn("applicability_inventory_missing", result["diagnostics"])
            self.assertEqual(self.state(root)["steps"]["step-0"]["state"], "failed")
            receipt = json.loads((root / ".auditooor" / "pipeline" / "receipts" / "step-0" / "attempt-1.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["applicability"]["evaluation_error"]["kind"], "applicability_probe_evaluation_error")

    def test_zero_exit_with_warning_cannot_credit_a_canonical_step(self) -> None:
        with self.workspace() as directory:
            root = Path(directory)
            output = root / "result.json"
            body = (
                "from pathlib import Path; "
                f"Path(r'{output}').write_text('{{}}'); "
                "print('WARN legacy continuation')"
            )
            graph = manifest(
                [step(0, produces=["result"], target=[sys.executable, "-c", body])],
                [{"id": "result", "path": "result.json", "kind": "file", "validators": ["json"]}],
            )
            result = executor.run_step(manifest_path=self.write_manifest(root, graph), workspace=root, step_id="step-0")
            self.assertFalse(result["ok"])
            receipt = json.loads((root / ".auditooor" / "pipeline" / "receipts" / "step-0" / "attempt-1.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["status"], "failed")
            self.assertIn("command_emitted_nonterminal_warning_or_advisory", (root / ".auditooor" / "pipeline" / "logs" / "step-0" / "attempt-1.stderr").read_text(encoding="utf-8"))

    def test_reorder_persists_blocking_failed_receipt(self) -> None:
        with self.workspace() as directory:
            root = Path(directory)
            output = root / "result.json"
            graph = manifest([step(0, produces=["a"], target=command(str(output), "{}")), step(1, produces=[], consumes=["a"])], [{"id": "a", "path": "result.json", "kind": "file", "validators": ["json"]}])
            result = executor.run_step(manifest_path=self.write_manifest(root, graph), workspace=root, step_id="step-1")
            self.assertFalse(result["ok"])
            state = self.state(root)
            self.assertEqual(state["steps"]["step-0"]["state"], "failed")
            self.assertIn("out_of_order_request:expected=step-0:requested=step-1", result["diagnostics"])

    def test_command_failure_then_retry(self) -> None:
        with self.workspace() as directory:
            root = Path(directory)
            output = root / "result.json"
            marker = root / "retry-marker"
            retry_body = (
                f"from pathlib import Path; marker=Path(r'{marker}'); output=Path(r'{output}'); "
                "output.parent.mkdir(parents=True, exist_ok=True); "
                "first=not marker.exists(); marker.touch(); "
                "output.write_text('{}') if not first else None; raise SystemExit(7 if first else 0)"
            )
            graph = manifest([step(0, produces=["a"], target=[sys.executable, "-c", retry_body])], [{"id": "a", "path": "result.json", "kind": "file", "validators": ["json"]}])
            path = self.write_manifest(root, graph)
            self.assertFalse(executor.run_step(manifest_path=path, workspace=root, step_id="step-0")["ok"])
            result = executor.run_step(manifest_path=path, workspace=root, step_id="step-0")
            self.assertTrue(result["ok"], result)
            self.assertEqual(self.state(root)["steps"]["step-0"]["attempt"], 2)

    def test_changed_credited_output_invalidates_and_reruns_producer(self) -> None:
        with self.workspace() as directory:
            root = Path(directory)
            output, downstream = root / "result.json", root / "downstream.json"
            graph = manifest(
                [step(0, produces=["a"], target=command(str(output), "{}")), step(1, produces=["b"], consumes=["a"], target=command(str(downstream), "{}"))],
                [{"id": "a", "path": "result.json", "kind": "file", "validators": ["json"]}, {"id": "b", "path": "downstream.json", "kind": "file", "validators": ["json"]}],
            )
            path = self.write_manifest(root, graph)
            self.assertTrue(executor.run_step(manifest_path=path, workspace=root, step_id="step-0")["ok"])
            output.write_text('{"changed":true}', encoding="utf-8")
            result = executor.run_all(manifest_path=path, workspace=root)
            self.assertTrue(result["ok"], result)
            state = self.state(root)
            self.assertEqual(state["steps"]["step-0"]["attempt"], 2)
            self.assertEqual(state["steps"]["step-1"]["state"], "succeeded")
            self.assertTrue(any(row["source_step_id"] == "step-0" for row in state["invalidation_history"]))

    def test_consumer_input_mutation_before_acceptance_is_rejected(self) -> None:
        with self.workspace() as directory:
            root = Path(directory)
            source, downstream = root / "result.json", root / "downstream.json"
            mutation = (
                "from pathlib import Path; "
                f"Path(r'{source}').write_text('null', encoding='utf-8'); "
                f"Path(r'{downstream}').write_text('[]', encoding='utf-8')"
            )
            graph = manifest(
                [
                    step(0, produces=["a"], target=command(str(source), "{}")),
                    step(1, produces=["b"], consumes=["a"], target=[sys.executable, "-c", mutation]),
                ],
                [
                    {"id": "a", "path": "result.json", "kind": "file", "validators": ["json"]},
                    {"id": "b", "path": "downstream.json", "kind": "file", "validators": ["json"]},
                ],
            )
            path = self.write_manifest(root, graph)
            self.assertTrue(executor.run_step(manifest_path=path, workspace=root, step_id="step-0")["ok"])
            result = executor.run_step(manifest_path=path, workspace=root, step_id="step-1")
            self.assertFalse(result["ok"])
            self.assertIn("input_artifact_stale_on_disk:a", result["diagnostics"])
            state = self.state(root)
            self.assertEqual(state["steps"]["step-1"]["state"], "failed")
            self.assertIsNone(state["steps"]["step-1"]["current_receipt_id"])

    def test_malformed_output_contract_persists_failure(self) -> None:
        with self.workspace() as directory:
            root = Path(directory)
            graph = manifest([step(0, produces=["missing"])], [{"id": "missing", "path": "result.json", "kind": "file", "validators": "json"}])
            result = executor.run_step(manifest_path=self.write_manifest(root, graph), workspace=root, step_id="step-0")
            self.assertFalse(result["ok"])
            self.assertIn("artifact_contract_0_malformed", result["diagnostics"])
            self.assertEqual(self.state(root)["steps"]["step-0"]["state"], "failed")

    def test_scope_change_archives_prior_run_and_does_not_loop(self) -> None:
        with self.workspace() as directory:
            root = Path(directory)
            output = root / "result.json"
            graph = manifest([step(0, produces=["a"], target=command(str(output), "{}"))], [{"id": "a", "path": "result.json", "kind": "file", "validators": ["json"]}])
            path = self.write_manifest(root, graph)
            first = executor.run_step(manifest_path=path, workspace=root, step_id="step-0")
            self.assertTrue(first["ok"], first)
            prior_state = self.state(root)
            (root / "SCOPE.md").write_text("changed\n", encoding="utf-8")
            result = executor.run_step(manifest_path=path, workspace=root, step_id="step-0")
            self.assertTrue(result["ok"], result)
            self.assertTrue(result["rotated"])
            self.assertIn("run_rotated:scope_sha256_mismatch", result["diagnostics"])
            archive = Path(result["archive_path"])
            archived_state = json.loads((archive / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(archived_state["run_id"], prior_state["run_id"])
            self.assertTrue((archive / "receipts" / "step-0" / "attempt-1.json").is_file())
            self.assertNotEqual(self.state(root)["run_id"], prior_state["run_id"])
            archive_count = len(list((root / ".auditooor" / "pipeline" / "archive").iterdir()))
            resumed = executor.run_step(manifest_path=path, workspace=root, step_id="step-0")
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(len(list((root / ".auditooor" / "pipeline" / "archive").iterdir())), archive_count)

    def test_source_change_restarts_from_step_zero_without_downstream_credit(self) -> None:
        with self.workspace() as directory:
            root = Path(directory)
            first, second = root / "first.json", root / "second.json"
            graph = manifest(
                [step(0, produces=["a"], target=command(str(first), "{}")), step(1, produces=["b"], consumes=["a"], target=command(str(second), "{}"))],
                [{"id": "a", "path": "first.json", "kind": "file", "validators": ["json"]}, {"id": "b", "path": "second.json", "kind": "file", "validators": ["json"]}],
            )
            path = self.write_manifest(root, graph)
            self.assertTrue(executor.run_all(manifest_path=path, workspace=root)["ok"])
            prior = self.state(root)
            (root / "src" / "app.py").write_text("x = 2\n", encoding="utf-8")
            result = executor.run_all(manifest_path=path, workspace=root)
            self.assertTrue(result["ok"], result)
            current = self.state(root)
            self.assertNotEqual(current["run_id"], prior["run_id"])
            self.assertEqual(current["steps"]["step-0"]["attempt"], 1)
            self.assertEqual(current["steps"]["step-1"]["attempt"], 1)
            archived = json.loads((Path(result["archives"][0]) / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(archived["steps"]["step-1"]["state"], "succeeded")
            self.assertNotEqual(current["steps"]["step-1"]["current_receipt_id"], archived["steps"]["step-1"]["current_receipt_id"])

    def test_tooling_change_rotates_run_and_is_receipt_provenance(self) -> None:
        with self.workspace() as directory:
            root = Path(directory)
            output = root / "result.json"
            graph = manifest([step(0, produces=["a"], target=command(str(output), "{}"))], [{"id": "a", "path": "result.json", "kind": "file", "validators": ["json"]}])
            path = self.write_manifest(root, graph)
            tooling = {"hash": "1" * 64}
            with mock.patch.object(executor, "_pipeline_tooling_hash", side_effect=lambda _manifest: tooling["hash"]):
                self.assertTrue(executor.run_all(manifest_path=path, workspace=root)["ok"])
                prior = self.state(root)
                tooling["hash"] = "2" * 64
                result = executor.run_all(manifest_path=path, workspace=root)
            self.assertTrue(result["ok"], result)
            current = self.state(root)
            self.assertEqual(current["pipeline_tooling_sha256"], "2" * 64)
            self.assertNotEqual(current["run_id"], prior["run_id"])
            archived = json.loads((Path(result["archives"][0]) / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(archived["pipeline_tooling_sha256"], "1" * 64)
            receipt = json.loads((root / ".auditooor" / "pipeline" / "receipts" / "step-0" / "attempt-1.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["pipeline_tooling_sha256"], "2" * 64)
            self.assertEqual(receipt["tool_versions"]["pipeline_tooling_sha256"], "2" * 64)

    def test_severity_targets_and_program_rules_changes_rotate_credit(self) -> None:
        cases = (
            ("SEVERITY.md", "new severity\n", "severity_sha256_mismatch"),
            ("targets.tsv", "repo\tpin\tchanged\n", "targets_sha256_mismatch"),
            (".auditooor/program_rules.json", '{"changed":true}\n', "program_rules_sha256_mismatch"),
        )
        for relative, replacement, diagnostic in cases:
            with self.subTest(relative=relative), self.workspace() as directory:
                root = Path(directory)
                output = root / "result.json"
                graph = manifest([step(0, produces=["a"], target=command(str(output), "{}"))], [{"id": "a", "path": "result.json", "kind": "file", "validators": ["json"]}])
                path = self.write_manifest(root, graph)
                self.assertTrue(executor.run_step(manifest_path=path, workspace=root, step_id="step-0")["ok"])
                prior_run = self.state(root)["run_id"]
                (root / relative).write_text(replacement, encoding="utf-8")
                result = executor.run_step(manifest_path=path, workspace=root, step_id="step-0")
                self.assertTrue(result["ok"], result)
                self.assertIn(f"run_rotated:{diagnostic}", result["diagnostics"])
                self.assertNotEqual(self.state(root)["run_id"], prior_run)

    def test_workspace_identity_change_rotates_shared_state_authority(self) -> None:
        with self.workspace() as first_directory, self.workspace() as second_directory:
            first_root, second_root = Path(first_directory), Path(second_directory)
            body = "import sys; from pathlib import Path; Path(sys.argv[1]).write_text('{}')"
            graph = manifest(
                [step(0, produces=["a"], target=[sys.executable, "-c", body, "{workspace}/result.json"])],
                [{"id": "a", "path": "result.json", "kind": "file", "validators": ["json"]}],
            )
            path = self.write_manifest(first_root, graph)
            shared_state = first_root / ".auditooor" / "pipeline" / "state.json"
            self.assertTrue(executor.run_step(manifest_path=path, workspace=first_root, state_path=shared_state, step_id="step-0")["ok"])
            prior_run = self.state(first_root)["run_id"]
            result = executor.run_step(manifest_path=path, workspace=second_root, state_path=shared_state, step_id="step-0")
            self.assertTrue(result["ok"], result)
            self.assertIn("run_rotated:workspace_identity_sha256_mismatch", result["diagnostics"])
            current = self.state(first_root)
            self.assertNotEqual(current["run_id"], prior_run)
            self.assertEqual(current["workspace_identity_sha256"], executor.current_baselines(second_root)["workspace_identity_sha256"])

    def test_resume_and_run_all_closeout(self) -> None:
        with self.workspace() as directory:
            root = Path(directory)
            first, second = root / "first.json", root / "second.json"
            graph = manifest(
                [step(0, produces=["a"], target=command(str(first), "{}")), step(1, produces=["b"], consumes=["a"], target=command(str(second), "{}"))],
                [{"id": "a", "path": "first.json", "kind": "file", "validators": ["json"]}, {"id": "b", "path": "second.json", "kind": "file", "validators": ["json"]}],
            )
            path = self.write_manifest(root, graph)
            self.assertTrue(executor.run_step(manifest_path=path, workspace=root, step_id="step-0")["ok"])
            result = executor.run_all(manifest_path=path, workspace=root)
            self.assertTrue(result["ok"], result)
            self.assertTrue(result["closeout"]["valid"])
            self.assertEqual(self.state(root)["steps"]["step-1"]["state"], "succeeded")

    def test_resume_converts_interrupted_running_attempt_to_failed_receipt(self) -> None:
        with self.workspace() as directory:
            root = Path(directory)
            output = root / "result.json"
            graph = manifest([step(0, produces=["a"], target=command(str(output), "{}"))], [{"id": "a", "path": "result.json", "kind": "file", "validators": ["json"]}])
            path = self.write_manifest(root, graph)
            execution_graph = executor._execution_manifest(graph, root.resolve())
            baselines = executor.current_baselines(root)
            baselines["pipeline_tooling_sha256"] = execution_graph["_pipeline_tooling_sha256"]
            state = executor._machine.initialize_state(execution_graph, run_id=executor._run_id(execution_graph, baselines), **baselines)
            token = executor._machine.start_step(state, execution_graph, "step-0")
            state_path = root / ".auditooor" / "pipeline" / "state.json"
            executor._machine.write_state(state_path, state)
            executor._write_token(executor._token_path(state_path, "step-0", 1), token)
            result = executor.run_step(manifest_path=path, workspace=root, step_id="step-0")
            self.assertFalse(result["ok"])
            self.assertIn("interrupted_running_step", result["diagnostics"])
            self.assertEqual(self.state(root)["steps"]["step-0"]["state"], "failed")

    def test_makefile_facing_cli_defaults_state_and_returns_json(self) -> None:
        with self.workspace() as directory:
            root = Path(directory)
            output = root / "result.json"
            graph = manifest([step(0, produces=["a"], target=command(str(output), "{}"))], [{"id": "a", "path": "result.json", "kind": "file", "validators": ["json"]}])
            output_stream = io.StringIO()
            with redirect_stdout(output_stream):
                rc = executor.main(["--workspace", str(root), "--manifest", str(self.write_manifest(root, graph)), "run-all"])
            self.assertEqual(rc, 0)
            result = json.loads(output_stream.getvalue())
            self.assertTrue(result["ok"])
            self.assertEqual(result["state_path"], str((root / ".auditooor" / "pipeline" / "state.json").resolve()))

    def test_environment_passthrough_and_expanded_argv_are_receipted(self) -> None:
        with self.workspace() as directory, mock.patch.dict(os.environ, {"AUDITOOOR_LLM_HUNT": "1", "SOURCE_ONLY": "yes", "GITHUB_ONLY": "no", "PIPELINE_FORCE": "true", "UNDECLARED_SECRET": "blocked"}, clear=False):
            root = Path(directory)
            output = root / "result.json"
            body = "import json, os, sys; from pathlib import Path; keys=['AUDITOOOR_LLM_HUNT','SOURCE_ONLY','GITHUB_ONLY','PIPELINE_FORCE','UNDECLARED_SECRET']; Path(sys.argv[1]).write_text(json.dumps(dict((key, os.environ.get(key)) for key in keys)))"
            graph = manifest(
                [step(0, produces=["a"], target=[sys.executable, "-c", body, "{workspace}/result.json"])],
                [{"id": "a", "path": "result.json", "kind": "file", "validators": ["json"]}],
            )
            graph["environment_passthrough"] = ["PIPELINE_FORCE", "GITHUB_ONLY", "AUDITOOOR_LLM_HUNT", "SOURCE_ONLY"]
            path = self.write_manifest(root, graph)
            result = executor.run_step(manifest_path=path, workspace=root, step_id="step-0")
            self.assertTrue(result["ok"], result)
            executed = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(executed["AUDITOOOR_LLM_HUNT"], "1")
            self.assertIsNone(executed["UNDECLARED_SECRET"])
            receipt = json.loads((root / ".auditooor" / "pipeline" / "receipts" / "step-0" / "attempt-1.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["argv"][-1], str(root.resolve() / "result.json"))
            self.assertNotIn("UNDECLARED_SECRET", receipt["selected_environment"])
            self.assertEqual(receipt["selected_environment"]["PIPELINE_FORCE"], "true")
            self.assertEqual(receipt["selected_environment"]["AUDITOOOR_LLM_HUNT"], "1")
            with self.assertRaises(executor.ExecutorError):
                executor._execution_environment({"environment_passthrough": ["UNSAFE_SECRET"]})

    def test_source_snapshot_uses_inventory_then_nested_target_registry(self) -> None:
        with self.workspace() as directory:
            root = Path(directory)
            nested = root / "src" / "nested"
            nested.mkdir()
            tracked, ignored = nested / "tracked.sol", root / "src" / "ignored.sol"
            tracked.write_text("one", encoding="utf-8")
            ignored.write_text("one", encoding="utf-8")
            (root / "targets.tsv").write_text("repo\tpin\tnested\n", encoding="utf-8")
            fallback = executor.current_baselines(root)["source_snapshot_sha256"]
            tracked.write_text("two", encoding="utf-8")
            self.assertNotEqual(fallback, executor.current_baselines(root)["source_snapshot_sha256"])
            (root / ".auditooor" / "inscope_units.jsonl").write_text(json.dumps({"file": "src/nested/tracked.sol", "lang": "solidity"}) + "\n", encoding="utf-8")
            inventory = executor.current_baselines(root)["source_snapshot_sha256"]
            ignored.write_text("changed-but-unscoped", encoding="utf-8")
            self.assertEqual(inventory, executor.current_baselines(root)["source_snapshot_sha256"])
            tracked.write_text("three", encoding="utf-8")
            self.assertNotEqual(inventory, executor.current_baselines(root)["source_snapshot_sha256"])

    def test_directory_artifact_has_deterministic_content_hash_and_size(self) -> None:
        with self.workspace() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            bundle.mkdir()
            (bundle / "a.txt").write_text("a", encoding="utf-8")
            (bundle / "nested").mkdir()
            (bundle / "nested" / "b.txt").write_text("bc", encoding="utf-8")
            contract = {
                "id": "bundle",
                "path": bundle,
                "kind": "directory",
                "validators": ["directory_exists", "file_nonempty"],
            }
            first, errors = executor._artifact_row(contract, root)
            self.assertFalse(errors)
            self.assertEqual(first["size"], 3)
            (bundle / "nested" / "b.txt").write_text("bcd", encoding="utf-8")
            second, errors = executor._artifact_row(contract, root)
            self.assertFalse(errors)
            self.assertNotEqual(first["sha256"], second["sha256"])
            self.assertEqual(second["size"], 4)
            mismatched = {**contract, "validators": ["file_exists"]}
            _row, errors = executor._artifact_row(mismatched, root)
            self.assertEqual(errors, ["artifact_validator_failed:bundle:file_exists"])

    def test_consumes_artifact_from_transitive_dependency_ancestor(self) -> None:
        with self.workspace() as directory:
            root = Path(directory)
            first, second, third = root / "a.json", root / "b.json", root / "c.json"
            steps = [
                step(0, produces=["a"], target=command(str(first), "{}")),
                step(1, produces=["b"], target=command(str(second), "{}")),
                step(2, produces=["c"], consumes=["a"], target=command(str(third), "{}")),
            ]
            steps[2]["depends_on"] = ["step-1"]
            graph = manifest(steps, [
                {"id": "a", "path": "a.json", "kind": "file", "validators": ["json"]},
                {"id": "b", "path": "b.json", "kind": "file", "validators": ["json"]},
                {"id": "c", "path": "c.json", "kind": "file", "validators": ["json"]},
            ])
            result = executor.run_all(manifest_path=self.write_manifest(root, graph), workspace=root)
            self.assertTrue(result["ok"], result)
            receipt = json.loads((root / ".auditooor" / "pipeline" / "receipts" / "step-2" / "attempt-1.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["input_artifacts"][0]["artifact_contract"], "a")

    def test_awareness_ledger_validator_rejects_json_without_semantic_completion(self) -> None:
        with self.workspace() as directory:
            root = Path(directory)
            path = root / "awareness.json"
            path.write_text(json.dumps({"schema": "auditooor.awareness_ledger.v1"}), encoding="utf-8")
            contract = {
                "id": "awareness", "path": path, "kind": "file",
                "validators": ["awareness_ledger"], "freshness_policy": "must_refresh",
            }
            _row, errors = executor._artifact_row(contract, root)
            self.assertEqual(errors, ["artifact_validator_failed:awareness:awareness_ledger"])

            pin = "commit:test"
            rows = [
                {
                    "source_id": f"source-{index}", "source_kind": kind,
                    "pin_binding": pin, "content": "reviewed source evidence",
                    "source_ref": f"https://example.test/{kind}/{index}",
                    "content_sha256": hashlib.sha256(b"reviewed source evidence").hexdigest(),
                    "awareness_state": "team_aware",
                }
                for index, kind in enumerate(sorted(executor._awareness.SOURCE_KINDS))
            ]
            source_ids = [row["source_id"] for row in rows]
            complete = executor._awareness.build_ledger({
                "audit_pin": pin,
                "expected_sources": [{
                    "source_id": row["source_id"], "source_kind": row["source_kind"],
                    "source_ref": row["source_ref"], "pin_binding": row["pin_binding"],
                } for row in rows],
                "evidence_rows": rows,
                "candidates": [{
                    "candidate_id": "reviewed-known", "source_ids": source_ids,
                    "pin_binding": pin, "root_cause": "binding omitted",
                    "affected_path": "entry -> transfer", "required_fix": "bind transfer",
                    "reviewer_rationale": "reviewed exact source set",
                    "semantic_review": {
                        "reviewer_id": "reviewer", "reviewed_at": "2026-07-18T10:00:00Z",
                        "method": "semantic review", "rationale": "known issue",
                        "source_ids": source_ids,
                    },
                }],
            })
            path.write_text(json.dumps(complete), encoding="utf-8")
            _row, errors = executor._artifact_row(contract, root)
            self.assertEqual(errors, [])

    def test_zero_exit_with_untouched_old_output_cannot_succeed(self) -> None:
        with self.workspace() as directory:
            root = Path(directory)
            output = root / "result.json"
            output.write_text("{}", encoding="utf-8")
            graph = manifest(
                [step(0, produces=["a"], target=[sys.executable, "-c", "pass"])],
                [{"id": "a", "path": "result.json", "kind": "file", "validators": ["json"]}],
            )
            result = executor.run_step(manifest_path=self.write_manifest(root, graph), workspace=root, step_id="step-0")
            self.assertFalse(result["ok"])
            self.assertIn("output_not_refreshed:a", result["diagnostics"])
            self.assertEqual(self.state(root)["steps"]["step-0"]["state"], "failed")

    def test_recreated_identical_output_is_fresh(self) -> None:
        with self.workspace() as directory:
            root = Path(directory)
            output = root / "result.json"
            output.write_text("{}", encoding="utf-8")
            body = f"from pathlib import Path; path=Path(r'{output}'); path.unlink(); path.write_text('{{}}')"
            graph = manifest(
                [step(0, produces=["a"], target=[sys.executable, "-c", body])],
                [{"id": "a", "path": "result.json", "kind": "file", "validators": ["json"]}],
            )
            result = executor.run_step(manifest_path=self.write_manifest(root, graph), workspace=root, step_id="step-0")
            self.assertTrue(result["ok"], result)

    def test_validate_existing_requires_explicit_manual_intake_policy(self) -> None:
        with self.workspace() as directory:
            root = Path(directory)
            output = root / "attestation.json"
            output.write_text("{}", encoding="utf-8")
            validation_step = step(0, produces=["attestation"], target=[sys.executable, "-c", "pass"])
            validation_step["phase"] = "intake"
            validation_step["class"] = "manual-judgment"
            validation_step["how_to_verify_done"] = {"attestation_required": True}
            graph = manifest(
                [validation_step],
                [{"id": "attestation", "path": "attestation.json", "kind": "file", "validators": ["json"], "freshness_policy": "validate_existing"}],
            )
            result = executor.run_step(manifest_path=self.write_manifest(root, graph), workspace=root, step_id="step-0")
            self.assertTrue(result["ok"], result)

    def test_validate_existing_is_rejected_outside_manual_intake(self) -> None:
        with self.workspace() as directory:
            root = Path(directory)
            output = root / "result.json"
            output.write_text("{}", encoding="utf-8")
            graph = manifest(
                [step(0, produces=["a"], target=[sys.executable, "-c", "pass"])],
                [{"id": "a", "path": "result.json", "kind": "file", "validators": ["json"], "freshness_policy": "validate_existing"}],
            )
            result = executor.run_step(manifest_path=self.write_manifest(root, graph), workspace=root, step_id="step-0")
            self.assertFalse(result["ok"])
            self.assertIn("validate_existing_not_manual_intake:a", result["diagnostics"])

    def test_failed_refresh_preserves_old_artifact_archive(self) -> None:
        with self.workspace() as directory:
            root = Path(directory)
            output = root / "result.json"
            old = '{"old":true}'
            output.write_text(old, encoding="utf-8")
            graph = manifest(
                [step(0, produces=["a"], target=[sys.executable, "-c", "raise SystemExit(7)"])],
                [{"id": "a", "path": "result.json", "kind": "file", "validators": ["json"]}],
            )
            result = executor.run_step(manifest_path=self.write_manifest(root, graph), workspace=root, step_id="step-0")
            self.assertFalse(result["ok"])
            self.assertIn("command_exit_nonzero:7", result["diagnostics"])
            archived = list((root / ".auditooor" / "pipeline" / "attempt-output-baselines" / "step-0" / "attempt-1").glob("*/artifact"))
            self.assertEqual(len(archived), 1)
            self.assertEqual(archived[0].read_text(encoding="utf-8"), old)
            self.assertEqual(output.read_text(encoding="utf-8"), old)


if __name__ == "__main__":
    unittest.main()
