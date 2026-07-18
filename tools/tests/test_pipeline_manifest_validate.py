from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "pipeline-manifest-validate.py"
SPEC = importlib.util.spec_from_file_location("pipeline_manifest_validate", TOOL)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _base_manifest() -> dict:
    steps = []
    for idx in range(69):
        step_id = f"step-{idx:02d}"
        produces = [f"artifact-{idx:02d}"]
        consumes = [f"artifact-{idx - 1:02d}"] if idx > 0 else []
        depends_on = [f"step-{idx - 1:02d}"] if idx > 0 else []
        phase = "reasoning" if idx == 34 else "drive"
        validators = ["validator.core"]
        step = {
            "step_id": step_id,
            "order_index": idx,
            "run_sequence": idx,
            "phase": phase,
            "execution_target": ["python3", "tools/pipeline-manifest-validate.py", "--manifest", "{workspace}/manifest.json"],
            "applicability_probe": "probe.always",
            "depends_on": depends_on,
            "consumes": consumes,
            "produces": produces,
            "validators": validators,
            "invalidates": [f"step-{idx + 1:02d}"] if idx == 10 else [],
            "terminal_output": idx == 68,
            "required": True,
            "how_to_verify_done": {
                "artifact_checks": [{"type": "file_exists"}] if idx == 0 else [],
            },
        }
        steps.append(step)
    artifact_contracts = [
        {
            "id": f"artifact-{idx:02d}",
            "path": f".auditooor/test/artifact-{idx:02d}.json",
            "kind": "file",
            "validators": ["validator.core"],
            "producer_step_ids": [f"step-{idx:02d}"],
            "consumer_step_ids": [f"step-{idx + 1:02d}"] if idx < 68 else [],
            "terminal": idx == 68,
        }
        for idx in range(69)
    ]
    return {
        "schema": "auditooor.pipeline_manifest.v2",
        "expected_step_count": 69,
        "steps": steps,
        "execution_target_registry": [
            {"step_id": step["step_id"], "argv": list(step["execution_target"])}
            for step in steps
        ],
        "execution_placeholders": [
            {"id": "workspace", "token": "{workspace}", "source": "executor.workspace_root"},
        ],
        "environment_passthrough": ["PIPELINE_FORCE", "PIPELINE_STRICT"],
        "applicability_probes": [{"id": "probe.always", "kind": "always"}],
        "validators": [{"id": "validator.core", "kind": "file_exists"}],
        "legacy_artifact_check_types": [{"id": "file_exists"}],
        "legacy_artifact_checks": [
            {"step_id": "step-00", "check_type": "file_exists"},
        ],
        "artifact_contracts": artifact_contracts,
        "reasoner_registry": [
            {"id": "reasoner.synthetic", "step_id": "step-34", "ledger_artifact": "artifact-34"},
        ],
        "reasoner_routes": [
            {
                "reasoner_id": "reasoner.synthetic",
                "step_id": "step-34",
                "ledger_artifact": "artifact-34",
                "producer_step_id": "step-34",
                "consumer_step_ids": ["step-35"],
                "queue_step_id": "step-35",
                "question_step_id": "step-35",
                "proof_step_id": "step-35",
                "resolution_step_id": "step-35",
            }
        ],
    }


def _mixed_order_manifest() -> dict:
    manifest = _base_manifest()
    manifest["steps"][0]["order_index"] = 5
    manifest["steps"][1]["order_index"] = 0
    manifest["steps"][2]["order_index"] = 1
    manifest["steps"][3]["order_index"] = 2
    manifest["steps"][4]["order_index"] = 3
    manifest["steps"][5]["order_index"] = 4
    return manifest


def _write_manifest(manifest: dict) -> str:
    handle = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    try:
        json.dump(manifest, handle)
        handle.flush()
        return handle.name
    finally:
        handle.close()


def _run_cli(manifest: dict) -> tuple[int, dict]:
    path = _write_manifest(manifest)
    try:
        proc = subprocess.run(
            ["python3", str(TOOL), "--manifest", path],
            capture_output=True,
            text=True,
        )
        return proc.returncode, json.loads(proc.stdout)
    finally:
        Path(path).unlink(missing_ok=True)


def _codes(result: dict) -> set[str]:
    return {item["code"] for item in result["diagnostics"]}


class PipelineManifestValidateTests(unittest.TestCase):
    def test_valid_synthetic_69_step_graph(self) -> None:
        result = MODULE.validate_manifest(_base_manifest())
        self.assertTrue(result["valid"], json.dumps(result, indent=2))
        self.assertEqual(result["error_count"], 0)

    def test_valid_when_order_index_differs_from_run_sequence(self) -> None:
        result = MODULE.validate_manifest(_mixed_order_manifest())
        self.assertTrue(result["valid"], json.dumps(result, indent=2))

    def test_cli_returns_zero_for_valid_manifest(self) -> None:
        rc, result = _run_cli(_base_manifest())
        self.assertEqual(rc, 0, json.dumps(result, indent=2))
        self.assertTrue(result["valid"])

    def test_malformed_top_level_shape_rejected(self) -> None:
        result = MODULE.validate_manifest([])
        self.assertFalse(result["valid"])
        self.assertIn("MALFORMED_TOP_LEVEL", _codes(result))

    def test_manifest_schema_is_required(self) -> None:
        manifest = _base_manifest()
        del manifest["schema"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("INVALID_MANIFEST_SCHEMA", _codes(result))

    def test_expected_step_count_must_match_steps(self) -> None:
        manifest = _base_manifest()
        manifest["expected_step_count"] = 68
        result = MODULE.validate_manifest(manifest)
        self.assertIn("MISMATCHED_EXPECTED_STEP_COUNT", _codes(result))

    def test_expected_step_count_must_be_positive(self) -> None:
        manifest = _base_manifest()
        manifest["expected_step_count"] = 0
        result = MODULE.validate_manifest(manifest)
        self.assertIn("INVALID_EXPECTED_STEP_COUNT", _codes(result))

    def test_missing_required_step_field_rejected(self) -> None:
        manifest = _base_manifest()
        del manifest["steps"][1]["execution_target"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("MISSING_STEP_FIELD", _codes(result))

    def test_duplicate_step_id_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][1]["step_id"] = manifest["steps"][0]["step_id"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("DUPLICATE_STEP_ID", _codes(result))

    def test_duplicate_order_index_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][2]["order_index"] = manifest["steps"][1]["order_index"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("DUPLICATE_ORDER_INDEX", _codes(result))

    def test_non_contiguous_order_indexes_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][5]["order_index"] = 99
        result = MODULE.validate_manifest(manifest)
        self.assertIn("NON_CONTIGUOUS_ORDER_INDEX", _codes(result))

    def test_duplicate_run_sequence_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][2]["run_sequence"] = manifest["steps"][1]["run_sequence"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("DUPLICATE_RUN_SEQUENCE", _codes(result))

    def test_non_contiguous_run_sequence_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][5]["run_sequence"] = 99
        result = MODULE.validate_manifest(manifest)
        self.assertIn("NON_CONTIGUOUS_RUN_SEQUENCE", _codes(result))

    def test_invalid_execution_target_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][3]["execution_target"] = [""]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("INVALID_EXECUTION_TARGET", _codes(result))

    def test_unregistered_execution_target_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][3]["execution_target"] = ["python3", "tools/not-a-real-target.py"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("UNKNOWN_EXECUTION_TARGET", _codes(result))

    def test_nonexistent_make_target_rejected_even_when_registered(self) -> None:
        manifest = _base_manifest()
        target = ["make", "target-that-does-not-exist", "WS={workspace}"]
        manifest["steps"][3]["execution_target"] = target
        manifest["execution_target_registry"][3]["argv"] = target
        result = MODULE.validate_manifest(manifest)
        self.assertIn("UNKNOWN_EXECUTION_TARGET", _codes(result))

    def test_unknown_target_placeholder_rejected(self) -> None:
        manifest = _base_manifest()
        target = ["python3", "tools/pipeline-manifest-validate.py", "--manifest", "{other}/manifest.json"]
        manifest["steps"][3]["execution_target"] = target
        manifest["execution_target_registry"][3]["argv"] = target
        result = MODULE.validate_manifest(manifest)
        self.assertIn("UNKNOWN_TARGET_PLACEHOLDER", _codes(result))

    def test_false_optionality_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][3]["required"] = False
        result = MODULE.validate_manifest(manifest)
        self.assertIn("FALSE_OPTIONALITY", _codes(result))

    def test_environment_passthrough_must_be_sorted_unique_and_secret_free(self) -> None:
        manifest = _base_manifest()
        manifest["environment_passthrough"] = ["PIPELINE_STRICT", "API_KEY", "PIPELINE_STRICT"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("SECRET_ENVIRONMENT_PASSTHROUGH", _codes(result))
        self.assertIn("DUPLICATE_ENVIRONMENT_PASSTHROUGH", _codes(result))
        self.assertIn("UNSORTED_ENVIRONMENT_PASSTHROUGH", _codes(result))

    def test_unknown_applicability_probe_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][4]["applicability_probe"] = "probe.unknown"
        result = MODULE.validate_manifest(manifest)
        self.assertIn("UNKNOWN_APPLICABILITY_PROBE", _codes(result))

    def test_applicability_registry_requires_explicit_object_definitions(self) -> None:
        manifest = _base_manifest()
        manifest["applicability_probes"] = ["probe.always"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("MALFORMED_APPLICABILITY_PROBE", _codes(result))

    def test_applicability_registry_rejects_unknown_kind_and_old_never_builtin(self) -> None:
        manifest = _base_manifest()
        manifest["applicability_probes"] = [{"id": "probe.always", "kind": "never"}]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("UNKNOWN_APPLICABILITY_PROBE_KIND", _codes(result))
        self.assertIn("UNKNOWN_APPLICABILITY_PROBE", _codes(result))

        manifest = _base_manifest()
        manifest["steps"][0]["applicability_probe"] = "never"
        result = MODULE.validate_manifest(manifest)
        self.assertIn("UNKNOWN_APPLICABILITY_PROBE", _codes(result))

    def test_language_any_registry_requires_sorted_unique_canonical_languages(self) -> None:
        manifest = _base_manifest()
        manifest["applicability_probes"] = [{"id": "probe.always", "kind": "language_any", "languages": ["Solidity", "EVM"]}]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("DUPLICATE_APPLICABILITY_LANGUAGE", _codes(result))

        manifest = _base_manifest()
        manifest["applicability_probes"] = [{"id": "probe.always", "kind": "language_any", "languages": ["Solidity", "go"]}]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("UNSORTED_APPLICABILITY_LANGUAGES", _codes(result))

        manifest = _base_manifest()
        manifest["applicability_probes"] = [{"id": "probe.always", "kind": "language_any", "languages": []}]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("MALFORMED_APPLICABILITY_LANGUAGES", _codes(result))

    def test_applicability_registry_rejects_duplicate_aliases(self) -> None:
        manifest = _base_manifest()
        manifest["applicability_probes"] = [
            {"id": "probe.always", "kind": "always", "aliases": ["common"]},
            {"id": "probe.other", "kind": "always", "aliases": ["common"]},
        ]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("DUPLICATE_APPLICABILITY_ALIAS", _codes(result))

    def test_unknown_validator_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][4]["validators"] = ["validator.unknown"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("UNKNOWN_VALIDATOR", _codes(result))

    def test_unknown_legacy_artifact_check_type_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["legacy_artifact_checks"][0]["check_type"] = "totally_unknown"
        result = MODULE.validate_manifest(manifest)
        self.assertIn("UNKNOWN_LEGACY_ARTIFACT_CHECK_TYPE", _codes(result))

    def test_unknown_step_artifact_check_type_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][0]["how_to_verify_done"]["artifact_checks"] = [{"type": "totally_unknown"}]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("UNKNOWN_LEGACY_ARTIFACT_CHECK_TYPE", _codes(result))

    def test_duplicate_dependency_entry_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][7]["depends_on"] = ["step-06", "step-06"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("DUPLICATE_DEPENDENCY_ENTRY", _codes(result))

    def test_duplicate_consumes_entry_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][7]["consumes"] = ["artifact-06", "artifact-06"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("DUPLICATE_CONSUMES_ENTRY", _codes(result))

    def test_duplicate_produces_entry_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][7]["produces"] = ["artifact-07", "artifact-07"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("DUPLICATE_PRODUCES_ENTRY", _codes(result))

    def test_duplicate_validator_entry_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][7]["validators"] = ["validator.core", "validator.core"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("DUPLICATE_VALIDATOR_ENTRY", _codes(result))

    def test_duplicate_invalidates_entry_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][10]["invalidates"] = ["step-11", "step-11"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("DUPLICATE_INVALIDATES_ENTRY", _codes(result))

    def test_missing_dependency_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][6]["depends_on"] = []
        result = MODULE.validate_manifest(manifest)
        self.assertIn("MISSING_DEPENDENCY", _codes(result))

    def test_unknown_dependency_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][7]["depends_on"] = ["step-does-not-exist"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("UNKNOWN_DEPENDENCY", _codes(result))

    def test_self_dependency_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][8]["depends_on"] = ["step-08"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("SELF_DEPENDENCY", _codes(result))

    def test_forward_dependency_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][8]["depends_on"] = ["step-09"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("FORWARD_DEPENDENCY", _codes(result))

    def test_forward_dependency_uses_run_sequence_not_order_index(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][8]["order_index"] = 9
        manifest["steps"][9]["order_index"] = 8
        manifest["steps"][8]["depends_on"] = ["step-09"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("FORWARD_DEPENDENCY", _codes(result))

    def test_dependency_cycle_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][0]["depends_on"] = ["step-01"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("DEPENDENCY_CYCLE", _codes(result))

    def test_consumed_artifact_without_producer_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][12]["consumes"] = ["artifact-missing"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("MISSING_PRODUCER", _codes(result))

    def test_unknown_artifact_contract_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][12]["consumes"] = ["artifact-unregistered"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("UNKNOWN_ARTIFACT_CONTRACT", _codes(result))

    def test_malformed_artifact_contract_path_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["artifact_contracts"][12]["path"] = "../outside.json"
        result = MODULE.validate_manifest(manifest)
        self.assertIn("MALFORMED_ARTIFACT_PATH", _codes(result))

    def test_unknown_artifact_freshness_policy_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["artifact_contracts"][12]["freshness_policy"] = "trust_existing"
        result = MODULE.validate_manifest(manifest)
        self.assertIn("MALFORMED_ARTIFACT_FRESHNESS_POLICY", _codes(result))

    def test_validate_existing_requires_attested_manual_intake_producer(self) -> None:
        manifest = _base_manifest()
        manifest["artifact_contracts"][0]["freshness_policy"] = "validate_existing"
        result = MODULE.validate_manifest(manifest)
        self.assertIn("INVALID_VALIDATE_EXISTING_POLICY", _codes(result))

        manifest["steps"][0]["phase"] = "intake"
        manifest["steps"][0]["class"] = "manual-judgment"
        manifest["steps"][0]["how_to_verify_done"]["attestation_required"] = True
        result = MODULE.validate_manifest(manifest)
        self.assertNotIn("INVALID_VALIDATE_EXISTING_POLICY", _codes(result))

    def test_artifact_contract_route_registry_must_match_graph(self) -> None:
        manifest = _base_manifest()
        manifest["artifact_contracts"][12]["consumer_step_ids"] = []
        result = MODULE.validate_manifest(manifest)
        self.assertIn("ARTIFACT_CONSUMER_REGISTRY_MISMATCH", _codes(result))

    def test_consumed_artifact_producer_must_precede_consumer(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][10]["consumes"] = ["artifact-11"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("FUTURE_PRODUCER", _codes(result))

    def test_consumed_artifact_producer_must_be_dependency_ancestor(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][11]["depends_on"] = ["step-08"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("MISSING_DEPENDENCY_PATH", _codes(result))

    def test_duplicate_producers_without_merge_semantics_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][12]["produces"] = ["artifact-10"]
        manifest["steps"][13]["consumes"] = ["artifact-10"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("DUPLICATE_PRODUCERS", _codes(result))

    def test_orphan_produced_artifact_requires_terminal_output(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][20]["produces"] = ["artifact-orphan"]
        manifest["steps"][21]["consumes"] = ["artifact-20"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("ORPHAN_PRODUCED_ARTIFACT", _codes(result))

    def test_terminal_output_requires_produced_artifact(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][20]["produces"] = []
        manifest["steps"][20]["terminal_output"] = True
        result = MODULE.validate_manifest(manifest)
        self.assertIn("EMPTY_TERMINAL_OUTPUT", _codes(result))

    def test_invalid_invalidates_reference_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][10]["invalidates"] = ["step-09"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("INVALID_INVALIDATES_REFERENCE", _codes(result))

    def test_reasoning_step_requires_reasoner_route(self) -> None:
        manifest = _base_manifest()
        manifest["reasoner_routes"] = []
        result = MODULE.validate_manifest(manifest)
        self.assertIn("MISSING_REASONER_ROUTE", _codes(result))

    def test_reasoning_step_rejects_duplicate_reasoner_routes(self) -> None:
        manifest = _base_manifest()
        manifest["reasoner_routes"].append(
            {
                "reasoner_id": "reasoner.synthetic",
                "step_id": "step-34",
                "ledger_artifact": "artifact-34",
                "producer_step_id": "step-34",
                "consumer_step_ids": ["step-35"],
                "queue_step_id": "step-35",
                "question_step_id": "step-35",
                "proof_step_id": "step-35",
                "resolution_step_id": "step-35",
            }
        )
        result = MODULE.validate_manifest(manifest)
        self.assertIn("DUPLICATE_REASONER_ROUTE", _codes(result))

    def test_incomplete_reasoner_route_rejected(self) -> None:
        manifest = _base_manifest()
        manifest["reasoner_routes"][0]["consumer_step_ids"] = []
        result = MODULE.validate_manifest(manifest)
        self.assertIn("INCOMPLETE_REASONER_ROUTE", _codes(result))

    def test_reasoner_route_requires_every_downstream_route(self) -> None:
        manifest = _base_manifest()
        del manifest["reasoner_routes"][0]["proof_step_id"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("INCOMPLETE_REASONER_ROUTE", _codes(result))

    def test_reasoner_route_consumer_must_consume_declared_ledger(self) -> None:
        manifest = _base_manifest()
        manifest["reasoner_routes"][0]["consumer_step_ids"] = ["step-10"]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("INVALID_REASONER_ROUTE", _codes(result))

    def test_merge_semantics_must_name_all_duplicate_producers(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][12]["produces"] = ["artifact-10"]
        manifest["steps"][13]["consumes"] = ["artifact-10"]
        manifest["merge_semantics"] = [
            {
                "artifact_contract": "artifact-10",
                "name": "merge-join",
                "producers": ["step-10"],
            }
        ]
        result = MODULE.validate_manifest(manifest)
        self.assertIn("INCOMPLETE_MERGE_SEMANTICS", _codes(result))

    def test_duplicate_producers_with_complete_merge_semantics_are_allowed(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][11]["consumes"] = ["artifact-09"]
        manifest["steps"][12]["produces"] = ["artifact-10"]
        manifest["steps"][13]["consumes"] = ["artifact-10"]
        manifest["merge_semantics"] = [
            {
                "artifact_contract": "artifact-10",
                "name": "merge-join",
                "producers": ["step-10", "step-12"],
            }
        ]
        manifest["artifact_contracts"] = [
            row for row in manifest["artifact_contracts"] if row["id"] != "artifact-12"
        ]
        artifact_10 = next(row for row in manifest["artifact_contracts"] if row["id"] == "artifact-10")
        artifact_10["producer_step_ids"] = ["step-10", "step-12"]
        artifact_10["consumer_step_ids"] = ["step-13"]
        artifact_09 = next(row for row in manifest["artifact_contracts"] if row["id"] == "artifact-09")
        artifact_09["consumer_step_ids"] = ["step-10", "step-11"]
        result = MODULE.validate_manifest(manifest)
        self.assertTrue(result["valid"], json.dumps(result, indent=2))

    def test_diagnostics_are_sorted_deterministically(self) -> None:
        manifest = _base_manifest()
        manifest["steps"][4]["validators"] = ["validator.unknown"]
        manifest["steps"][3]["applicability_probe"] = "probe.unknown"
        result = MODULE.validate_manifest(manifest)
        paths = [item["path"] for item in result["diagnostics"]]
        self.assertEqual(paths, sorted(paths))


if __name__ == "__main__":
    unittest.main()
