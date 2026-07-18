from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "pipeline-receipt.py"
SPEC = importlib.util.spec_from_file_location("pipeline_receipt", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
pipeline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pipeline)


class PipelineReceiptTest(unittest.TestCase):
    def make_receipt(
        self,
        status: str = "succeeded",
        *,
        applicability_error_diagnostics: list[str] | None = None,
    ) -> dict:
        return pipeline.build_receipt(
            run_id="run-1",
            manifest_sha256="1" * 64,
            workspace_identity_sha256="2" * 64,
            source_snapshot_sha256="3" * 64,
            scope_sha256="4" * 64,
            severity_sha256="5" * 64,
            targets_sha256="6" * 64,
            program_rules_sha256="7" * 64,
            pipeline_tooling_sha256="8" * 64,
            step_id="step-1",
            order_index=0,
            attempt=1,
            step_token="d" * 64,
            status=status,
            applicability_probe_id="probe-1",
            applicability_inputs={"target": "fixture", "enabled": True},
            applicability_result=status != "not_applicable",
            applicability_error_diagnostics=applicability_error_diagnostics,
            argv=["python3", "-c", "pass"],
            selected_environment={"LANG": "C", "PATH": "/usr/bin"},
            started_at="2026-07-17T10:00:00+00:00",
            finished_at=None if status == "running" else "2026-07-17T10:00:01+00:00",
            exit_code=None if status == "running" else (1 if status == "failed" else 0),
            upstream_receipt_ids=[] if status == "not_applicable" else ["c" * 64],
            input_artifacts=[] if status == "not_applicable" else [{"artifact_contract": "input.contract", "path": "input.json", "sha256": "8" * 64, "size": 4}],
            output_artifacts=[] if status == "not_applicable" else [
                {
                    "artifact_contract": "output.contract",
                    "path": "output.json",
                    "sha256": "9" * 64,
                    "size": 12,
                    "semantic_validator_results": [
                        {"validator_id": "json", "status": "succeeded"}
                    ],
                }
            ],
            stdout_sha256="a" * 64,
            stderr_sha256="b" * 64,
            tool_versions={"pipeline": "2"},
            toolchain_versions={"python": "3.14"},
        )

    def assert_valid_terminal(self, receipt: dict) -> None:
        ok, errors = pipeline.validate_terminal_receipt(receipt)
        self.assertTrue(ok, errors)

    def test_valid_terminal_statuses(self) -> None:
        for status in ("succeeded", "failed", "not_applicable"):
            with self.subTest(status=status):
                self.assert_valid_terminal(self.make_receipt(status))

    def test_running_is_representable_but_not_terminal(self) -> None:
        receipt = self.make_receipt("running")
        ok, errors = pipeline.validate_receipt(receipt)
        self.assertTrue(ok, errors)
        ok, errors = pipeline.validate_terminal_receipt(receipt)
        self.assertFalse(ok)
        self.assertIn("non_terminal_status", errors)

    def test_missing_provenance_and_invalid_hashes(self) -> None:
        receipt = self.make_receipt()
        receipt["manifest_sha256"] = "bad"
        ok, errors = pipeline.validate_receipt(receipt)
        self.assertFalse(ok)
        self.assertIn("invalid_manifest_sha256", errors)
        receipt.pop("scope_sha256")
        ok, errors = pipeline.validate_receipt(receipt)
        self.assertFalse(ok)
        self.assertIn("missing_scope_sha256", errors)
        receipt = self.make_receipt()
        receipt["pipeline_tooling_sha256"] = "bad"
        ok, errors = pipeline.validate_receipt(receipt)
        self.assertFalse(ok)
        self.assertIn("invalid_pipeline_tooling_sha256", errors)

    def test_step_token_is_required_and_must_be_64_hex(self) -> None:
        receipt = self.make_receipt()
        receipt["step_token"] = "not-a-token"
        ok, errors = pipeline.validate_receipt(receipt)
        self.assertFalse(ok)
        self.assertIn("invalid_step_token", errors)

        receipt = self.make_receipt()
        receipt.pop("step_token")
        ok, errors = pipeline.validate_receipt(receipt)
        self.assertFalse(ok)
        self.assertIn("missing_step_token", errors)

    def test_bad_time_order_and_exit_status_combinations(self) -> None:
        receipt = self.make_receipt()
        receipt["finished_at"] = "2026-07-17T09:59:59+00:00"
        receipt["exit_code"] = 2
        ok, errors = pipeline.validate_receipt(receipt)
        self.assertFalse(ok)
        self.assertIn("timestamp_ordering", errors)
        self.assertIn("invalid_exit_code_for_status", errors)

    def test_not_applicable_requires_false_proven_probe(self) -> None:
        receipt = self.make_receipt("not_applicable")
        receipt["applicability"]["result"] = True
        ok, errors = pipeline.validate_receipt(receipt)
        self.assertFalse(ok)
        self.assertIn("not_applicable_unproven", errors)
        self.assertIn("applicability_hash_mismatch", errors)

    def test_execution_statuses_require_applicability(self) -> None:
        for status in ("succeeded", "failed"):
            with self.subTest(status=status):
                receipt = self.make_receipt(status)
                receipt["applicability"]["result"] = False
                receipt["applicability"]["hash"] = pipeline.stable_hash(
                    {
                        "probe_id": receipt["applicability"]["probe_id"],
                        "canonical_inputs": receipt["applicability"]["canonical_inputs"],
                        "result": False,
                    }
                )
                ok, errors = pipeline.validate_receipt(receipt)
                self.assertFalse(ok)
                self.assertIn("execution_requires_applicability", errors)

    def test_failed_may_carry_typed_applicability_evaluation_error(self) -> None:
        receipt = self.make_receipt(
            "failed",
            applicability_error_diagnostics=["applicability_inventory_malformed_row:1"],
        )
        self.assert_valid_terminal(receipt)

    def test_non_failed_statuses_reject_typed_applicability_evaluation_error(self) -> None:
        invalid_succeeded = self.make_receipt(
            "succeeded",
            applicability_error_diagnostics=["applicability_inventory_malformed_row:1"],
        )
        ok, errors = pipeline.validate_receipt(invalid_succeeded)
        self.assertFalse(ok)
        self.assertIn("succeeded_forbids_applicability_evaluation_error", errors)

        invalid_na = self.make_receipt(
            "not_applicable",
            applicability_error_diagnostics=["applicability_inventory_malformed_row:1"],
        )
        ok, errors = pipeline.validate_receipt(invalid_na)
        self.assertFalse(ok)
        self.assertIn("not_applicable_forbids_applicability_evaluation_error", errors)

    def test_failed_rejects_malformed_typed_applicability_evaluation_error(self) -> None:
        receipt = self.make_receipt(
            "failed",
            applicability_error_diagnostics=["applicability_inventory_malformed_row:1"],
        )
        receipt["applicability"]["evaluation_error"]["diagnostics"] = ["", "applicability_inventory_malformed_row:1"]
        receipt["receipt_id"] = pipeline.receipt_id(receipt)
        receipt["self_hash"] = receipt["receipt_id"]
        ok, errors = pipeline.validate_receipt(receipt)
        self.assertFalse(ok)
        self.assertIn("invalid_applicability_evaluation_error_diagnostics", errors)

    def test_not_applicable_rejects_output_artifacts(self) -> None:
        receipt = self.make_receipt("not_applicable")
        receipt["output_artifacts"] = [
            {
                "artifact_contract": "output.contract",
                "path": "output.json",
                "sha256": "9" * 64,
                "size": 12,
                "semantic_validator_results": [
                    {"validator_id": "json", "status": "succeeded"}
                ],
            }
        ]
        ok, errors = pipeline.validate_receipt(receipt)
        self.assertFalse(ok)
        self.assertIn("not_applicable_has_output_artifacts", errors)

    def test_not_applicable_rejects_input_artifacts(self) -> None:
        receipt = self.make_receipt("not_applicable")
        receipt["input_artifacts"] = [
            {"artifact_contract": "input.contract", "path": "input.json", "sha256": "8" * 64, "size": 4}
        ]
        ok, errors = pipeline.validate_receipt(receipt)
        self.assertFalse(ok)
        self.assertIn("not_applicable_has_input_artifacts", errors)

    def test_failed_validator_requires_failed_step(self) -> None:
        receipt = self.make_receipt("succeeded")
        receipt["output_artifacts"][0]["semantic_validator_results"][0]["status"] = "failed"
        ok, errors = pipeline.validate_receipt(receipt)
        self.assertFalse(ok)
        self.assertIn("failed_validator_requires_failed_status", errors)
        self.assertIn("succeeded_contains_failed_validator", errors)

    def test_succeeded_step_requires_every_output_validator_to_succeed(self) -> None:
        receipt = self.make_receipt("succeeded")
        receipt["output_artifacts"][0]["semantic_validator_results"][0]["status"] = "not_applicable"
        ok, errors = pipeline.validate_receipt(receipt)
        self.assertFalse(ok)
        self.assertIn("succeeded_requires_succeeded_validators", errors)

    def test_artifact_order_uses_contract_path_and_hash_key(self) -> None:
        receipt = self.make_receipt()
        receipt["input_artifacts"] = [
            {"artifact_contract": "a.contract", "path": "z.json", "sha256": "8" * 64, "size": 4},
            {"artifact_contract": "b.contract", "path": "a.json", "sha256": "7" * 64, "size": 5},
        ]
        receipt["receipt_id"] = pipeline.receipt_id(receipt)
        receipt["self_hash"] = receipt["receipt_id"]
        ok, errors = pipeline.validate_receipt(receipt)
        self.assertTrue(ok, errors)

    def test_upstream_receipt_ids_are_hashes_and_empty_is_valid(self) -> None:
        first_step = self.make_receipt("not_applicable")
        ok, errors = pipeline.validate_receipt(first_step)
        self.assertTrue(ok, errors)
        invalid = self.make_receipt("succeeded")
        invalid["upstream_receipt_ids"] = ["upstream-1"]
        ok, errors = pipeline.validate_receipt(invalid)
        self.assertFalse(ok)
        self.assertIn("invalid_upstream_receipt_id", errors)

    def test_version_maps_must_be_nonempty_strings(self) -> None:
        for field in ("tool_versions", "toolchain_versions"):
            with self.subTest(field=field):
                receipt = self.make_receipt()
                receipt[field] = {}
                ok, errors = pipeline.validate_receipt(receipt)
                self.assertFalse(ok)
                self.assertIn(f"invalid_{field}", errors)
                receipt[field] = {"": "1"}
                ok, errors = pipeline.validate_receipt(receipt)
                self.assertFalse(ok)
                self.assertIn(f"invalid_{field}", errors)
                receipt[field] = {"tool": ""}
                ok, errors = pipeline.validate_receipt(receipt)
                self.assertFalse(ok)
                self.assertIn(f"invalid_{field}", errors)

    def test_artifact_and_validator_defects(self) -> None:
        receipt = self.make_receipt()
        receipt["output_artifacts"][0]["size"] = -1
        receipt["output_artifacts"][0]["semantic_validator_results"][0]["status"] = "running"
        receipt["input_artifacts"][0]["sha256"] = "bad"
        ok, errors = pipeline.validate_receipt(receipt)
        self.assertFalse(ok)
        self.assertIn("invalid_output_artifacts_0_size", errors)
        self.assertIn("invalid_output_artifacts_0_validator_0_status", errors)
        self.assertIn("invalid_input_artifacts_0_sha256", errors)

    def test_artifacts_require_nonempty_contracts(self) -> None:
        receipt = self.make_receipt()
        receipt["input_artifacts"][0].pop("artifact_contract")
        receipt["output_artifacts"][0]["artifact_contract"] = ""
        ok, errors = pipeline.validate_receipt(receipt)
        self.assertFalse(ok)
        self.assertIn("missing_input_artifacts_0_artifact_contract", errors)
        self.assertIn("missing_output_artifacts_0_artifact_contract", errors)

    def test_deterministic_hashing_and_write_read(self) -> None:
        first = self.make_receipt()
        second = self.make_receipt()
        second["selected_environment"] = {"PATH": "/usr/bin", "LANG": "C"}
        second["upstream_receipt_ids"] = ["c" * 64]
        self.assertEqual(pipeline.receipt_id(first), pipeline.receipt_id(second))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "receipt.json"
            pipeline.write_receipt(path, first)
            text_one = path.read_text(encoding="utf-8")
            pipeline.write_receipt(path, second)
            self.assertEqual(text_one, path.read_text(encoding="utf-8"))
            loaded, errors = pipeline.read_receipt(path)
            self.assertEqual(errors, [])
            self.assertEqual(loaded, first)

    def test_tampering_after_construction_is_detected(self) -> None:
        receipt = self.make_receipt()
        receipt["argv"].append("tampered")
        ok, errors = pipeline.validate_receipt(receipt)
        self.assertFalse(ok)
        self.assertIn("receipt_id_mismatch", errors)

    def test_artifact_metadata_uses_shared_file_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "artifact.txt"
            path.write_text("hello", encoding="utf-8")
            row = pipeline.artifact_metadata(path, artifact_contract="fixture.contract")
            expected_hash = pipeline.file_sha256(path)
        self.assertEqual(row["sha256"], expected_hash)
        self.assertEqual(row["size"], 5)
        self.assertEqual(row["artifact_contract"], "fixture.contract")

    def test_cli_and_file_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "receipt.json"
            pipeline.write_receipt(path, self.make_receipt())
            ok, errors, loaded = pipeline.validate_receipt_file(path)
            self.assertTrue(ok, errors)
            self.assertEqual(loaded["receipt_id"], pipeline.receipt_id(loaded))
            self.assertEqual(pipeline._cli([str(path)]), 0)
            path.write_text(json.dumps({"bad": True}), encoding="utf-8")
            self.assertEqual(pipeline._cli([str(path)]), 1)


if __name__ == "__main__":
    unittest.main()
