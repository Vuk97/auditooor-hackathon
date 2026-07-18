from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "execution-manifest-proof-readiness.py"


def _import():
    spec = importlib.util.spec_from_file_location("execution_manifest_proof_readiness_test", str(TOOL))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _write_source_file(ws: Path, rel_path: str = "target_project/src/Vault.sol", line_count: int = 4) -> None:
    path = ws / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(f"line {idx} withdraw transfer" for idx in range(1, line_count + 1))
    path.write_text(body + "\n", encoding="utf-8")


def _unit(candidate: str, family: str = "asset_custody") -> dict[str, object]:
    return {
        "candidate_id": candidate,
        "impact_contract_id": f"impact-contract-{candidate}",
        "route_family": family,
        "tier": "Critical",
        "requirement": "proved_exploit_impact_execution_manifest",
        "blocker_class": "terminal_execution_manifest_not_proved",
        "next_command": f"make poc-execution-record CANDIDATE_ID={candidate}",
    }


def _source_import_ready(candidate: str, family: str = "asset_custody") -> dict[str, object]:
    return {
        "units": [
            {
                "candidate_id": candidate,
                "route_family": family,
                "requirement": "candidate_bound_project_source_citation",
                "source_import_status": "source_review_candidate_lines_found",
                "line_hit_count": 1,
                "line_hits": [{"file": "target_project/src/Vault.sol", "line": 1}],
            },
            {
                "candidate_id": candidate,
                "route_family": family,
                "requirement": "project_specific_harness_execution",
                "source_import_status": "harness_binding_candidate_lines_found",
                "line_hit_count": 1,
                "line_hits": [{"file": "target_project/src/Vault.sol", "line": 1}],
            },
        ]
    }


def _proved_manifest(command: str = "forge test --match-test testExploitImpact") -> dict[str, object]:
    return {
        "final_result": "proved",
        "impact_assertion": "exploit_impact",
        "evidence_class": "executed_with_manifest",
        "commands_attempted": [
            {
                "command": command,
                "status": "pass",
                "exit_code": 0,
            }
        ],
    }


def _write_ready_inputs(ws: Path, candidate: str, input_path: Path, family: str = "asset_custody") -> None:
    _write_source_file(ws)
    _write_json(input_path, {"units": [_unit(candidate, family)]})
    _write_json(
        ws / ".auditooor" / "project_source_root_readiness.json",
        {"roots": [{"usable": True, "sample_files": [{"file": "target_project/src/Vault.sol"}]}]},
    )
    _write_json(
        ws / ".auditooor" / "impact_binding_source_harness_discovery.json",
        {
            "reductions": [
                {
                    "candidate_id": candidate,
                    "requirement": "project_specific_harness_execution",
                    "discovery_status": "source_harness_binding_ready",
                    "candidate_bound_project_source_citation": "target_project/src/Vault.sol:1",
                    "project_harness_binding": f"poc-tests/{candidate}/run_harness.sh",
                }
            ]
        },
    )
    _write_json(ws / ".auditooor" / "impact_binding_source_import_readiness.json", _source_import_ready(candidate, family))


def _reason_codes(row: dict[str, object]) -> set[str]:
    return {str(reason.get("code")) for reason in row.get("non_ready_reasons", []) if isinstance(reason, dict)}


class ExecutionManifestProofReadinessTests(unittest.TestCase):
    def test_invalid_bound_sources_cannot_grant_proof_readiness(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-critical-asset-custody-bound-source-invalid"
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            _write_ready_inputs(ws, candidate, input_path)
            manifest = _proved_manifest()
            manifest["bound_sources"] = [{
                "path": "target_project/src/Vault.sol",
                "sha256": hashlib.sha256(b"wrong").hexdigest(),
                "size": 5,
            }]
            _write_json(ws / "poc_execution" / candidate / "execution_manifest.json", manifest)
            mod.bound_source_validation = lambda supplied, workspace: {
                "supplied": True,
                "valid": False,
                "entries": [],
                "errors": ["bound_source_size_mismatch"],
            }

            payload = mod.build_payload(ws, input_path=input_path)

        row = payload["rows"][0]
        self.assertEqual(payload["proof_ready_count"], 0)
        self.assertFalse(row["proof_ready"])
        self.assertIn("bound_source_validation", _reason_codes(row))
        self.assertIn("bound_source_size_mismatch", row["missing_inputs"])
        self.assertIn("bound_source_size_mismatch", row["manifest_status"]["bound_sources"]["errors"])

    def test_missing_and_empty_bound_sources_remain_compatible(self) -> None:
        mod = _import()
        for bound_sources in (None, []):
            with self.subTest(bound_sources=bound_sources):
                with tempfile.TemporaryDirectory() as td:
                    ws = Path(td)
                    candidate = "imo-critical-asset-custody-bound-source-compatible"
                    input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
                    _write_ready_inputs(ws, candidate, input_path)
                    manifest = _proved_manifest()
                    if bound_sources is not None:
                        manifest["bound_sources"] = bound_sources
                    _write_json(ws / "poc_execution" / candidate / "execution_manifest.json", manifest)

                    payload = mod.build_payload(ws, input_path=input_path)

                self.assertEqual(payload["proof_ready_count"], 1)
                self.assertTrue(payload["rows"][0]["proof_ready"])

    def test_terminalizes_proof_when_no_project_source_root_exists(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-critical-asset-custody-01"
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            _write_json(input_path, {"units": [_unit(candidate)]})
            _write_json(ws / ".auditooor" / "project_source_root_readiness.json", {"roots": []})
            _write_json(
                ws / ".auditooor" / "impact_binding_source_harness_discovery.json",
                {
                    "reductions": [
                        {
                            "candidate_id": candidate,
                            "requirement": "project_specific_harness_execution",
                            "discovery_status": "terminal_harness_blocked_no_project_source_roots",
                        }
                    ]
                },
            )
            _write_json(
                ws / "poc_execution" / candidate / "execution_manifest.json",
                {"final_result": "blocked_path", "impact_assertion": "not_demonstrated", "commands_attempted": ["./run.sh"]},
            )

            payload = mod.build_payload(ws, input_path=input_path, bundle_dir=ws / ".auditooor" / "bundles")
            bundle_exists = (ws / ".auditooor" / "bundles" / "asset_custody.json").exists()

        row = payload["rows"][0]
        self.assertEqual(payload["proved_execution_requirement_count"], 1)
        self.assertEqual(payload["proof_ready_count"], 0)
        self.assertEqual(row["readiness_status"], "terminal_no_project_source_root_for_execution_proof")
        self.assertIn("project_source_root", row["missing_inputs"])
        self.assertIn("missing_execution_evidence", _reason_codes(row))
        self.assertTrue(bundle_exists)

    def test_detects_exact_proved_exploit_manifest_without_promotion(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-critical-asset-custody-02"
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            _write_ready_inputs(ws, candidate, input_path)
            _write_json(ws / "poc_execution" / candidate / "execution_manifest.json", _proved_manifest())

            payload = mod.build_payload(ws, input_path=input_path)

        row = payload["rows"][0]
        self.assertEqual(payload["proof_ready_count"], 1)
        self.assertEqual(payload["proved_manifest_ready_count"], 1)
        self.assertEqual(row["readiness_status"], "execution_proof_ready")
        self.assertTrue(row["execution_proof_ready"])
        self.assertEqual(row["missing_inputs"], [])
        self.assertEqual(row["manifest_status"]["passing_command_count"], 1)
        self.assertEqual(
            row["source_harness_status"]["candidate_bound_project_source_citations"],
            ["target_project/src/Vault.sol:1"],
        )
        self.assertEqual(row["source_import_status"]["status"], "source_import_line_hits_ready")
        self.assertEqual(row["current_workspace_source_ref_status"]["status"], "current_workspace_source_refs_ready")
        self.assertEqual(row["non_ready_reasons"], [])
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")

    def test_ready_status_without_source_citation_and_harness_binding_stays_blocked(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_source_file(ws)
            candidate = "imo-critical-asset-custody-03"
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            _write_json(input_path, {"units": [_unit(candidate)]})
            _write_json(
                ws / ".auditooor" / "project_source_root_readiness.json",
                {"roots": [{"usable": True, "sample_files": [{"file": "target_project/src/Vault.sol"}]}]},
            )
            _write_json(
                ws / ".auditooor" / "impact_binding_source_harness_discovery.json",
                {
                    "reductions": [
                        {
                            "candidate_id": candidate,
                            "requirement": "project_specific_harness_execution",
                            "discovery_status": "source_harness_binding_ready",
                        }
                    ]
                },
            )
            _write_json(ws / ".auditooor" / "impact_binding_source_import_readiness.json", _source_import_ready(candidate))
            _write_json(ws / "poc_execution" / candidate / "execution_manifest.json", _proved_manifest())

            payload = mod.build_payload(ws, input_path=input_path)

        row = payload["rows"][0]
        self.assertEqual(payload["proof_ready_count"], 0)
        self.assertEqual(row["readiness_status"], "blocked_project_binding_or_manual_review")
        self.assertEqual(row["source_harness_status"]["status"], "source_harness_ready_status_missing_evidence")
        self.assertIn("candidate_bound_project_source_citation", row["missing_inputs"])
        self.assertIn("project_harness_binding", row["missing_inputs"])
        self.assertIn("missing_source_refs", _reason_codes(row))

    def test_project_source_workflow_positive_fixture_becomes_proof_ready(self) -> None:
        mod = _import()
        readiness_spec = importlib.util.spec_from_file_location(
            "project_source_root_readiness_exec_positive",
            str(ROOT / "tools" / "project-source-root-readiness.py"),
        )
        assert readiness_spec is not None and readiness_spec.loader is not None
        readiness_mod = importlib.util.module_from_spec(readiness_spec)
        readiness_spec.loader.exec_module(readiness_mod)

        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-critical-asset-custody-04"
            target_root = ws / "target_project" / "src"
            target_root.mkdir(parents=True)
            (target_root / "Vault.sol").write_text(
                "contract Vault { function withdraw(uint256 amount) external {} }\n",
                encoding="utf-8",
            )
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            manifest = ws / ".auditooor" / "project_source_roots.json"
            readiness = ws / ".auditooor" / "project_source_root_readiness.json"
            _write_json(input_path, {"units": [_unit(candidate)]})
            _write_json(
                manifest,
                {
                    "schema": "auditooor.project_source_roots.v1",
                    "roots": [{"label": "target", "path": "target_project/src", "kind": "target_project_source"}],
                },
            )
            readiness_payload = readiness_mod.build_payload(ws, manifest_path=manifest)
            _write_json(readiness, readiness_payload)
            _write_json(
                ws / ".auditooor" / "impact_binding_source_harness_discovery.json",
                {
                    "reductions": [
                        {
                            "candidate_id": candidate,
                            "requirement": "candidate_bound_project_source_citation",
                            "discovery_status": "project_source_and_harness_ready",
                            "candidate_bound_project_source_citation": "target_project/src/Vault.sol:1",
                            "project_harness_binding": f"poc-tests/{candidate}/run_harness.sh",
                        },
                        {
                            "candidate_id": candidate,
                            "requirement": "project_specific_harness_execution",
                            "discovery_status": "project_source_and_harness_ready",
                            "candidate_bound_project_source_citation": "target_project/src/Vault.sol:1",
                            "project_harness_binding": f"poc-tests/{candidate}/run_harness.sh",
                        },
                    ]
                },
            )
            _write_json(ws / ".auditooor" / "impact_binding_source_import_readiness.json", _source_import_ready(candidate))
            _write_json(ws / "poc_execution" / candidate / "execution_manifest.json", _proved_manifest())

            payload = mod.build_payload(ws, input_path=input_path, bundle_dir=ws / ".auditooor" / "bundles")

        row = payload["rows"][0]
        self.assertEqual(readiness_payload["ready_root_count"], 1)
        self.assertEqual(payload["proved_execution_requirement_count"], 1)
        self.assertEqual(payload["proof_ready_count"], 1)
        self.assertEqual(row["readiness_status"], "execution_proof_ready")
        self.assertTrue(row["proof_ready"])
        self.assertTrue(row["execution_proof_ready"])
        self.assertEqual(row["missing_inputs"], [])
        self.assertEqual(row["manifest_status"]["status"], "proved_exploit_impact_manifest_present")
        self.assertEqual(row["manifest_status"]["command_status_counts"], {"pass": 1})
        self.assertEqual(row["source_harness_status"]["status"], "source_harness_binding_ready")
        self.assertEqual(row["source_import_status"]["status"], "source_import_line_hits_ready")
        self.assertIn("target_project/src/Vault.sol:1", row["source_harness_status"]["candidate_bound_project_source_citations"])
        self.assertIn(f"poc-tests/{candidate}/run_harness.sh", row["source_harness_status"]["project_harness_bindings"])
        self.assertFalse(payload["promotion_allowed"])

    def test_proved_manifest_and_binding_without_source_import_line_hits_stays_blocked(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_source_file(ws)
            candidate = "imo-critical-asset-custody-05"
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            _write_json(input_path, {"units": [_unit(candidate)]})
            _write_json(
                ws / ".auditooor" / "project_source_root_readiness.json",
                {"roots": [{"usable": True, "sample_files": [{"file": "target_project/src/Vault.sol"}]}]},
            )
            _write_json(
                ws / ".auditooor" / "impact_binding_source_harness_discovery.json",
                {
                    "reductions": [
                        {
                            "candidate_id": candidate,
                            "requirement": "project_specific_harness_execution",
                            "discovery_status": "source_harness_binding_ready",
                            "candidate_bound_project_source_citation": "target_project/src/Vault.sol:1",
                            "project_harness_binding": f"poc-tests/{candidate}/run_harness.sh",
                        }
                    ]
                },
            )
            _write_json(
                ws / ".auditooor" / "impact_binding_source_import_readiness.json",
                {
                    "units": [
                        {
                            "candidate_id": candidate,
                            "requirement": "candidate_bound_project_source_citation",
                            "source_import_status": "terminal_no_candidate_line_hits_in_project_source",
                            "line_hit_count": 0,
                        }
                    ]
                },
            )
            _write_json(ws / "poc_execution" / candidate / "execution_manifest.json", _proved_manifest())

            payload = mod.build_payload(ws, input_path=input_path)

        row = payload["rows"][0]
        self.assertEqual(payload["proof_ready_count"], 0)
        self.assertEqual(row["readiness_status"], "blocked_project_binding_or_manual_review")
        self.assertEqual(row["source_import_status"]["status"], "source_import_line_hits_missing")
        self.assertIn("candidate_bound_source_line_hit", row["missing_inputs"])
        self.assertIn("project_harness_line_hit", row["missing_inputs"])
        self.assertIn("missing_source_refs", _reason_codes(row))

    def test_rejects_proved_manifest_without_exploit_impact_assertion(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-high-availability-dos-01"
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            _write_ready_inputs(ws, candidate, input_path, "availability_dos")
            _write_json(
                ws / "poc_execution" / candidate / "execution_manifest.json",
                {"final_result": "proved", "impact_assertion": "not_demonstrated", "commands_attempted": ["cargo test"]},
            )

            payload = mod.build_payload(ws, input_path=input_path)

        row = payload["rows"][0]
        self.assertEqual(payload["proof_ready_count"], 0)
        self.assertEqual(row["readiness_status"], "terminal_execution_manifest_not_proved")
        self.assertIn("impact_assertion_exploit_impact", row["missing_inputs"])
        self.assertIn("missing_execution_evidence", _reason_codes(row))

    def test_manifest_with_noncanonical_evidence_class_is_not_proof_ready(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-critical-asset-custody-06"
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            _write_ready_inputs(ws, candidate, input_path)
            manifest = _proved_manifest()
            manifest["evidence_class"] = "generated_hypothesis"
            _write_json(ws / "poc_execution" / candidate / "execution_manifest.json", manifest)

            payload = mod.build_payload(ws, input_path=input_path)

        row = payload["rows"][0]
        self.assertEqual(payload["proof_ready_count"], 0)
        self.assertEqual(row["readiness_status"], "terminal_execution_manifest_not_proved")
        self.assertIn("evidence_class_executed_with_manifest", row["missing_inputs"])

    def test_recorded_without_execution_is_not_proof_ready(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-critical-asset-custody-07"
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            _write_ready_inputs(ws, candidate, input_path)
            manifest = _proved_manifest()
            manifest["commands_attempted"] = [
                {"command": "forge test", "status": "recorded_without_execution", "exit_code": None}
            ]
            _write_json(ws / "poc_execution" / candidate / "execution_manifest.json", manifest)

            payload = mod.build_payload(ws, input_path=input_path)

        row = payload["rows"][0]
        self.assertEqual(payload["proof_ready_count"], 0)
        self.assertEqual(row["readiness_status"], "terminal_execution_manifest_not_proved")
        self.assertIn("commands_attempted_pass_exit_0", row["missing_inputs"])
        self.assertIn("missing_execution_evidence", _reason_codes(row))

    def test_no_commands_is_not_proof_ready(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-critical-asset-custody-10"
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            _write_ready_inputs(ws, candidate, input_path)
            manifest = _proved_manifest()
            manifest["commands_attempted"] = []
            _write_json(ws / "poc_execution" / candidate / "execution_manifest.json", manifest)

            payload = mod.build_payload(ws, input_path=input_path)

        row = payload["rows"][0]
        self.assertEqual(payload["proof_ready_count"], 0)
        self.assertFalse(row["execution_proof_ready"])
        self.assertEqual(row["readiness_status"], "terminal_execution_manifest_not_proved")
        self.assertIn("commands_attempted", row["missing_inputs"])
        self.assertIn("commands_attempted_pass_exit_0", row["missing_inputs"])

    def test_failed_command_is_not_proof_ready(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-critical-asset-custody-08"
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            _write_ready_inputs(ws, candidate, input_path)
            manifest = _proved_manifest()
            manifest["commands_attempted"] = [{"command": "forge test", "status": "fail", "exit_code": 1}]
            _write_json(ws / "poc_execution" / candidate / "execution_manifest.json", manifest)

            payload = mod.build_payload(ws, input_path=input_path)

        row = payload["rows"][0]
        self.assertEqual(payload["proof_ready_count"], 0)
        self.assertEqual(row["readiness_status"], "terminal_execution_manifest_not_proved")
        self.assertIn("commands_attempted_pass_exit_0", row["missing_inputs"])

    def test_unstructured_command_is_not_proof_ready(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-critical-asset-custody-09"
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            _write_ready_inputs(ws, candidate, input_path)
            manifest = _proved_manifest()
            manifest["commands_attempted"] = ["forge test --match-test testExploitImpact"]
            _write_json(ws / "poc_execution" / candidate / "execution_manifest.json", manifest)

            payload = mod.build_payload(ws, input_path=input_path)

        row = payload["rows"][0]
        self.assertEqual(payload["proof_ready_count"], 0)
        self.assertEqual(row["readiness_status"], "terminal_execution_manifest_not_proved")
        self.assertEqual(row["manifest_status"]["command_status_counts"], {"unstructured": 1})
        self.assertIn("commands_attempted_pass_exit_0", row["missing_inputs"])

    def test_empty_command_text_is_not_proof_ready(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-critical-asset-custody-11"
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            _write_ready_inputs(ws, candidate, input_path)
            manifest = _proved_manifest("  ")
            _write_json(ws / "poc_execution" / candidate / "execution_manifest.json", manifest)

            payload = mod.build_payload(ws, input_path=input_path)

        row = payload["rows"][0]
        self.assertEqual(payload["proof_ready_count"], 0)
        self.assertEqual(row["readiness_status"], "terminal_execution_manifest_not_proved")
        self.assertEqual(row["manifest_status"]["passing_command_count"], 0)
        self.assertEqual(row["manifest_status"]["command_with_text_count"], 0)
        self.assertIn("commands_attempted_nonempty_command", row["missing_inputs"])
        self.assertIn("commands_attempted_pass_exit_0", row["missing_inputs"])

    def test_missing_exit_code_is_not_proof_ready(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-critical-asset-custody-12"
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            _write_ready_inputs(ws, candidate, input_path)
            manifest = _proved_manifest()
            manifest["commands_attempted"] = [{"command": "forge test", "status": "pass"}]
            _write_json(ws / "poc_execution" / candidate / "execution_manifest.json", manifest)

            payload = mod.build_payload(ws, input_path=input_path)

        row = payload["rows"][0]
        self.assertEqual(payload["proof_ready_count"], 0)
        self.assertEqual(row["readiness_status"], "terminal_execution_manifest_not_proved")
        self.assertEqual(row["manifest_status"]["passing_command_count"], 0)
        self.assertEqual(row["manifest_status"]["missing_exit_code_count"], 1)
        self.assertIn("commands_attempted_pass_exit_0", row["missing_inputs"])

    def test_bool_exit_code_is_not_proof_ready(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-critical-asset-custody-13"
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            _write_ready_inputs(ws, candidate, input_path)
            manifest = _proved_manifest()
            manifest["commands_attempted"] = [{"command": "forge test", "status": "pass", "exit_code": False}]
            _write_json(ws / "poc_execution" / candidate / "execution_manifest.json", manifest)

            payload = mod.build_payload(ws, input_path=input_path)

        row = payload["rows"][0]
        self.assertEqual(payload["proof_ready_count"], 0)
        self.assertEqual(row["readiness_status"], "terminal_execution_manifest_not_proved")
        self.assertEqual(row["manifest_status"]["passing_command_count"], 0)
        self.assertEqual(row["manifest_status"]["bool_exit_code_count"], 1)
        self.assertIn("commands_attempted_pass_exit_0", row["missing_inputs"])

    def test_focused_missing_execution_manifest_has_typed_reason(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-critical-asset-custody-missing-exec"
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            _write_ready_inputs(ws, candidate, input_path)

            payload = mod.build_payload(ws, input_path=input_path)

        row = payload["rows"][0]
        self.assertFalse(row["proof_ready"])
        self.assertEqual(row["readiness_status"], "missing_execution_manifest_after_binding")
        self.assertIn("missing_execution_evidence", _reason_codes(row))

    def test_focused_stale_source_refs_have_typed_reason(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-critical-asset-custody-stale-source"
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            _write_ready_inputs(ws, candidate, input_path)
            source_import = _source_import_ready(candidate)
            source_import["units"][0]["line_hits"] = [{"file": "target_project/src/Vault.sol", "line": 500}]
            _write_json(ws / ".auditooor" / "impact_binding_source_import_readiness.json", source_import)
            _write_json(ws / "poc_execution" / candidate / "execution_manifest.json", _proved_manifest())

            payload = mod.build_payload(ws, input_path=input_path)

        row = payload["rows"][0]
        self.assertFalse(row["proof_ready"])
        self.assertEqual(row["readiness_status"], "stale_current_workspace_source_refs")
        self.assertIn("stale_source_refs", _reason_codes(row))
        self.assertEqual(row["current_workspace_source_ref_status"]["status"], "stale_source_refs")
        self.assertIn("stale_source_refs", row["missing_inputs"])

    def test_focused_missing_source_refs_have_typed_reason(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-critical-asset-custody-missing-source"
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            _write_ready_inputs(ws, candidate, input_path)
            _write_json(
                ws / ".auditooor" / "impact_binding_source_harness_discovery.json",
                {
                    "reductions": [
                        {
                            "candidate_id": candidate,
                            "requirement": "project_specific_harness_execution",
                            "discovery_status": "source_harness_binding_ready",
                            "project_harness_binding": f"poc-tests/{candidate}/run_harness.sh",
                        }
                    ]
                },
            )
            _write_json(ws / "poc_execution" / candidate / "execution_manifest.json", _proved_manifest())

            payload = mod.build_payload(ws, input_path=input_path)

        row = payload["rows"][0]
        self.assertFalse(row["proof_ready"])
        self.assertEqual(row["readiness_status"], "blocked_project_binding_or_manual_review")
        self.assertIn("missing_source_refs", _reason_codes(row))
        self.assertIn("missing_source_refs", row["missing_inputs"])

    def test_focused_blocker_marker_propagates_as_typed_reason(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-critical-asset-custody-blocked"
            input_path = ws / ".auditooor" / "impact_binding_next_input_validator.json"
            _write_ready_inputs(ws, candidate, input_path)
            manifest = _proved_manifest()
            manifest["blockers"] = ["manual proof review still open"]
            _write_json(ws / "poc_execution" / candidate / "execution_manifest.json", manifest)

            payload = mod.build_payload(ws, input_path=input_path)

        row = payload["rows"][0]
        self.assertFalse(row["proof_ready"])
        self.assertEqual(row["readiness_status"], "blocked_by_blocker_or_advisory_marker")
        self.assertIn("blocker_or_advisory_marker", _reason_codes(row))
        self.assertIn("blocker_or_advisory_marker", row["missing_inputs"])
        self.assertEqual(row["blocker_advisory_markers"][0]["kind"], "blocker")


if __name__ == "__main__":
    unittest.main()
