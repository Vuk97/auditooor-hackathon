#!/usr/bin/env python3
"""Tests for runtime-dlt-execution-evidence-validator.py."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "runtime-dlt-execution-evidence-validator.py"


def run_tool(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=60,
    )


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def dlt_row(benchmark_id: str, route_family: str) -> dict[str, object]:
    return {
        "task_id": f"impact-miss-{benchmark_id}",
        "benchmark_id": benchmark_id,
        "tier": "Critical",
        "asset_category": "Blockchain/DLT",
        "route_family": route_family,
        "harness_family": "base_dlt_or_runtime_harness",
        "status": "ready_for_harness_execution",
        "submission_posture": "NOT_SUBMIT_READY",
        "promotion_allowed": False,
        "required_artifacts": [
            {"artifact": "impact_contract", "path": ".auditooor/impact_contracts.json", "exists": True, "required": True},
            {"artifact": "node_harness", "path": f"poc-tests/{benchmark_id}", "exists": True, "required": True},
            {"artifact": "liveness_measurement", "path": f"poc_execution/{benchmark_id}/execution_manifest.json", "exists": True, "required": True},
        ],
        "missing_artifacts": [],
    }


class RuntimeDltExecutionEvidenceValidatorTests(unittest.TestCase):
    def _write_runtime_ready_inputs(self, ws: Path, benchmark_id: str) -> None:
        auditooor = ws / ".auditooor"
        write_json(
            auditooor / "rust_runtime_semantic_blockers.json",
            {
                "runtime_component_family_counts": {"execution_client": 1},
                "items": [{"queue_id": "RRS-001", "runtime_component_family": "execution_client"}],
            },
        )
        write_json(
            auditooor / "impact_miss_harness_blocker_queue.json",
            {"rows": [dlt_row(benchmark_id, "node_liveness")]},
        )
        harness = ws / "poc-tests" / benchmark_id / "run_harness.sh"
        harness.parent.mkdir(parents=True, exist_ok=True)
        harness.write_text("#!/bin/sh\necho project_bound_runtime\nexit 0\n", encoding="utf-8")

    def test_splits_dlt_rows_by_runtime_family_and_manifest_blockers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime_dlt_validator_") as tmp:
            ws = Path(tmp)
            auditooor = ws / ".auditooor"
            write_json(
                auditooor / "rust_runtime_semantic_blockers.json",
                {
                    "schema": "auditooor.rust_runtime_semantic_blockers.v1",
                    "runtime_component_family_counts": {
                        "execution_client": 2,
                        "runtime_resource": 1,
                    },
                    "items": [
                        {
                            "queue_id": "RRS-001",
                            "runtime_component_family": "execution_client",
                            "runtime_model_requirement": {"model_status": "required_not_collected"},
                        },
                        {
                            "queue_id": "RRS-002",
                            "runtime_component_family": "runtime_resource",
                            "runtime_model_requirement": {"model_status": "required_not_collected"},
                        },
                    ],
                },
            )
            write_json(
                auditooor / "impact_miss_harness_blocker_queue.json",
                {
                    "schema": "auditooor.pr560.impact_miss_harness_blocker_queue.v1",
                    "rows": [
                        dlt_row("imo-critical-node-liveness-01", "node_liveness"),
                        dlt_row("imo-critical-resource-consumption-01", "resource_consumption"),
                        dlt_row("imo-critical-consensus-safety-01", "consensus_safety"),
                        {
                            "benchmark_id": "imo-critical-asset-custody-01",
                            "asset_category": "Smart Contract",
                            "route_family": "asset_custody",
                        },
                    ],
                },
            )
            for benchmark_id in (
                "imo-critical-node-liveness-01",
                "imo-critical-resource-consumption-01",
                "imo-critical-consensus-safety-01",
            ):
                harness = ws / "poc-tests" / benchmark_id / "run_harness.sh"
                harness.parent.mkdir(parents=True, exist_ok=True)
                harness.write_text("#!/bin/sh\necho blocked_missing_target_project\nexit 2\n", encoding="utf-8")
                write_json(
                    ws / "poc_execution" / benchmark_id / "execution_manifest.json",
                    {
                        "candidate_id": benchmark_id,
                        "final_result": "blocked_path",
                        "impact_assertion": "not_demonstrated",
                        "commands_attempted": [{"command": str(harness), "exit_code": 2}],
                    },
                )

            out = ws / "out.json"
            proc = run_tool(["--workspace", str(ws), "--demo-fixture", "--out-json", str(out)])
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.pr560.runtime_dlt_execution_evidence_validator.v1")
            self.assertEqual(payload["dlt_row_count"], 3)
            self.assertEqual(payload["closure_candidate_count"], 0)
            self.assertEqual(payload["proved_exploit_impact_count"], 0)
            self.assertFalse(payload["promotion_allowed"])
            self.assertEqual(payload["hermetic_fixture_check"]["status"], "passed")
            self.assertEqual(
                payload["summary"]["expected_runtime_family_status_counts"],
                {
                    "consensus_client:missing": 1,
                    "execution_client:present": 1,
                    "runtime_resource:present": 1,
                },
            )
            self.assertEqual(payload["summary"]["blocker_counts"]["execution_manifest_not_proved"], 3)
            self.assertEqual(payload["summary"]["blocker_counts"]["runtime_harness_not_project_bound"], 3)
            self.assertEqual(payload["summary"]["blocker_counts"]["missing_expected_runtime_family"], 1)
            self.assertNotIn("missing_or_incomplete_hermetic_fixture", payload["summary"]["blocker_counts"])
            bundle = ws / ".auditooor" / "runtime_dlt_execution_evidence_bundles" / "node_liveness.json"
            self.assertTrue(bundle.is_file())
            self.assertTrue((ws / "benchmark_fixtures" / "runtime_dlt_execution_evidence" / "non_base_runtime_demo").is_dir())

    def test_missing_hermetic_fixture_blocks_all_dlt_rows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime_dlt_no_fixture_") as tmp:
            ws = Path(tmp)
            auditooor = ws / ".auditooor"
            write_json(
                auditooor / "rust_runtime_semantic_blockers.json",
                {
                    "runtime_component_family_counts": {"execution_client": 1},
                    "items": [{"queue_id": "RRS-001", "runtime_component_family": "execution_client"}],
                },
            )
            write_json(
                auditooor / "impact_miss_harness_blocker_queue.json",
                {"rows": [dlt_row("imo-critical-node-liveness-01", "node_liveness")]},
            )

            out = ws / "out.json"
            proc = run_tool(["--workspace", str(ws), "--out-json", str(out)])
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["hermetic_fixture_check"]["status"], "missing_or_incomplete")
            self.assertEqual(payload["summary"]["blocker_counts"]["missing_or_incomplete_hermetic_fixture"], 1)
            self.assertEqual(payload["closure_candidate_count"], 0)

    def test_strict_manifest_counts_but_runtime_family_proof_still_blocks_closure(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime_dlt_strict_manifest_") as tmp:
            ws = Path(tmp)
            benchmark_id = "imo-critical-node-liveness-01"
            self._write_runtime_ready_inputs(ws, benchmark_id)
            write_json(
                ws / "poc_execution" / benchmark_id / "execution_manifest.json",
                {
                    "candidate_id": benchmark_id,
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": [{"command": "cargo test runtime_proof", "status": "pass", "exit_code": "0"}],
                },
            )

            out = ws / "out.json"
            proc = run_tool(["--workspace", str(ws), "--demo-fixture", "--out-json", str(out)])
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(out.read_text(encoding="utf-8"))

        self.assertEqual(payload["closure_candidate_count"], 0)
        self.assertEqual(payload["proved_exploit_impact_count"], 1)
        row = payload["rows"][0]
        self.assertEqual(row["status"], "terminal_runtime_execution_inputs_missing")
        self.assertIn("runtime_family_present_but_unproved", row["blockers"])
        self.assertNotIn("execution_manifest_not_proved", row["blockers"])
        self.assertEqual(row["execution_manifest_status"]["passing_command_count"], 1)

    def test_loose_manifest_is_not_runtime_closure_candidate(self) -> None:
        loose_manifests = {
            "missing-evidence-class": {
                "final_result": "proved",
                "impact_assertion": "exploit_impact",
                "commands_attempted": [{"command": "cargo test runtime_proof", "status": "pass", "exit_code": 0}],
            },
            "legacy-string-command": {
                "final_result": "proved",
                "impact_assertion": "exploit_impact",
                "evidence_class": "executed_with_manifest",
                "commands_attempted": ["cargo test runtime_proof"],
            },
            "missing-command-text": {
                "final_result": "proved",
                "impact_assertion": "exploit_impact",
                "evidence_class": "executed_with_manifest",
                "commands_attempted": [{"command": "", "status": "pass", "exit_code": 0}],
            },
            "failed-command": {
                "final_result": "proved",
                "impact_assertion": "exploit_impact",
                "evidence_class": "executed_with_manifest",
                "commands_attempted": [{"command": "cargo test runtime_proof", "status": "fail", "exit_code": 1}],
            },
            "bool-exit-code": {
                "final_result": "proved",
                "impact_assertion": "exploit_impact",
                "evidence_class": "executed_with_manifest",
                "commands_attempted": [{"command": "cargo test runtime_proof", "status": "pass", "exit_code": True}],
            },
        }
        for label, manifest in loose_manifests.items():
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory(prefix=f"runtime_dlt_loose_{label}_") as tmp:
                    ws = Path(tmp)
                    benchmark_id = "imo-critical-node-liveness-01"
                    self._write_runtime_ready_inputs(ws, benchmark_id)
                    write_json(ws / "poc_execution" / benchmark_id / "execution_manifest.json", manifest)

                    out = ws / "out.json"
                    proc = run_tool(["--workspace", str(ws), "--demo-fixture", "--out-json", str(out)])
                    self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                    payload = json.loads(out.read_text(encoding="utf-8"))

                self.assertEqual(payload["closure_candidate_count"], 0)
                self.assertEqual(payload["proved_exploit_impact_count"], 0)
                row = payload["rows"][0]
                self.assertIn("execution_manifest_not_proved", row["blockers"])
                self.assertFalse(row["execution_manifest_status"]["proved_exploit_impact"])
                if label == "bool-exit-code":
                    self.assertEqual(row["execution_manifest_status"]["passing_command_count"], 0)

    def test_bound_sources_are_workspace_bound_and_content_verified(self) -> None:
        manifest_base = {
            "final_result": "proved",
            "impact_assertion": "exploit_impact",
            "evidence_class": "executed_with_manifest",
            "commands_attempted": [{"command": "cargo test runtime_proof", "status": "pass", "exit_code": 0}],
        }
        cases = {
            "valid": ("valid.rs", None),
            "malformed": ("malformed.rs", {"bound_sources": {}}),
            "outside": ("outside.rs", {"bound_sources": [{"path": "/tmp/outside.rs", "sha256": "0" * 64, "size": 1}]}),
            "missing": ("missing.rs", {"bound_sources": [{"path": "missing.rs", "sha256": "0" * 64, "size": 1}]}),
            "legacy-size-bytes": ("legacy.rs", {"bound_sources": [{"path": "legacy.rs", "sha256": hashlib.sha256(b"right").hexdigest(), "size_bytes": 5}]}),
            "hash": ("hash.rs", {"bound_sources": [{"path": "hash.rs", "sha256": "0" * 64, "size": 5}]}),
            "size": ("size.rs", {"bound_sources": [{"path": "size.rs", "sha256": hashlib.sha256(b"right").hexdigest(), "size": 99}]}),
        }
        for label, (filename, override) in cases.items():
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory(prefix=f"runtime_dlt_bound_{label}_") as tmp:
                    ws = Path(tmp)
                    benchmark_id = "imo-critical-node-liveness-01"
                    self._write_runtime_ready_inputs(ws, benchmark_id)
                    source = ws / filename
                    if label != "missing":
                        source.write_text("right", encoding="utf-8")
                    manifest = dict(manifest_base)
                    if label == "valid":
                        manifest["bound_sources"] = [{
                            "path": filename,
                            "sha256": hashlib.sha256(b"right").hexdigest(),
                            "size": 5,
                        }]
                    elif override:
                        manifest.update(override)
                    write_json(ws / "poc_execution" / benchmark_id / "execution_manifest.json", manifest)
                    out = ws / "out.json"
                    proc = run_tool(["--workspace", str(ws), "--demo-fixture", "--out-json", str(out)])
                    self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                    row = json.loads(out.read_text(encoding="utf-8"))["rows"][0]
                    status = row["execution_manifest_status"]
                    self.assertEqual(status["bound_sources"]["valid"], label == "valid")
                    self.assertEqual(status["proved_exploit_impact"], label == "valid")
                    if label != "valid":
                        self.assertIn("execution_manifest_not_proved", row["blockers"])

    def test_bound_source_symlink_does_not_receive_proof_credit(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime_dlt_bound_symlink_") as tmp:
            ws = Path(tmp)
            benchmark_id = "imo-critical-node-liveness-01"
            self._write_runtime_ready_inputs(ws, benchmark_id)
            target = ws / "real.rs"
            target.write_text("right", encoding="utf-8")
            link = ws / "link.rs"
            link.symlink_to(target)
            write_json(
                ws / "poc_execution" / benchmark_id / "execution_manifest.json",
                {
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": [{"command": "cargo test", "status": "pass", "exit_code": 0}],
                    "bound_sources": [{"path": "link.rs", "sha256": hashlib.sha256(b"right").hexdigest(), "size": 5}],
                },
            )
            out = ws / "out.json"
            proc = run_tool(["--workspace", str(ws), "--demo-fixture", "--out-json", str(out)])
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            status = json.loads(out.read_text(encoding="utf-8"))["rows"][0]["execution_manifest_status"]
            self.assertFalse(status["bound_sources"]["valid"])
            self.assertIn("bound_source_symlink", status["bound_sources"]["errors"])
            self.assertFalse(status["proved_exploit_impact"])


if __name__ == "__main__":
    unittest.main()
