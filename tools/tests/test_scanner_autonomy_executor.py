#!/usr/bin/env python3
"""Tests for tools/scanner-autonomy-executor.py."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "scanner-autonomy-executor.py"
NON_BASE_SAMPLE = ROOT / "tools" / "tests" / "fixtures" / "scanner_autonomy" / "non_base_sample_artifacts.json"


def load_tool():
    spec = importlib.util.spec_from_file_location("scanner_autonomy_executor", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tool = load_tool()


class ScannerAutonomyExecutorTests(unittest.TestCase):
    def make_ws(self) -> Path:
        ws = Path(tempfile.mkdtemp(prefix="scanner_autonomy_executor_"))
        (ws / ".auditooor").mkdir()
        return ws

    def write_non_base_sample_workspace(self, ws: Path) -> None:
        sample = json.loads(NON_BASE_SAMPLE.read_text(encoding="utf-8"))
        audit = ws / ".auditooor"
        (audit / "semantic_scanner_inventory.json").write_text(
            json.dumps(sample["semantic_inventory"]),
            encoding="utf-8",
        )
        (audit / "rust_runtime_semantic_blockers.json").write_text(
            json.dumps(sample["rust_runtime_semantic_blockers"]),
            encoding="utf-8",
        )
        (audit / "agent_recall_detector_tasks.json").write_text(
            json.dumps(sample["agent_recall_detector_tasks"]),
            encoding="utf-8",
        )
        fixture_dir = ws / "detectors" / "fixtures" / sample["workspace_label"]
        fixture_dir.mkdir(parents=True)
        for idx in range(int(sample["fixture_count"])):
            (fixture_dir / f"neon-fix-{idx:03d}_manifest.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.semantic_fixture_materialization.v1",
                        "fixture_id": f"NEON-FIX-{idx:03d}",
                        "detector_slug": f"{sample['detector_slug_prefix']}_{idx:03d}",
                        "materialization_status": "exact_extraction_command_ready",
                        "positive_fixture_path": str(fixture_dir / f"positive_{idx:03d}.sol"),
                        "clean_fixture_path": str(fixture_dir / f"clean_{idx:03d}.sol"),
                        "smoke_record_path": str(fixture_dir / f"smoke_{idx:03d}.json"),
                        "argv": [
                            sys.executable,
                            "tools/p1-fixture-extractor.py",
                            "--pattern",
                            f"neon-lending-{idx}",
                            "--workspace",
                            str(ws),
                            "--fixture-dir",
                            str(fixture_dir),
                            "--mock-dispatcher",
                        ],
                        "advisory_only": True,
                        "promotion_allowed": False,
                        "severity": "none",
                        "submission_posture": "NOT_SUBMIT_READY",
                    }
                ),
                encoding="utf-8",
            )

    def test_build_plan_consumes_all_scanner_inputs_and_caps_to_fifty(self) -> None:
        ws = self.make_ws()
        audit = ws / ".auditooor"
        fixture_dir = ws / "detectors" / "fixtures" / "alpha"
        fixture_dir.mkdir(parents=True)
        for idx in range(55):
            (fixture_dir / f"ssi-fix-{idx:03d}_manifest.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.semantic_fixture_materialization.v1",
                        "fixture_id": f"SSI-FIX-{idx:03d}",
                        "materialization_status": "exact_extraction_command_ready",
                        "positive_fixture_path": str(fixture_dir / f"ssi-fix-{idx:03d}_positive.sol"),
                        "clean_fixture_path": str(fixture_dir / f"ssi-fix-{idx:03d}_clean.sol"),
                        "smoke_record_path": str(fixture_dir / f"ssi-fix-{idx:03d}_smoke.json"),
                        "argv": [
                            sys.executable,
                            "tools/p1-fixture-extractor.py",
                            "--pattern",
                            f"alpha-{idx}",
                            "--workspace",
                            str(ws),
                            "--fixture-dir",
                            str(fixture_dir),
                            "--mock-dispatcher",
                        ],
                        "advisory_only": True,
                        "promotion_allowed": False,
                        "severity": "none",
                        "submission_posture": "NOT_SUBMIT_READY",
                    }
                ),
                encoding="utf-8",
            )
        (audit / "semantic_scanner_inventory.json").write_text(
            json.dumps(
                {
                    "detector_fixture_task_queue": [
                        {
                            "queue_id": "SSI-Q-001",
                            "inventory_id": "SSI-001",
                            "task_type": "detector_rewrite_with_fixture_pair",
                            "suggested_detector_slug": "vault_withdraw",
                            "promotion_blockers": ["vulnerable fixture missing"],
                            "fixture_task": {
                                "positive_fixture_path": "detectors/fixtures/vault/positive.sol",
                                "clean_fixture_path": "detectors/fixtures/vault/clean.sol",
                            },
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (audit / "rust_runtime_semantic_blockers.json").write_text(
            json.dumps(
                {
                    "items": [
                        {
                            "queue_id": "RRS-001",
                            "action_lane": "safe_detectorization_handoff",
                            "blocker_ids": ["rust-fixture-smoke-required"],
                            "detectorization_handoff": {"candidate_detector_family": "rust_external_call"},
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (audit / "agent_recall_detector_tasks.json").write_text(
            json.dumps(
                {
                    "tasks": [
                        {
                            "task_id": "ARDT-001",
                            "task_type": "detector_task",
                            "terminal_state": "detector_queue_ready",
                            "terminal_blockers": ["missing_clean_fixture"],
                            "provider_classifications": ["needs_fixture"],
                            "reason": "needs detector fixture",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        payload = tool.build_plan(ws, limit=50)
        self.assertEqual(payload["schema"], "auditooor.scanner_autonomy_executor.v1")
        self.assertEqual(payload["task_count"], 50)
        self.assertTrue(payload["truncated"])
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["severity"], "none")
        self.assertEqual(payload["selected_impact"], "")
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(payload["evidence_class"], "scaffolded_unverified")
        self.assertEqual(payload["lane_counts"]["fixture_manifest_runnable"], 47)
        self.assertEqual(payload["source_counts"]["fixture_manifest"], 47)
        self.assertEqual(payload["source_counts"]["semantic_scanner_inventory"], 1)
        self.assertEqual(payload["source_counts"]["rust_runtime_semantic_blockers"], 1)
        self.assertEqual(payload["source_counts"]["agent_recall_detector_tasks"], 1)
        self.assertEqual(payload["provider_output_summary"]["provider_derived_task_count"], 1)
        self.assertEqual(
            payload["stop_condition_summary"]["manual_triage_items_mechanically_accounted"],
            50,
        )
        self.assertTrue(all(row["submission_posture"] == "NOT_SUBMIT_READY" for row in payload["tasks"]))
        self.assertTrue(all(row["evidence_class"] == "scaffolded_unverified" for row in payload["tasks"]))
        self.assertTrue(all(row["promotion_allowed"] is False for row in payload["tasks"]))
        self.assertEqual(payload["execution_allowed_count"], 49)

    def test_default_plan_handles_large_non_base_workspace_neutral_artifacts(self) -> None:
        ws = self.make_ws()
        self.write_non_base_sample_workspace(ws)

        payload = tool.build_plan(ws, limit=200)

        self.assertEqual(payload["task_count"], 200)
        self.assertEqual(payload["candidate_count"], 233)
        self.assertTrue(payload["truncated"])
        self.assertTrue(payload["workspace_neutral"])
        self.assertEqual(payload["source_counts"]["fixture_manifest"], 197)
        self.assertEqual(payload["source_counts"]["semantic_scanner_inventory"], 1)
        self.assertEqual(payload["source_counts"]["rust_runtime_semantic_blockers"], 1)
        self.assertEqual(payload["source_counts"]["agent_recall_detector_tasks"], 1)
        self.assertEqual(payload["lane_counts"]["fixture_manifest_runnable"], 197)
        self.assertEqual(payload["execution_allowed_count"], 199)
        self.assertIn("detectors/test_fixtures/**/*_manifest.json", payload["source_artifacts"]["fixture_manifest_globs"])
        serialized = json.dumps(payload).lower()
        self.assertIn("neon-lending-demo", serialized)
        self.assertNotIn("base-azul", serialized)
        self.assertNotIn("swival", serialized)
        self.assertTrue(all(row["coverage_claim"] == "none_scanner_autonomy_only" for row in payload["tasks"]))
        self.assertTrue(all(row["promotion_allowed"] is False for row in payload["tasks"]))
        self.assertTrue(all(row["submission_posture"] == "NOT_SUBMIT_READY" for row in payload["tasks"]))

    def test_cli_writes_plan_and_execute_runs_only_allowlisted_commands(self) -> None:
        ws = self.make_ws()
        audit = ws / ".auditooor"
        (audit / "semantic_scanner_inventory.json").write_text(
            json.dumps(
                {
                    "detector_fixture_task_queue": [
                        {
                            "queue_id": "SSI-Q-001",
                            "task_type": "detector_rewrite_with_fixture_pair",
                            "promotion_blockers": ["detector smoke output missing"],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--workspace",
                str(ws),
                "--limit",
                "1",
                "--execute",
                "--max-execute",
                "1",
                "--print-json",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["task_count"], 1)
        self.assertEqual(payload["execution_allowed_count"], 1)
        self.assertEqual(payload["evidence_class"], "scaffolded_unverified")
        self.assertTrue((audit / "scanner_autonomy_plan.json").is_file())
        execution = json.loads((audit / "scanner_autonomy_execution.json").read_text(encoding="utf-8"))
        self.assertEqual(execution["evidence_class"], "scaffolded_unverified")
        self.assertTrue(all(row["evidence_class"] == "scaffolded_unverified" for row in execution["rows"]))
        self.assertEqual(execution["schema"], "auditooor.scanner_autonomy_execution.v1")
        self.assertEqual(execution["executed_count"], 1)
        self.assertEqual(execution["outcome_count"], 1)
        self.assertEqual(execution["unique_command_execution_count"], 1)
        self.assertEqual(execution["allowlisted_outcome_count"], 1)
        self.assertEqual(execution["rows"][0]["status"], "executed_ok")
        self.assertFalse(execution["promotion_allowed"])
        self.assertEqual(execution["submission_posture"], "NOT_SUBMIT_READY")

    def test_execute_records_duplicate_and_blocked_task_outcomes(self) -> None:
        ws = self.make_ws()
        audit = ws / ".auditooor"
        (audit / "semantic_scanner_inventory.json").write_text(
            json.dumps(
                {
                    "detector_fixture_task_queue": [
                        {"queue_id": "SSI-Q-001", "task_type": "detector_rewrite_with_fixture_pair"},
                        {"queue_id": "SSI-Q-002", "task_type": "detector_rewrite_with_fixture_pair"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        fixture_dir = ws / "detectors" / "fixtures" / "unsafe"
        fixture_dir.mkdir(parents=True)
        (fixture_dir / "unsafe_manifest.json").write_text(
            json.dumps(
                {
                    "fixture_id": "UNSAFE",
                    "positive_fixture_path": str(fixture_dir / "positive.sol"),
                    "clean_fixture_path": str(fixture_dir / "clean.sol"),
                    "smoke_record_path": str(fixture_dir / "smoke.json"),
                    "argv": ["bash", "-lc", "echo unsafe"],
                }
            ),
            encoding="utf-8",
        )

        plan = tool.build_plan(ws, limit=3)
        execution = tool.execute_plan(plan, workspace=ws, max_execute=3, timeout=60)

        self.assertEqual(execution["outcome_count"], 3)
        self.assertEqual(execution["executed_count"], 1)
        self.assertEqual(execution["unique_command_execution_count"], 1)
        self.assertEqual(execution["allowlisted_outcome_count"], 2)
        self.assertEqual(execution["status_counts"]["blocked_not_allowlisted"], 1)
        self.assertEqual(execution["status_counts"]["covered_by_prior_execution"], 1)
        self.assertEqual(execution["rows"][1]["status"], "executed_ok")
        self.assertEqual(execution["rows"][2]["status"], "covered_by_prior_execution")
        self.assertEqual(execution["rows"][2]["covered_by_task_id"], execution["rows"][1]["task_id"])

    def test_prior_detector_smoke_rows_count_as_execution_without_promotion(self) -> None:
        ws = self.make_ws()
        audit = ws / ".auditooor"
        (audit / "semantic_detector_smoke_executor.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.semantic_detector_smoke_executor.v1",
                    "counts": {"passed_vulnerable_clean_smoke": 2, "not_executed": 1},
                    "promotion_allowed": False,
                    "submission_posture": "NOT_SUBMIT_READY",
                    "rows": [
                        {
                            "argument": "alpha",
                            "status": "passed_vulnerable_clean_smoke",
                            "detector_paths": ["detectors/wave15/alpha.py"],
                            "positive_fixture": "detectors/test_fixtures/alpha_vulnerable.sol",
                            "clean_fixture": "detectors/test_fixtures/alpha_clean.sol",
                        },
                        {
                            "argument": "beta",
                            "status": "passed_vulnerable_clean_smoke",
                            "detector_paths": ["detectors/wave15/beta.py"],
                            "positive_fixture": "detectors/test_fixtures/beta_vulnerable.sol",
                            "clean_fixture": "detectors/test_fixtures/beta_clean.sol",
                        },
                        {
                            "argument": "gamma",
                            "status": "not_executed",
                            "reason": "terminal_extraction_failed_detector_argument_unresolved",
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )

        plan = tool.build_plan(ws, limit=3)
        self.assertEqual(plan["source_counts"]["semantic_detector_smoke_executor"], 3)
        self.assertEqual(plan["execution_allowed_count"], 2)
        execution = tool.execute_plan(plan, workspace=ws, max_execute=3, timeout=60)

        self.assertEqual(execution["prior_detector_smoke_execution_count"], 2)
        self.assertEqual(execution["effective_executed_count"], 2)
        self.assertEqual(execution["allowlisted_outcome_count"], 2)
        self.assertEqual(execution["status_counts"]["covered_by_prior_detector_smoke"], 2)
        self.assertEqual(execution["status_counts"]["terminal_detector_smoke_blocker"], 1)
        self.assertFalse(execution["promotion_allowed"])
        self.assertEqual(execution["submission_posture"], "NOT_SUBMIT_READY")

    def test_execute_consumes_ep_fixture_manifest_outcomes_without_rerun(self) -> None:
        ws = self.make_ws()
        audit = ws / ".auditooor"
        fixture_dir = ws / "detectors" / "fixtures" / "ep"
        fixture_dir.mkdir(parents=True)
        for idx, source_id in enumerate(("EP-FIX-001", "EP-FIX-002")):
            (fixture_dir / f"ep_{idx}_manifest.json").write_text(
                json.dumps(
                    {
                        "fixture_id": source_id,
                        "positive_fixture_path": str(fixture_dir / f"positive_{idx}.sol"),
                        "clean_fixture_path": str(fixture_dir / f"clean_{idx}.sol"),
                        "smoke_record_path": str(fixture_dir / f"smoke_{idx}.json"),
                        "argv": [
                            sys.executable,
                            "tools/p1-fixture-extractor.py",
                            "--pattern",
                            f"ep-{idx}",
                            "--workspace",
                            str(ws),
                            "--fixture-dir",
                            str(fixture_dir),
                        ],
                    }
                ),
                encoding="utf-8",
            )
        (audit / "scanner_autonomy_remaining_execution_ep.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.scanner_autonomy_remaining_execution_ep.v1",
                    "rows": [
                        {
                            "source_id": "EP-FIX-001",
                            "status": "executed_ok_smoke_passed",
                            "returncode": 0,
                            "stdout_tail": "ok",
                            "stderr_tail": "",
                        },
                        {
                            "source_id": "EP-FIX-002",
                            "status": "executed_smoke_or_extraction_failed",
                            "returncode": 1,
                            "stdout_tail": "",
                            "stderr_tail": "vuln: expected >=1 hit, got 0\n[hint] save full output: python3 detectors/run_custom.py /tmp/vuln.sol ep-1 --tier=ALL",
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )

        plan = tool.build_plan(ws, limit=2)
        execution = tool.execute_plan(plan, workspace=ws, max_execute=2, timeout=60)

        self.assertEqual(execution["executed_count"], 2)
        self.assertEqual(execution["effective_executed_count"], 2)
        self.assertEqual(execution["allowlisted_outcome_count"], 2)
        self.assertEqual(execution["terminal_outcome_count"], 1)
        self.assertEqual(execution["status_counts"]["executed_ok_smoke_passed"], 1)
        self.assertEqual(execution["status_counts"]["terminal_vulnerable_fixture_no_detector_hit"], 1)
        self.assertTrue(all("covered_by_ep_artifact" in row for row in execution["rows"]))
        self.assertEqual(execution["rows"][0]["evidence_class"], "executed_with_manifest")
        self.assertEqual(execution["rows"][1]["evidence_class"], "scaffolded_unverified")
        self.assertEqual(execution["rows"][1]["terminal_evidence_status"], "terminal_blocker")
        self.assertEqual(execution["rows"][1]["execution_blockers"], ["vulnerable_fixture_no_detector_hit"])
        self.assertIn("detectors/run_custom.py", execution["rows"][1]["next_command"])
        self.assertFalse(execution["promotion_allowed"])
        self.assertEqual(execution["submission_posture"], "NOT_SUBMIT_READY")

    def test_execute_classifies_ep_compile_and_clean_false_positive_failures(self) -> None:
        ws = self.make_ws()
        audit = ws / ".auditooor"
        fixture_dir = ws / "detectors" / "fixtures" / "ep_exact"
        fixture_dir.mkdir(parents=True)
        for source_id in ("EP-FIX-COMPILE", "EP-FIX-CLEAN"):
            (fixture_dir / f"{source_id.lower()}_manifest.json").write_text(
                json.dumps(
                    {
                        "fixture_id": source_id,
                        "positive_fixture_path": str(fixture_dir / f"{source_id}_positive.sol"),
                        "clean_fixture_path": str(fixture_dir / f"{source_id}_clean.sol"),
                        "smoke_record_path": str(fixture_dir / f"{source_id}_smoke.json"),
                        "argv": [
                            sys.executable,
                            "tools/p1-fixture-extractor.py",
                            "--pattern",
                            source_id.lower(),
                            "--workspace",
                            str(ws),
                            "--fixture-dir",
                            str(fixture_dir),
                        ],
                    }
                ),
                encoding="utf-8",
            )
        (audit / "scanner_autonomy_remaining_execution_ep.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.scanner_autonomy_remaining_execution_ep.v1",
                    "rows": [
                        {
                            "source_id": "EP-FIX-COMPILE",
                            "status": "executed_smoke_or_extraction_failed",
                            "returncode": 1,
                            "stderr_tail": "solc failed\nError: Identifier already declared.",
                        },
                        {
                            "source_id": "EP-FIX-CLEAN",
                            "status": "executed_smoke_or_extraction_failed",
                            "returncode": 1,
                            "stderr_tail": "clean: expected 0 hits, got 1\n[hint] save full output: python3 detectors/run_custom.py /tmp/clean.sol ep-clean --tier=ALL",
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )

        plan = tool.build_plan(ws, limit=2)
        execution = tool.execute_plan(plan, workspace=ws, max_execute=2, timeout=60)
        by_source = {row["source_id"]: row for row in execution["rows"]}

        self.assertEqual(by_source["EP-FIX-COMPILE"]["status"], "terminal_generated_fixture_compile_failure")
        self.assertEqual(by_source["EP-FIX-COMPILE"]["execution_blockers"], ["generated_fixture_compile_failure"])
        self.assertEqual(by_source["EP-FIX-CLEAN"]["status"], "terminal_clean_fixture_false_positive")
        self.assertEqual(by_source["EP-FIX-CLEAN"]["execution_blockers"], ["clean_fixture_false_positive"])
        self.assertEqual(execution["terminal_outcome_count"], 2)
        self.assertEqual(execution["allowlisted_outcome_count"], 2)

    def test_current_manifest_smoke_record_overrides_stale_ep_failure(self) -> None:
        ws = self.make_ws()
        audit = ws / ".auditooor"
        fixture_dir = ws / "detectors" / "fixtures" / "current_smoke"
        fixture_dir.mkdir(parents=True)
        smoke = fixture_dir / "smoke.json"
        smoke.write_text(
            json.dumps(
                {
                    "status": "passed_vulnerable_clean_smoke",
                    "positive_hits": 1,
                    "clean_hits": 0,
                }
            ),
            encoding="utf-8",
        )
        (fixture_dir / "current_manifest.json").write_text(
            json.dumps(
                {
                    "fixture_id": "EP-FIX-CURRENT",
                    "positive_fixture_path": str(fixture_dir / "positive.sol"),
                    "clean_fixture_path": str(fixture_dir / "clean.sol"),
                    "smoke_record_path": str(smoke),
                    "argv": [
                        sys.executable,
                        "tools/p1-fixture-extractor.py",
                        "--pattern",
                        "current",
                        "--workspace",
                        str(ws),
                        "--fixture-dir",
                        str(fixture_dir),
                    ],
                }
            ),
            encoding="utf-8",
        )
        (audit / "scanner_autonomy_remaining_execution_ep.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.scanner_autonomy_remaining_execution_ep.v1",
                    "rows": [
                        {
                            "source_id": "EP-FIX-CURRENT",
                            "status": "executed_smoke_or_extraction_failed",
                            "returncode": 1,
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )

        plan = tool.build_plan(ws, limit=1)
        execution = tool.execute_plan(plan, workspace=ws, max_execute=1, timeout=60)

        row = execution["rows"][0]
        self.assertEqual(row["status"], "executed_ok_smoke_passed")
        self.assertIn("covered_by_manifest_smoke_record", row)
        self.assertNotIn("covered_by_ep_artifact", row)
        self.assertEqual(row["evidence_class"], "executed_with_manifest")

    def test_ep_fixture_outcomes_prefer_stable_source_id_over_regenerated_task_id(self) -> None:
        ws = self.make_ws()
        audit = ws / ".auditooor"
        fixture_dir = ws / "detectors" / "fixtures" / "ep_drift"
        fixture_dir.mkdir(parents=True)
        for source_id in ("EP-FIX-A", "EP-FIX-B"):
            (fixture_dir / f"{source_id.lower()}_manifest.json").write_text(
                json.dumps(
                    {
                        "fixture_id": source_id,
                        "positive_fixture_path": str(fixture_dir / f"{source_id}_positive.sol"),
                        "clean_fixture_path": str(fixture_dir / f"{source_id}_clean.sol"),
                        "smoke_record_path": str(fixture_dir / f"{source_id}_smoke.json"),
                        "argv": [
                            sys.executable,
                            "tools/p1-fixture-extractor.py",
                            "--pattern",
                            source_id.lower(),
                            "--workspace",
                            str(ws),
                            "--fixture-dir",
                            str(fixture_dir),
                        ],
                    }
                ),
                encoding="utf-8",
            )
        (audit / "scanner_autonomy_remaining_execution_ep.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.scanner_autonomy_remaining_execution_ep.v1",
                    "rows": [
                        {
                            "task_id": "SAE-001",
                            "source_id": "EP-FIX-A",
                            "status": "executed_ok_smoke_passed",
                            "returncode": 0,
                        },
                        {
                            "task_id": "SAE-002",
                            "source_id": "EP-FIX-B",
                            "status": "terminal_cannot_run",
                            "returncode": 2,
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )

        plan = tool.build_plan(ws, limit=2)
        plan["tasks"][0]["task_id"] = "SAE-002"
        plan["tasks"][1]["task_id"] = "SAE-001"
        execution = tool.execute_plan(plan, workspace=ws, max_execute=2, timeout=60)

        by_source = {row["source_id"]: row for row in execution["rows"]}
        self.assertEqual(by_source["EP-FIX-A"]["status"], "executed_ok_smoke_passed")
        self.assertEqual(by_source["EP-FIX-B"]["status"], "terminal_fixture_command_cannot_run")

    def test_blocks_non_allowlisted_fixture_manifest_commands(self) -> None:
        ws = self.make_ws()
        fixture_dir = ws / "detectors" / "fixtures" / "unsafe"
        fixture_dir.mkdir(parents=True)
        (fixture_dir / "unsafe_manifest.json").write_text(
            json.dumps(
                {
                    "fixture_id": "UNSAFE",
                    "positive_fixture_path": str(fixture_dir / "positive.sol"),
                    "clean_fixture_path": str(fixture_dir / "clean.sol"),
                    "smoke_record_path": str(fixture_dir / "smoke.json"),
                    "argv": ["bash", "-lc", "echo unsafe"],
                }
            ),
            encoding="utf-8",
        )
        payload = tool.build_plan(ws, limit=5)
        row = payload["tasks"][0]
        self.assertTrue(row["runnable"])
        self.assertFalse(row["execution_allowed"])
        self.assertIn("tool_not_allowlisted:bash", row["execution_blockers"])

    def test_no_command_rows_are_exact_terminal_blockers(self) -> None:
        ws = self.make_ws()
        audit = ws / ".auditooor"
        (audit / "rust_runtime_semantic_blockers.json").write_text(
            json.dumps(
                {
                    "items": [
                        {
                            "source_id": "reth.fixture.step",
                            "action_lane": "runtime_semantic_blocker_queue",
                            "next_command": "make rust-runtime-semantic-blockers WS=<workspace> GENERATE=1",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (audit / "agent_recall_detector_tasks.json").write_text(
            json.dumps(
                {
                    "tasks": [
                        {
                            "task_id": "ARDT-HARNESS",
                            "task_type": "terminal_blocker",
                            "reason": "agent output requires local harness/PoC execution or replay",
                            "next_command": "make harness-task-queue WS=<workspace>",
                            "terminal_blockers": ["advisory_provider_or_recall_row_not_proof"],
                        },
                        {
                            "task_id": "ARDT-INTERNAL",
                            "task_type": "terminal_blocker",
                            "reason": "provider row targets Auditooor internal tool code, not a smart-contract detector fixture",
                            "next_command": "rg -n internal tools docs",
                            "terminal_blockers": ["advisory_provider_or_recall_row_not_proof"],
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )

        plan = tool.build_plan(ws, limit=5)
        execution = tool.execute_plan(plan, workspace=ws, max_execute=5, timeout=60)
        by_source = {row["source_id"]: row for row in execution["rows"]}

        self.assertEqual(
            by_source["reth.fixture.step"]["status"],
            "terminal_no_local_command_runtime_semantic_blocker",
        )
        self.assertEqual(
            by_source["ARDT-HARNESS"]["status"],
            "terminal_no_local_command_harness_required",
        )
        self.assertEqual(
            by_source["ARDT-INTERNAL"]["status"],
            "terminal_no_local_command_non_detectorizable",
        )
        self.assertEqual(execution["status_counts"].get("blocked_no_command"), None)
        self.assertEqual(execution["terminal_outcome_count"], 3)

    def test_materialized_canonical_smoke_blocked_fixture_overrides_stale_ep_failure(self) -> None:
        ws = self.make_ws()
        audit = ws / ".auditooor"
        fixture_dir = ws / "detectors" / "fixtures" / "canonical_guard"
        fixture_dir.mkdir(parents=True)
        positive = fixture_dir / "positive.sol"
        clean = fixture_dir / "clean.sol"
        positive.write_text("// positive\n", encoding="utf-8")
        clean.write_text("// clean\n", encoding="utf-8")
        (fixture_dir / "guard_manifest.json").write_text(
            json.dumps(
                {
                    "fixture_id": "SSI-FIX-GUARD",
                    "materialization_status": "fixture_pair_materialized_canonical_smoke_blocked",
                    "positive_fixture_path": str(positive),
                    "clean_fixture_path": str(clean),
                    "smoke_record_path": str(fixture_dir / "missing_smoke.json"),
                    "argv": [
                        sys.executable,
                        "tools/p1-fixture-extractor.py",
                        "--pattern",
                        "guard",
                        "--workspace",
                        str(ws),
                        "--fixture-dir",
                        str(fixture_dir),
                    ],
                }
            ),
            encoding="utf-8",
        )
        (audit / "scanner_autonomy_remaining_execution_ep.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "source_id": "SSI-FIX-GUARD",
                            "status": "executed_smoke_or_extraction_failed",
                            "stdout_tail": "solc failed: identifier already declared",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        plan = tool.build_plan(ws, limit=1)
        execution = tool.execute_plan(plan, workspace=ws, max_execute=1, timeout=60)
        row = execution["rows"][0]

        self.assertEqual(row["action_lane"], "fixture_pair_materialized_canonical_smoke_blocked")
        self.assertEqual(row["status"], "terminal_fixture_pair_materialized_canonical_smoke_blocked")
        self.assertNotIn("covered_by_ep_artifact", row)


if __name__ == "__main__":
    unittest.main()
