"""Tests for scanner-wiring-burndown.py."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "scanner-wiring-burndown.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("scanner_wiring_burndown", TOOL)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _inventory_with_row(row_id: str) -> dict:
    return {
        "schema": "auditooor.scanner_wiring_truth_inventory.v1",
        "limit": 1,
        "item_count": 1,
        "total_row_count": 1,
        "truncated": False,
        "rows": [
            {
                "scanner_id": row_id,
                "pattern_id": "",
                "backend": "solidity",
                "source_paths": [f"detectors/wave17/{row_id}.py"],
                "evidence_kind": "detector_python",
                "wiring_status": "generated_no_fixture",
                "proof_status": "detector_without_fixture_pair",
                "blockers": ["positive_or_vulnerable_fixture_missing"],
                "suggested_next_action": "add fixtures",
                "memory_priority": 80,
            }
        ],
    }


class ScannerWiringBurndownTests(unittest.TestCase):
    def test_build_burndown_queue_assigns_lanes_and_bounds_actions(self):
        tool = _load_tool()
        inventory = {
            "schema": "auditooor.scanner_wiring_truth_inventory.v1",
            "limit": 99,
            "item_count": 7,
            "total_row_count": 7,
            "truncated": False,
            "rows": [
                {
                    "scanner_id": "",
                    "pattern_id": "fake-dsl",
                    "backend": "solidity",
                    "source_paths": ["reference/patterns.dsl/fake-dsl.yaml"],
                    "evidence_kind": "dsl_yaml",
                    "wiring_status": "in_dsl_fake_suspect",
                    "proof_status": "fake_or_suspect_dsl_evidence",
                    "blockers": ["dsl_fake_or_suspect_marker_present", "detector_wiring_not_trusted"],
                    "suggested_next_action": "quarantine",
                    "memory_priority": 95,
                },
                {
                    "scanner_id": "",
                    "pattern_id": "already-quarantined-dsl",
                    "backend": "solidity",
                    "source_paths": ["reference/patterns.dsl/_quarantine/already-quarantined-dsl.yaml"],
                    "evidence_kind": "dsl_yaml",
                    "wiring_status": "in_dsl_fake_suspect",
                    "proof_status": "fake_or_suspect_dsl_evidence",
                    "blockers": ["dsl_fake_or_suspect_marker_present", "detector_wiring_not_trusted"],
                    "suggested_next_action": "quarantine",
                    "memory_priority": 100,
                },
                {
                    "scanner_id": "rust_shape",
                    "pattern_id": "",
                    "backend": "rust",
                    "source_paths": ["detectors/rust_wave1/rust_shape.py"],
                    "evidence_kind": "detector_python",
                    "wiring_status": "rust_source_shape_only",
                    "proof_status": "source_shape_only",
                    "blockers": [
                        "positive_or_vulnerable_fixture_missing",
                        "clean_or_negative_fixture_missing",
                        "rust_runtime_semantics_unverified",
                        "source_shape_only",
                    ],
                    "suggested_next_action": "lift rust proof",
                    "memory_priority": 90,
                },
                {
                    "scanner_id": "move-backend-executor",
                    "pattern_id": "",
                    "backend": "move",
                    "source_paths": [],
                    "evidence_kind": "backend_executor_signal",
                    "wiring_status": "backend_executor_missing_or_tbd",
                    "proof_status": "no_known_executor_signal_found",
                    "blockers": ["move_executor_missing_or_unknown"],
                    "suggested_next_action": "add move executor",
                    "memory_priority": 85,
                },
                {
                    "scanner_id": "draft_detector",
                    "pattern_id": "",
                    "backend": "go",
                    "source_paths": ["detectors/wave17/draft_detector.py"],
                    "evidence_kind": "detector_python",
                    "wiring_status": "generated_no_fixture",
                    "proof_status": "generated_detector_without_fixture_pair",
                    "blockers": ["generated_or_draft_detector", "positive_or_vulnerable_fixture_missing"],
                    "suggested_next_action": "add fixtures",
                    "memory_priority": 80,
                },
                {
                    "scanner_id": "",
                    "pattern_id": "docs-scanner-overview",
                    "backend": "unknown",
                    "source_paths": ["docs/SCANNER_OVERVIEW.md"],
                    "evidence_kind": "doc_artifact",
                    "wiring_status": "documentation_only",
                    "proof_status": "report_or_doc_only",
                    "blockers": ["documentation_is_not_detector_wiring_proof"],
                    "suggested_next_action": "docs only",
                    "memory_priority": 30,
                },
                {
                    "scanner_id": "verified_detector",
                    "pattern_id": "",
                    "backend": "solidity",
                    "source_paths": ["detectors/wave18/verified_detector.py"],
                    "evidence_kind": "detector_python",
                    "wiring_status": "wired_verified",
                    "proof_status": "detector_and_fixture_pair_present",
                    "blockers": [],
                    "suggested_next_action": "keep wired",
                    "memory_priority": 20,
                },
            ],
        }

        queue = tool.build_burndown_queue(inventory, action_limit=4, per_lane_limit=2)
        self.assertEqual(queue["schema"], "auditooor.scanner_wiring_burndown_queue.v1")
        self.assertEqual(queue["top_action_count"], 4)
        self.assertTrue(queue["truncated"])
        self.assertEqual(
            [action["lane"] for action in queue["actions"]],
            [
                "retire_or_quarantine_fake",
                "rust_detector_lift",
                "wire_backend_executor",
                "add_fixture_or_proof",
            ],
        )
        self.assertEqual(queue["lane_counts"]["documentation_only"], 2)
        self.assertEqual(queue["status_counts"]["wired_verified"], 1)
        self.assertIn("Do not claim this scanner detects a real exploit", queue["actions"][0]["claim_guard"])
        self.assertNotIn("already-quarantined-dsl", {action["row_id"] for action in queue["actions"]})
        self.assertTrue(all(action["advisory_only"] for action in queue["actions"]))
        self.assertIn("suggested_commands", queue["actions"][0])
        self.assertGreaterEqual(len(queue["actions"][0]["suggested_commands"]), 1)
        self.assertEqual(queue["worker_slot_cap"], 11)
        self.assertEqual(queue["worker_slot_count"], 4)
        self.assertEqual(queue["next_worker_slots"][0]["task_kind"], "end_to_end_scanner_burndown_closure")
        self.assertEqual(queue["next_worker_slots"][0]["row_id"], "fake-dsl")
        self.assertIn("workers implement; coordinator reviews", queue["next_worker_slots"][0]["coordination_rules"][0])
        self.assertEqual(len(queue["lane_top_actions"]["retire_or_quarantine_fake"]), 1)
        self.assertEqual(len(queue["lane_top_actions"]["rust_detector_lift"]), 1)
        self.assertEqual(len(queue["lane_top_actions"]["wire_backend_executor"]), 1)
        self.assertEqual(len(queue["lane_top_actions"]["add_fixture_or_proof"]), 1)
        self.assertEqual(len(queue["lane_top_actions"]["documentation_only"]), 2)

    def test_build_burndown_report_closes_quarantine_and_reconciles_fixture_pairs(self):
        tool = _load_tool()
        inventory = {
            "schema": "auditooor.scanner_wiring_truth_inventory.v1",
            "limit": 7,
            "item_count": 7,
            "total_row_count": 7,
            "truncated": False,
            "rows": [
                {
                    "scanner_id": "already_quarantined",
                    "pattern_id": "",
                    "backend": "solidity",
                    "source_paths": ["detectors/wave_overnight_quarantine/already_quarantined.py"],
                    "evidence_kind": "detector_python",
                    "wiring_status": "quarantined_fake",
                    "proof_status": "quarantined_or_fake_detector_artifact",
                    "blockers": ["detector_must_not_count_as_wired", "quarantine_path_present"],
                    "suggested_next_action": "keep out of wired coverage memory unless explicitly restored with proof",
                    "memory_priority": 100,
                },
                {
                    "scanner_id": "fixture_pair_present",
                    "pattern_id": "",
                    "backend": "go",
                    "source_paths": [
                        "detectors/wave17/fixture_pair_present.py",
                        "patterns/fixtures/fixture-pair-present_clean.sol",
                        "patterns/fixtures/fixture-pair-present_vuln.sol",
                    ],
                    "evidence_kind": "detector_python",
                    "wiring_status": "generated_no_fixture",
                    "proof_status": "generated_detector_without_fixture_pair",
                    "blockers": ["generated_or_draft_detector", "positive_or_vulnerable_fixture_missing"],
                    "suggested_next_action": "materialize vulnerable/clean fixtures before counting as wired",
                    "memory_priority": 80,
                },
                {
                    "scanner_id": "missing_fixture_pair",
                    "pattern_id": "",
                    "backend": "move",
                    "source_paths": ["detectors/wave17/missing_fixture_pair.py"],
                    "evidence_kind": "detector_python",
                    "wiring_status": "generated_no_fixture",
                    "proof_status": "generated_detector_without_fixture_pair",
                    "blockers": ["generated_or_draft_detector", "positive_or_vulnerable_fixture_missing"],
                    "suggested_next_action": "materialize vulnerable/clean fixtures before counting as wired",
                    "memory_priority": 70,
                },
                {
                    "scanner_id": "rust_shape",
                    "pattern_id": "",
                    "backend": "rust",
                    "source_paths": ["detectors/rust_wave1/rust_shape.py"],
                    "evidence_kind": "detector_python",
                    "wiring_status": "rust_source_shape_only",
                    "proof_status": "source_shape_only",
                    "blockers": [
                        "positive_or_vulnerable_fixture_missing",
                        "clean_or_negative_fixture_missing",
                        "rust_runtime_semantics_unverified",
                        "source_shape_only",
                    ],
                    "suggested_next_action": "lift rust proof",
                    "memory_priority": 90,
                },
                {
                    "scanner_id": "move-backend-executor",
                    "pattern_id": "",
                    "backend": "move",
                    "source_paths": [],
                    "evidence_kind": "backend_executor_signal",
                    "wiring_status": "backend_executor_missing_or_tbd",
                    "proof_status": "no_known_executor_signal_found",
                    "blockers": ["move_executor_missing_or_unknown"],
                    "suggested_next_action": "add move executor",
                    "memory_priority": 85,
                },
                {
                    "scanner_id": "",
                    "pattern_id": "fake-dsl",
                    "backend": "solidity",
                    "source_paths": ["reference/patterns.dsl/fake-dsl.yaml"],
                    "evidence_kind": "dsl_yaml",
                    "wiring_status": "in_dsl_fake_suspect",
                    "proof_status": "fake_or_suspect_dsl_evidence",
                    "blockers": ["dsl_fake_or_suspect_marker_present", "detector_wiring_not_trusted"],
                    "suggested_next_action": "quarantine",
                    "memory_priority": 95,
                },
                {
                    "scanner_id": "",
                    "pattern_id": "already-quarantined-dsl",
                    "backend": "solidity",
                    "source_paths": ["reference/patterns.dsl/_quarantine/already-quarantined-dsl.yaml"],
                    "evidence_kind": "dsl_yaml",
                    "wiring_status": "in_dsl_fake_suspect",
                    "proof_status": "fake_or_suspect_dsl_evidence",
                    "blockers": ["dsl_fake_or_suspect_marker_present", "detector_wiring_not_trusted"],
                    "suggested_next_action": "quarantine",
                    "memory_priority": 100,
                },
            ],
        }

        report = tool.build_burndown_report(inventory, action_limit=4, per_lane_limit=2)

        self.assertEqual(report["schema"], "auditooor.scanner_wiring_burndown.v1")
        self.assertEqual(report["closed_row_counts"]["closed_quarantine"], 2)
        self.assertEqual(report["closed_gap_counts"]["fixture_pair_gap_closed_from_local_paths"], 1)
        self.assertEqual(report["blocker_counts"]["runtime_or_smoke_proof_missing"], 1)
        self.assertEqual(report["blocker_counts"]["fixture_pair_missing"], 1)
        self.assertEqual(report["blocker_counts"]["rust_runtime_semantics_unverified"], 1)
        self.assertEqual(report["blocker_counts"]["backend_executor_route_missing"], 1)
        self.assertEqual(report["blocker_counts"]["fake_dsl_requires_quarantine"], 1)
        self.assertEqual(
            [action["lane"] for action in report["actions"]],
            [
                "retire_or_quarantine_fake",
                "rust_detector_lift",
                "wire_backend_executor",
                "runtime_or_smoke_proof",
            ],
        )
        runtime_gap = report["actions"][3]
        self.assertTrue(runtime_gap["fixture_pair_visible_from_source_paths"])
        self.assertTrue(runtime_gap["fixture_gap_closed_from_local_paths"])
        self.assertEqual(runtime_gap["missing_evidence"], ["runtime_or_smoke_proof"])
        self.assertNotIn("positive_or_vulnerable_fixture_missing", runtime_gap["blockers"])
        self.assertIn("next_command", runtime_gap)
        self.assertEqual(report["worker_slot_cap"], 11)
        self.assertEqual(report["worker_slot_count"], 4)
        self.assertEqual(report["next_worker_slots"][0]["task_kind"], "end_to_end_scanner_burndown_closure")

    def test_build_burndown_report_closes_only_detector_backed_fixture_pairs(self):
        tool = _load_tool()
        inventory = {
            "schema": "auditooor.scanner_wiring_truth_inventory.v1",
            "limit": 3,
            "item_count": 3,
            "total_row_count": 3,
            "truncated": False,
            "rows": [
                {
                    "scanner_id": "",
                    "pattern_id": "can-withdraw-uses-entry-price",
                    "backend": "solidity",
                    "source_paths": [
                        "reference/patterns.dsl/can-withdraw-uses-entry-price.yaml",
                        "detectors/wave17/can_withdraw_uses_entry_price.py",
                        "patterns/fixtures/can-withdraw-uses-entry-price_clean.sol",
                        "patterns/fixtures/can-withdraw-uses-entry-price_vuln.sol",
                        "detectors/fixtures/can_withdraw_uses_entry_price/row_smoke.json",
                    ],
                    "evidence_kind": "dsl_yaml_with_detector_fixture_pair",
                    "wiring_status": "wired_verified",
                    "proof_status": "detector_and_fixture_pair_present",
                    "blockers": [],
                    "suggested_next_action": "keep wired",
                    "memory_priority": 20,
                },
                {
                    "scanner_id": "",
                    "pattern_id": "passive-doc-with-fixture-names",
                    "backend": "solidity",
                    "source_paths": [
                        "docs/passive-doc-with-fixture-names.md",
                        "patterns/fixtures/passive-doc-with-fixture-names_clean.sol",
                        "patterns/fixtures/passive-doc-with-fixture-names_vuln.sol",
                    ],
                    "evidence_kind": "doc_artifact",
                    "wiring_status": "wired_verified",
                    "proof_status": "detector_and_fixture_pair_present",
                    "blockers": ["documentation_is_not_detector_wiring_proof"],
                    "suggested_next_action": "link to detector",
                    "memory_priority": 35,
                },
            ],
        }

        report = tool.build_burndown_report(inventory, action_limit=5, per_lane_limit=5)

        self.assertEqual(report["closed_row_counts"]["closed_wired_fixture_pair"], 1)
        self.assertEqual(report["closed_row_count"], 1)
        open_ids = {row["row_id"] for row in report["actions"]}
        self.assertIn("passive-doc-with-fixture-names", open_ids)
        closed_ids = {row["row_id"] for row in report["closed_samples"]}
        self.assertIn("can-withdraw-uses-entry-price", closed_ids)

    def test_fail_closed_backend_gap_is_closed_and_excluded_from_action_queue(self):
        tool = _load_tool()
        inventory = {
            "schema": "auditooor.scanner_wiring_truth_inventory.v1",
            "limit": 2,
            "item_count": 2,
            "total_row_count": 2,
            "truncated": False,
            "rows": [
                {
                    "scanner_id": "move-backend-executor",
                    "pattern_id": "",
                    "backend": "move",
                    "source_paths": [
                        "tools/lang-detect.py",
                        "docs/POLYGLOT_WAVE2_2026-05-04.md",
                        "detectors/move_wave2/inflation_attack_zero_stake.py",
                    ],
                    "evidence_kind": "backend_executor_signal",
                    "wiring_status": "backend_executor_gap_fail_closed",
                    "proof_status": "no_shared_backend_executor_fail_closed",
                    "blockers": [
                        "move_shared_backend_executor_absent",
                        "lang_detect_loads_move_wave1_only",
                        "move_wave2_regression_harness_missing",
                    ],
                    "suggested_next_action": "fail closed until a shared Move executor exists",
                    "memory_priority": 45,
                },
                {
                    "scanner_id": "go-backend-executor",
                    "pattern_id": "",
                    "backend": "go",
                    "source_paths": ["tools/lang-detect.py", "detectors/go_wave1/test_fixtures/test_detectors.sh"],
                    "evidence_kind": "backend_executor_signal",
                    "wiring_status": "unknown",
                    "proof_status": "executor_signal_present_not_detector_proof",
                    "blockers": ["executor_presence_does_not_prove_individual_scanner_wiring"],
                    "suggested_next_action": "executor route is locally visible",
                    "memory_priority": 25,
                },
            ],
        }

        queue = tool.build_burndown_queue(inventory, action_limit=5, per_lane_limit=5)
        self.assertEqual(queue["top_action_count"], 1)
        self.assertNotIn("move-backend-executor", {row["row_id"] for row in queue["actions"]})

        report = tool.build_burndown_report(inventory, action_limit=5, per_lane_limit=5)
        self.assertEqual(report["closed_row_counts"]["closed_backend_gap_fail_closed"], 1)
        self.assertEqual(report["blocker_counts"], {"documentation_only": 1})
        closed = {row["row_id"]: row for row in report["closed_samples"]}
        self.assertIn("move-backend-executor", closed)
        self.assertEqual(closed["move-backend-executor"]["missing_evidence"], ["shared_backend_executor", "positive_clean_backend_harness"])
        self.assertTrue(closed["move-backend-executor"]["blocked_command_templates"])

    def test_cli_without_inventory_uses_latest_compatible_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reports = root / "reports"
            reports.mkdir()
            old_report = reports / "scanner_wiring_truth_inventory_2026-05-05.json"
            latest_report = reports / "scanner_wiring_truth_inventory_2026-05-08.json"
            incompatible_report = reports / "scanner_wiring_truth_inventory_2026-05-09.json"
            old_report.write_text(json.dumps(_inventory_with_row("old_row")), encoding="utf-8")
            latest_report.write_text(json.dumps(_inventory_with_row("latest_row")), encoding="utf-8")
            incompatible_report.write_text(json.dumps({"schema": "not-compatible", "rows": []}), encoding="utf-8")
            os.utime(old_report, (1, 1))
            os.utime(latest_report, (2, 2))
            os.utime(incompatible_report, (3, 3))

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--repo-root",
                    str(root),
                    "--print-json",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["source_inventory_path"], "reports/scanner_wiring_truth_inventory_2026-05-08.json")
            self.assertEqual([action["row_id"] for action in payload["actions"]], ["latest_row"])

    def test_cli_refresh_from_repo_ignores_stale_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reports = root / "reports"
            reports.mkdir()
            (reports / "scanner_wiring_truth_inventory_2026-05-05.json").write_text(
                json.dumps(_inventory_with_row("stale_row")),
                encoding="utf-8",
            )
            tool_dir = root / "tools"
            tool_dir.mkdir()
            (tool_dir / "scanner-wiring-truth-inventory.py").write_text(
                """
def build_inventory(repo_root, limit=None):
    return {
        "schema": "auditooor.scanner_wiring_truth_inventory.v1",
        "limit": limit,
        "item_count": 1,
        "total_row_count": 1,
        "truncated": False,
        "rows": [
            {
                "scanner_id": "live_row",
                "pattern_id": "",
                "backend": "solidity",
                "source_paths": ["detectors/wave17/live_row.py"],
                "evidence_kind": "detector_python",
                "wiring_status": "generated_no_fixture",
                "proof_status": "detector_without_fixture_pair",
                "blockers": ["positive_or_vulnerable_fixture_missing"],
                "suggested_next_action": "add fixtures",
                "memory_priority": 80,
            }
        ],
    }
""".lstrip(),
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--repo-root",
                    str(root),
                    "--refresh-from-repo",
                    "--live-inventory-limit",
                    "7",
                    "--print-json",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["source_inventory_path"], f"live:{root.resolve()}")
            self.assertEqual(payload["source_inventory_limit"], 7)
            self.assertEqual([action["row_id"] for action in payload["actions"]], ["live_row"])

    def test_cli_writes_json_and_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            inventory_path = ws / "inventory.json"
            json_out = ws / "queue.json"
            md_out = ws / "queue.md"
            inventory_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.scanner_wiring_truth_inventory.v1",
                        "limit": 2,
                        "item_count": 2,
                        "total_row_count": 2,
                        "truncated": True,
                        "rows": [
                            {
                                "scanner_id": "",
                                "pattern_id": "fake-row",
                                "backend": "solidity",
                                "source_paths": ["reference/patterns.dsl/fake-row.yaml"],
                                "evidence_kind": "dsl_yaml",
                                "wiring_status": "in_dsl_fake_suspect",
                                "proof_status": "fake_or_suspect_dsl_evidence",
                                "blockers": ["dsl_fake_or_suspect_marker_present"],
                                "suggested_next_action": "quarantine",
                                "memory_priority": 95,
                            },
                            {
                                "scanner_id": "go-backend-executor",
                                "pattern_id": "",
                                "backend": "go",
                                "source_paths": [],
                                "evidence_kind": "backend_executor_signal",
                                "wiring_status": "backend_executor_missing_or_tbd",
                                "proof_status": "no_known_executor_signal_found",
                                "blockers": ["go_executor_missing_or_unknown"],
                                "suggested_next_action": "add executor",
                                "memory_priority": 85,
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    str(inventory_path),
                    "--json-out",
                    str(json_out),
                    "--md-out",
                    str(md_out),
                    "--action-limit",
                    "1",
                    "--per-lane-limit",
                    "1",
                    "--print-json",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["top_action_count"], 1)
            self.assertTrue(json_out.is_file())
            self.assertTrue(md_out.is_file())
            written = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertTrue(written["source_inventory_truncated"])
            self.assertEqual(len(written["lane_top_actions"]["retire_or_quarantine_fake"]), 1)
            markdown = md_out.read_text(encoding="utf-8")
            self.assertIn("Source inventory truncated before queueing", markdown)
            self.assertIn("retire_or_quarantine_fake", markdown)
            self.assertIn("Command:", markdown)
            self.assertIn("Next Worker Slots", markdown)

    def test_cli_burndown_writes_reconciled_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            inventory_path = ws / "inventory.json"
            json_out = ws / "burndown.json"
            md_out = ws / "burndown.md"
            inventory_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.scanner_wiring_truth_inventory.v1",
                        "limit": 3,
                        "item_count": 3,
                        "total_row_count": 3,
                        "truncated": False,
                        "rows": [
                            {
                                "scanner_id": "already_quarantined",
                                "pattern_id": "",
                                "backend": "solidity",
                                "source_paths": ["detectors/wave_overnight_quarantine/already_quarantined.py"],
                                "evidence_kind": "detector_python",
                                "wiring_status": "quarantined_fake",
                                "proof_status": "quarantined_or_fake_detector_artifact",
                                "blockers": ["detector_must_not_count_as_wired", "quarantine_path_present"],
                                "suggested_next_action": "keep out of wired coverage memory unless explicitly restored with proof",
                                "memory_priority": 100,
                            },
                            {
                                "scanner_id": "fixture_pair_present",
                                "pattern_id": "",
                                "backend": "go",
                                "source_paths": [
                                    "detectors/wave17/fixture_pair_present.py",
                                    "patterns/fixtures/fixture-pair-present_clean.sol",
                                    "patterns/fixtures/fixture-pair-present_vuln.sol",
                                ],
                                "evidence_kind": "detector_python",
                                "wiring_status": "generated_no_fixture",
                                "proof_status": "generated_detector_without_fixture_pair",
                                "blockers": ["generated_or_draft_detector", "positive_or_vulnerable_fixture_missing"],
                                "suggested_next_action": "materialize vulnerable/clean fixtures before counting as wired",
                                "memory_priority": 80,
                            },
                            {
                                "scanner_id": "go-backend-executor",
                                "pattern_id": "",
                                "backend": "go",
                                "source_paths": [],
                                "evidence_kind": "backend_executor_signal",
                                "wiring_status": "backend_executor_missing_or_tbd",
                                "proof_status": "no_known_executor_signal_found",
                                "blockers": ["go_executor_missing_or_unknown"],
                                "suggested_next_action": "add executor",
                                "memory_priority": 85,
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    str(inventory_path),
                    "--mode",
                    "burndown",
                    "--json-out",
                    str(json_out),
                    "--md-out",
                    str(md_out),
                    "--action-limit",
                    "5",
                    "--per-lane-limit",
                    "2",
                    "--print-json",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["schema"], "auditooor.scanner_wiring_burndown.v1")
            self.assertEqual(payload["closed_row_counts"]["closed_quarantine"], 1)
            self.assertEqual(payload["closed_gap_counts"]["fixture_pair_gap_closed_from_local_paths"], 1)
            self.assertTrue(json_out.is_file())
            self.assertTrue(md_out.is_file())
            markdown = md_out.read_text(encoding="utf-8")
            self.assertIn("Closed This Pass", markdown)
            self.assertIn("runtime_or_smoke_proof_missing", markdown)
            self.assertIn("Next command:", markdown)


if __name__ == "__main__":
    unittest.main()
