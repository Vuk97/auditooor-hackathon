#!/usr/bin/env python3
"""Offline tests for tools/model-takeover-readiness.py."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "model-takeover-readiness.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("model_takeover_readiness", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _write_required_packet(root: Path) -> None:
    _write_json(
        root / "reports" / "shared_memory_index_2026-05-05.json",
        {"items": [{"id": "A"}, {"id": "B"}, {"id": "C"}]},
    )
    (root / "docs").mkdir(parents=True, exist_ok=True)
    (root / "docs" / "MEMORY_BRIEF_2026-05-05.md").write_text(
        "# Memory Brief\n\n- Current engagement state\n- Active blockers cleared\n",
        encoding="utf-8",
    )
    (root / "docs" / "KNOWN_LIMITATIONS_DISPATCH_2026-05-05.md").write_text(
        "# Known Limitations\n\n- Regex detectors are leads, not proof.\n",
        encoding="utf-8",
    )
    _write_json(
        root / "reports" / "scanner_wiring_burndown_queue_2026-05-05.json",
        {
            "schema": "auditooor.scanner_wiring_burndown_queue.v1",
            "status_counts": {"generated_no_fixture": 2},
            "next_worker_slots": [
                {
                    "slot_id": "scanner-slot-1",
                    "row_id": "sample_scanner_row",
                    "task_kind": "end_to_end_scanner_burndown_closure",
                    "lane": "add_fixture_or_proof",
                    "model_hint": "gpt-5.4/high",
                    "owned_paths": ["detectors/fixtures/sample_scanner_row"],
                    "acceptance_criteria": ["clean fixture produces zero hits"],
                }
            ],
        },
    )
    _write_json(
        root / "reports" / "harness_execution_queue_2026-05-05.json",
        {"rows": [{"row_id": f"H-{i}", "status": "queued"} for i in range(20)]},
    )
    _write_json(
        root / "reports" / "source_mirror_verify_2026-05-05.json",
        {"results": [{"path": "src/A.sol", "status": "verified"}]},
    )
    _write_json(
        root / "reports" / "commit_mining_scan_tasks_2026-05-05.json",
        {"tasks": [{"task_id": "scan-A", "lane": "mirror_verified_source_review"}]},
    )


class BuildPacketTests(unittest.TestCase):
    def test_all_required_artifacts_ready_and_bounded(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_required_packet(root)
            packet = mod.build_packet(root, max_items=5)

        self.assertEqual(packet["readiness_counts"], {"READY": 3, "WARN": 0, "BLOCKED": 0})
        self.assertEqual(packet["categories"]["known_limitation_burndown"]["status"], "READY")
        scanner = next(a for a in packet["artifacts"] if a["key"] == "scanner_wiring_burndown")
        self.assertEqual(scanner["bounded_items"][0]["worker_slot"]["row_id"], "sample_scanner_row")
        self.assertEqual(scanner["bounded_items"][0]["worker_slot"]["owned_paths"], ["detectors/fixtures/sample_scanner_row"])
        self.assertEqual(packet["categories"]["harness"]["status"], "READY")
        harness = next(
            a for a in packet["artifacts"] if a["key"] == "harness_execution_queue"
        )
        self.assertEqual(harness["item_count"], 20)
        self.assertEqual(harness["bounded_item_count"], 5)
        self.assertGreater(packet["token_estimates"]["est_token_savings"], 0)
        self.assertEqual(packet["fail_closed_blockers"], [])

    def test_scanner_burndown_prefers_selector_backed_klb_memory_status(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_required_packet(root)
            _write_json(
                root / "reports" / "known_limitations_harness_memory_status_2026-05-05.json",
                {
                    "schema": "auditooor.known_limitations_harness_memory_status.v1",
                    "scanner_burndown_snapshot": {
                        "status": "open_actions_present",
                        "next_worker_slots": [
                            {
                                "slot_id": "scanner-slot-1",
                                "row_id": "selector_row",
                                "task_kind": "end_to_end_scanner_burndown_closure",
                                "lane": "add_fixture_or_proof",
                                "model_hint": "gpt-5.5/high",
                                "local_coordination_status": "unclaimed_from_local_checkout",
                                "coordination_note": "selected by scanner-worker-next-rows",
                                "owned_paths": ["detectors/fixtures/selector_row"],
                                "acceptance_criteria": ["clean fixture produces zero hits"],
                            }
                        ],
                        "skipped_worker_slot_count": 47,
                        "skipped_worker_slots": [
                            {
                                "slot_id": "skipped-scanner-slot-1",
                                "row_id": "already_done_row",
                                "lane": "add_fixture_or_proof",
                                "local_coordination_status": "already_committed",
                                "skip_reason": "already_committed",
                                "committed_after_queue_paths": ["tools/tests/test_already_done_row.py"],
                                "coordination_note": "row-local evidence paths were committed after the queue baseline",
                            }
                        ],
                        "worker_slot_coordination_counts": {
                            "already_committed": 46,
                            "claimed_dirty_worktree": 1,
                            "unclaimed_from_local_checkout": 1,
                        },
                        "scanner_coordination_guidance": {
                            "do_not_redispatch_statuses": ["already_committed", "claimed_dirty_worktree"],
                            "do_not_redispatch_sample_row_ids": ["already_done_row"],
                            "refresh_inventory_before_more_detector_assignments": True,
                            "refresh_recommended_statuses": ["already_committed"],
                            "reason": "refresh scanner inventory before assigning more detector work",
                        },
                        "scanner_worker_next_rows": {
                            "selection": {
                                "selected_count": 1,
                                "candidate_rows_scanned": 49,
                                "skipped_counts": {
                                    "already_committed": 46,
                                    "claimed_dirty_worktree": 1,
                                },
                            }
                        },
                    },
                },
            )

            packet = mod.build_packet(root, max_items=5)

        scanner = next(a for a in packet["artifacts"] if a["key"] == "scanner_wiring_burndown")
        self.assertEqual(scanner["path"], "reports/known_limitations_harness_memory_status_2026-05-05.json")
        self.assertEqual(scanner["bounded_items"][0]["worker_slot"]["row_id"], "selector_row")
        self.assertEqual(
            scanner["bounded_items"][0]["worker_slot"]["local_coordination_status"],
            "unclaimed_from_local_checkout",
        )
        self.assertEqual(
            scanner["bounded_items"][0]["worker_slot"]["coordination_note"],
            "selected by scanner-worker-next-rows",
        )
        summary = scanner["snapshot_summary"]
        self.assertEqual(summary["worker_slot_count"], 1)
        self.assertEqual(summary["skipped_worker_slot_count"], 47)
        self.assertTrue(
            summary["scanner_coordination_guidance"]["refresh_inventory_before_more_detector_assignments"]
        )
        self.assertEqual(
            summary["skipped_worker_slot_samples"][0]["committed_after_queue_paths"],
            ["tools/tests/test_already_done_row.py"],
        )
        self.assertEqual(summary["worker_slot_coordination_counts"]["already_committed"], 46)
        self.assertEqual(
            summary["selector_skipped_or_already_counts"][
                "scanner_worker_next_rows.selection.skipped_counts.claimed_dirty_worktree"
            ],
            1,
        )
        self.assertEqual(packet["categories"]["known_limitation_burndown"]["status"], "READY")

    def test_malformed_selector_backed_scanner_snapshot_fails_closed(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_required_packet(root)
            _write_json(
                root / "reports" / "known_limitations_harness_memory_status_2026-05-05.json",
                {
                    "schema": "auditooor.known_limitations_harness_memory_status.v1",
                    "scanner_burndown_snapshot": {"status": "open_actions_present"},
                },
            )

            packet = mod.build_packet(root)

        scanner = next(a for a in packet["artifacts"] if a["key"] == "scanner_wiring_burndown")
        self.assertEqual(
            scanner["parse_error"],
            "missing scanner_burndown_snapshot.next_worker_slots list",
        )
        self.assertEqual(packet["categories"]["known_limitation_burndown"]["status"], "BLOCKED")
        self.assertTrue(
            any("scanner wiring burndown parse failed" in b["message"] for b in packet["fail_closed_blockers"])
        )

    def test_missing_core_artifacts_fail_closed(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            packet = mod.build_packet(root)

        self.assertEqual(packet["readiness_counts"]["BLOCKED"], 3)
        blockers = [b["message"] for b in packet["fail_closed_blockers"]]
        self.assertIn("missing required shared-memory index", blockers)
        self.assertIn("missing required scanner wiring burndown", blockers)
        self.assertIn("missing required source mirror verify", blockers)
        self.assertIn("missing required commit-mining scan tasks", blockers)

    def test_source_verify_without_positive_status_blocks(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_required_packet(root)
            _write_json(
                root / "reports" / "source_mirror_verify_2026-05-05.json",
                {"results": [{"path": "src/A.sol", "status": "blocked"}]},
            )
            packet = mod.build_packet(root)

        self.assertEqual(packet["categories"]["source"]["status"], "BLOCKED")
        self.assertTrue(
            any("no positive" in b["message"] for b in packet["fail_closed_blockers"])
        )

    def test_advisory_only_harness_queue_warns_not_ready(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_required_packet(root)
            _write_json(
                root / "reports" / "harness_execution_queue_2026-05-05.json",
                {
                    "schema": "auditooor.harness_execution_queue.v0",
                    "counts_by_status": {"advisory_only": 1},
                    "rows": [
                        {
                            "row_id": "KLBQ-004",
                            "status": "advisory_only",
                            "ready_command_count": 0,
                            "expected_next_action": "treat as advisory/status evidence",
                        }
                    ],
                },
            )

            packet = mod.build_packet(root)

        self.assertEqual(packet["categories"]["harness"]["status"], "WARN")
        self.assertIn(
            "harness execution queue has no ready/queued runnable command rows",
            packet["categories"]["harness"]["warnings"],
        )
        self.assertEqual(packet["fail_closed_blockers"], [])

    def test_missing_entrypoint_report_is_dependency_note_only(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_required_packet(root)

            packet = mod.build_packet(root)
            markdown = mod.render_markdown(packet)

        self.assertEqual(packet["readiness_counts"], {"READY": 3, "WARN": 0, "BLOCKED": 0})
        self.assertEqual(packet["bounds"]["artifact_search_roots"], [str(root.resolve())])
        self.assertEqual(packet["bounds"]["obsidian_entrypoint_reports"], [])
        self.assertEqual(packet["dependency_notes"][0]["key"], "obsidian_memory_entrypoints")
        self.assertIn("repo-local paths", packet["dependency_notes"][0]["message"])
        self.assertIn("## Dependency notes", markdown)

    def test_entrypoint_memory_root_supplies_current_artifacts(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            memory_root = Path(tmp) / "memory"
            root.mkdir()
            _write_json(
                root / "reports" / "obsidian_memory_entrypoints_2026-05-05.json",
                {
                    "memory_root": str(memory_root),
                    "memory_brief_entrypoints": [
                        {
                            "exists": True,
                            "path": "reports/memory_brief_2026-05-05.json",
                        }
                    ],
                    "shared_memory_entrypoints": [
                        {
                            "exists": True,
                            "path": "reports/shared_memory_index_2026-05-05.json",
                        }
                    ],
                },
            )
            _write_required_packet(memory_root)

            packet = mod.build_packet(root)

        self.assertEqual(packet["readiness_counts"], {"READY": 3, "WARN": 0, "BLOCKED": 0})
        self.assertIn(
            str(memory_root.resolve()), packet["bounds"]["artifact_search_roots"]
        )
        self.assertEqual(packet["dependency_notes"], [])
        memory_brief = next(a for a in packet["artifacts"] if a["key"] == "memory_brief")
        self.assertEqual(memory_brief["source_root"], str(memory_root.resolve()))


class CliTests(unittest.TestCase):
    def test_cli_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_required_packet(root)
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--root",
                    str(root),
                    "--out",
                    "reports/packet.json",
                    "--doc",
                    "docs/packet.md",
                    "--json",
                    "--max-items-per-artifact",
                    "3",
                ],
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["readiness_counts"]["READY"], 3)
            self.assertTrue((root / "reports" / "packet.json").is_file())
            self.assertTrue((root / "docs" / "packet.md").is_file())

    def test_fail_on_blockers_returns_two_after_writing_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--root",
                    str(root),
                    "--out",
                    "reports/packet.json",
                    "--doc",
                    "docs/packet.md",
                    "--fail-on-blockers",
                ],
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 2)
            self.assertTrue((root / "reports" / "packet.json").is_file())
            self.assertTrue((root / "docs" / "packet.md").is_file())


if __name__ == "__main__":
    unittest.main()
