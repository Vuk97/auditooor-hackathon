#!/usr/bin/env python3
"""Offline tests for tools/model-takeover-handoff.py."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "model-takeover-handoff.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("model_takeover_handoff", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["model_takeover_handoff"] = module
    spec.loader.exec_module(module)
    return module


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _fixture_report(root: Path) -> dict[str, object]:
    return {
        "schema": "auditooor.model_takeover_readiness.v1",
        "generated_at": "2026-05-05T18:56:36+00:00",
        "root": str(root.resolve()),
        "categories": {
            "context": {"label": "Context transfer", "status": "READY", "blockers": [], "warnings": []},
            "limits": {
                "label": "Known limitations",
                "status": "WARN",
                "blockers": [],
                "warnings": ["known limitations dispatch contains failing/blocked status rows"],
            },
            "known_limitation_burndown": {
                "label": "Known limitation burndown",
                "status": "READY",
                "blockers": [],
                "warnings": [],
            },
            "harness": {
                "label": "Harness execution",
                "status": "WARN",
                "blockers": [],
                "warnings": ["harness execution queue contains failing/blocked status rows"],
            },
            "source": {
                "label": "Source mirror",
                "status": "WARN",
                "blockers": [],
                "warnings": ["source mirror verify contains failing/blocked status rows"],
            },
            "commit_mining": {"label": "Commit-mining scan tasks", "status": "READY", "blockers": [], "warnings": []},
        },
        "provider_gates": {
            "claude": {
                "display_name": "Claude",
                "status": "WARN",
                "readiness_estimate_percent": 88,
                "target_packet_tokens": 60000,
            },
            "kimi": {
                "display_name": "Kimi",
                "status": "WARN",
                "readiness_estimate_percent": 88,
                "target_packet_tokens": 48000,
            },
            "minimax": {
                "display_name": "Minimax",
                "status": "WARN",
                "readiness_estimate_percent": 88,
                "target_packet_tokens": 48000,
            },
        },
        "artifacts": [
            {
                "key": "shared_memory_index",
                "category": "context",
                "label": "shared-memory index",
                "required": True,
                "present": True,
                "path": "reports/shared_memory_index_2026-05-05.json",
                "format": "json",
                "status_counts": {},
                "parse_error": None,
                "bounded_items": [{"index": 0, "status": None, "summary": "context summary row"}],
            },
            {
                "key": "memory_brief",
                "category": "context",
                "label": "memory brief",
                "required": True,
                "present": True,
                "path": "reports/memory_brief_2026-05-05.json",
                "format": "json",
                "status_counts": {},
                "parse_error": None,
                "bounded_items": [{"index": 0, "status": None, "summary": "memory brief row"}],
            },
            {
                "key": "known_limitations_dispatch",
                "category": "limits",
                "label": "known limitations dispatch",
                "required": True,
                "present": True,
                "path": "reports/known_limitations_dispatch_2026-05-05.json",
                "format": "json",
                "status_counts": {"open_blocked": 3},
                "parse_error": None,
                "bounded_items": [
                    {"index": 0, "status": "open_blocked", "summary": "KLBQ-001 blocker"},
                    {"index": 1, "status": "implemented_verified", "summary": "KLBQ-002 done"},
                    {"index": 2, "status": "open_blocked", "summary": "KLBQ-003 blocker"},
                ],
            },
            {
                "key": "scanner_wiring_burndown",
                "category": "known_limitation_burndown",
                "label": "scanner wiring burndown",
                "required": True,
                "present": True,
                "path": "reports/scanner_wiring_burndown_queue_2026-05-05.json",
                "format": "json",
                "status_counts": {"generated_no_fixture": 4},
                "parse_error": None,
                "snapshot_summary": {
                    "skipped_worker_slot_count": 2,
                    "selector_skipped_or_already_counts": {
                        "scanner_worker_next_rows.selection.skipped_counts.already_committed": 46,
                        "scanner_worker_next_rows.selection.skipped_counts.claimed_dirty_worktree": 1,
                    },
                    "scanner_coordination_guidance": {
                        "do_not_redispatch_statuses": ["claimed_dirty_worktree", "already_committed"],
                        "do_not_redispatch_sample_row_ids": ["sample_scanner_row", "already_done_row"],
                        "refresh_inventory_before_more_detector_assignments": True,
                        "refresh_recommended_statuses": ["already_committed"],
                        "reason": "refresh scanner inventory before assigning more detector work",
                    },
                    "skipped_worker_slot_samples": [
                        {
                            "row_id": "already_done_row",
                            "skip_reason": "already_committed",
                            "matching_dirty_paths": [],
                            "local_evidence_paths": [],
                            "committed_after_queue_paths": ["tools/tests/test_already_done_row.py"],
                        }
                    ],
                },
                "bounded_items": [
                    {
                        "index": 0,
                        "status": None,
                        "summary": "sample_scanner_row",
                        "worker_slot": {
                            "slot_id": "scanner-slot-1",
                            "row_id": "sample_scanner_row",
                            "lane": "add_fixture_or_proof",
                            "model_hint": "gpt-5.4/high",
                            "local_coordination_status": "claimed_dirty_worktree",
                            "owned_paths": ["detectors/fixtures/sample_scanner_row"],
                        },
                    }
                ],
            },
            {
                "key": "harness_execution_queue",
                "category": "harness",
                "label": "harness execution queue",
                "required": True,
                "present": True,
                "path": "reports/harness_execution_queue_2026-05-05.json",
                "format": "json",
                "status_counts": {"blocked_missing_inputs": 8},
                "parse_error": None,
                "bounded_items": [{"index": 0, "status": "blocked_missing_inputs", "summary": "H-001 blocked"}],
            },
            {
                "key": "source_mirror_verify",
                "category": "source",
                "label": "source mirror verify",
                "required": True,
                "present": True,
                "path": "reports/source_mirror_verify_2026-05-05.json",
                "format": "json",
                "status_counts": {"verified": 4, "blocked": 1},
                "parse_error": None,
                "bounded_items": [{"index": 0, "status": "blocked", "summary": "BA-BLOB-01 blocked"}],
            },
            {
                "key": "commit_mining_scan_tasks",
                "category": "commit_mining",
                "label": "commit-mining scan tasks",
                "required": True,
                "present": True,
                "path": "reports/commit_mining_scan_tasks_2026-05-05.json",
                "format": "json",
                "status_counts": {},
                "parse_error": None,
                "bounded_items": [{"index": 0, "status": None, "summary": "scan task row"}],
            },
        ],
    }


FIXTURE_DOC = """# Model Takeover Readiness Packet

## Provider gates

| Provider | Status | Readiness estimate | Target packet tokens |
|---|---:|---:|---:|
| Claude | WARN | 88% | 60000 |
| Kimi | WARN | 88% | 48000 |
| Minimax | WARN | 88% | 48000 |
"""


class BuildPacketTests(unittest.TestCase):
    def test_builds_bounded_provider_packets_without_token_savings_artifact(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_json(
                root / "reports" / "model_takeover_readiness_2026-05-05.json",
                _fixture_report(root),
            )
            _write_text(root / "docs" / "MODEL_TAKEOVER_READINESS_2026-05-05.md", FIXTURE_DOC)

            packet = mod.build_packet(
                root,
                bounds=mod.Bounds.from_values(max_artifacts=3, max_items_per_artifact=1, max_text_chars=90),
            )

        self.assertFalse(packet["fail_closed"])
        self.assertNotIn("token_estimates", packet)
        self.assertEqual(set(packet["providers"]), {"claude", "kimi", "minimax"})
        self.assertEqual(packet["mode"], "full")
        self.assertEqual(packet["compact_check"]["policy_results"][1]["status"], "READY")
        claude = packet["providers"]["claude"]
        self.assertEqual(claude["takeover_posture"], "bounded_warn_handoff_only")
        self.assertTrue(claude["handoff_allowed"])
        self.assertLessEqual(len(claude["artifact_focus"]), 3)
        for artifact in claude["artifact_focus"]:
            self.assertLessEqual(len(artifact["bounded_items"]), 1)
        self.assertIn(
            "scanner_wiring_burndown",
            {artifact["key"] for artifact in claude["artifact_focus"]},
        )
        scanner = next(artifact for artifact in claude["artifact_focus"] if artifact["key"] == "scanner_wiring_burndown")
        self.assertEqual(scanner["bounded_items"][0]["worker_slot"]["row_id"], "sample_scanner_row")
        self.assertEqual(
            scanner["snapshot_summary"]["selector_skipped_or_already_counts"][
                "scanner_worker_next_rows.selection.skipped_counts.already_committed"
            ],
            46,
        )
        self.assertTrue(
            scanner["snapshot_summary"]["scanner_coordination_guidance"][
                "refresh_inventory_before_more_detector_assignments"
            ]
        )
        markdown = mod.render_markdown(packet)
        self.assertIn("coordination=`claimed_dirty_worktree`", markdown)
        self.assertIn("refresh_before_more_detector_assignments=`true`", markdown)
        self.assertIn(
            "selector_skipped_or_already_counts: "
            "`scanner_worker_next_rows.selection.skipped_counts.already_committed=46`",
            markdown,
        )
        self.assertIn("tools/tests/test_already_done_row.py", markdown)
        self.assertIn("Only executed local commands", claude["proof_boundary"])
        self.assertFalse(claude["bootstrap_query"]["present"])

    def test_missing_doc_or_report_fails_closed(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            packet = mod.build_packet(root)

        self.assertTrue(packet["fail_closed"])
        messages = [row["message"] for row in packet["fail_closed_blockers"]]
        self.assertTrue(any("reports/model_takeover_readiness_2026-05-05.json: missing file" in msg for msg in messages))
        self.assertTrue(any("docs/MODEL_TAKEOVER_READINESS_2026-05-05.md: missing file" in msg for msg in messages))
        self.assertFalse(packet["providers"]["claude"]["handoff_allowed"])

    def test_doc_report_mismatch_fails_closed(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = _fixture_report(root)
            report["provider_gates"]["kimi"]["target_packet_tokens"] = 47000
            _write_json(root / "reports" / "model_takeover_readiness_2026-05-05.json", report)
            _write_text(root / "docs" / "MODEL_TAKEOVER_READINESS_2026-05-05.md", FIXTURE_DOC)

            packet = mod.build_packet(root)

        self.assertTrue(packet["fail_closed"])
        mismatch = [row for row in packet["fail_closed_blockers"] if row["scope"] == "kimi"]
        self.assertEqual(len(mismatch), 1)
        self.assertIn("target_packet_tokens", mismatch[0]["message"])

    def test_compact_check_surfaces_bootstrap_query_and_uses_tighter_bounds(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_json(
                root / "reports" / "model_takeover_readiness_2026-05-05.json",
                _fixture_report(root),
            )
            _write_text(root / "docs" / "MODEL_TAKEOVER_READINESS_2026-05-05.md", FIXTURE_DOC)
            _write_text(
                root / "agent_briefs" / "AGENT_BOOTSTRAP_QUERY_2026-05-05.md",
                "# Query\n\n- Reopen compact takeover inputs first.\n",
            )

            packet = mod.build_packet(root, bounds=mod.COMPACT_BOUNDS, mode=mod.COMPACT_CHECK_MODE)

        self.assertFalse(packet["fail_closed"])
        self.assertEqual(packet["mode"], "compact-check")
        self.assertEqual(packet["bounds"]["max_artifacts_per_provider"], 3)
        self.assertEqual(packet["bounds"]["max_items_per_artifact"], 1)
        self.assertEqual(
            packet["compact_check"]["bootstrap_query"]["path"],
            "agent_briefs/AGENT_BOOTSTRAP_QUERY_2026-05-05.md",
        )
        self.assertEqual(packet["compact_check"]["policy_results"][0]["status"], "READY")

    def test_stale_worktree_root_and_broad_doc_artifact_fail_closed(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = _fixture_report(root)
            report["root"] = "/Users/wolf/auditooor-worktrees/continuation-plan-update"
            report["artifacts"][0]["path"] = "docs/CURRENT_STATE.md"
            _write_json(root / "reports" / "model_takeover_readiness_2026-05-05.json", report)
            _write_text(root / "docs" / "MODEL_TAKEOVER_READINESS_2026-05-05.md", FIXTURE_DOC)

            packet = mod.build_packet(root, mode=mod.COMPACT_CHECK_MODE)

        self.assertTrue(packet["fail_closed"])
        policy = {row["key"]: row for row in packet["compact_check"]["policy_results"]}
        self.assertEqual(policy["recovery_branch_safety"]["status"], "BLOCKED")
        self.assertEqual(policy["blocked_worktree_state"]["status"], "BLOCKED")
        self.assertEqual(policy["broad_docs_not_live_state"]["status"], "BLOCKED")
        blocker_messages = [row["message"] for row in packet["fail_closed_blockers"]]
        self.assertTrue(any("current worktree" in message for message in blocker_messages))
        self.assertTrue(any("continuation-plan-update" in message for message in blocker_messages))


class CliTests(unittest.TestCase):
    def test_cli_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_json(
                root / "reports" / "model_takeover_readiness_2026-05-05.json",
                _fixture_report(root),
            )
            _write_text(root / "docs" / "MODEL_TAKEOVER_READINESS_2026-05-05.md", FIXTURE_DOC)

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--root",
                    str(root),
                    "--stdout-format",
                    "json",
                    "--max-artifacts",
                    "2",
                    "--max-items-per-artifact",
                    "1",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertFalse(payload["fail_closed"])
            self.assertTrue((root / "reports" / "model_takeover_provider_handoff_2026-05-05.json").is_file())
            self.assertTrue((root / "docs" / "MODEL_TAKEOVER_PROVIDER_HANDOFF_2026-05-05.md").is_file())

    def test_compact_mode_cli_prints_compact_packet(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_json(
                root / "reports" / "model_takeover_readiness_2026-05-05.json",
                _fixture_report(root),
            )
            _write_text(root / "docs" / "MODEL_TAKEOVER_READINESS_2026-05-05.md", FIXTURE_DOC)

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--root",
                    str(root),
                    "--mode",
                    "compact-check",
                    "--stdout-format",
                    "json",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["mode"], "compact-check")
            self.assertEqual(payload["bounds"]["max_artifacts_per_provider"], 3)
            self.assertEqual(payload["bounds"]["max_items_per_artifact"], 1)

    def test_fail_on_blockers_returns_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--root",
                    str(root),
                    "--stdout-format",
                    "none",
                    "--fail-on-blockers",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 2)
            self.assertTrue((root / "reports" / "model_takeover_provider_handoff_2026-05-05.json").is_file())
            self.assertTrue((root / "docs" / "MODEL_TAKEOVER_PROVIDER_HANDOFF_2026-05-05.md").is_file())


if __name__ == "__main__":
    unittest.main()
