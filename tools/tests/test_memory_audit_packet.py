from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "memory-audit-packet.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("memory_audit_packet", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["memory_audit_packet"] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).strip() + "\n", encoding="utf-8")


def _write_scanner_truth(path: Path, *, item_count: int, wiring_status: str) -> None:
    _write_json(
        path,
        {
            "schema": "auditooor.scanner_wiring_truth_inventory.v1",
            "item_count": item_count,
            "rows": [
                {
                    "scanner_id": f"{path.stem}_{index}",
                    "wiring_status": wiring_status,
                    "backend": "solidity",
                }
                for index in range(item_count)
            ],
        },
    )


class MemoryAuditPacketTests(unittest.TestCase):
    def test_build_packet_from_fixture_reports_preserves_required_sections_and_caveats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_json(
                root / "reports" / "known_limitations_burndown_queue_2026-05-05.json",
                {
                    "schema": "auditooor.known_limitations_burndown_queue.v1",
                    "implementation_summary": {
                        "implemented_v0": ["KLBQ-005"],
                        "partially_implemented_v0": ["KLBQ-004"],
                        "open": ["KLBQ-001"],
                    },
                    "rows": [
                        {
                            "rank": 1,
                            "id": "KLBQ-001",
                            "implementation_status": "partially_implemented_v0",
                            "owner_lane": "source replay",
                            "concrete_next_patch": "Materialize exact source-ref fixture evidence.",
                            "verification_status": "partial_pass",
                            "remaining_blockers": ["fixture report missing"],
                            "not_submission_evidence": True,
                        }
                    ],
                },
            )
            _write_json(
                root / "reports" / "scanner_wiring_truth_inventory_2026-05-05.json",
                {
                    "item_count": 2,
                    "rows": [
                        {"wiring_status": "wired_verified", "backend": "solidity"},
                        {"wiring_status": "dsl_only_or_unverified", "backend": "solidity"},
                    ],
                },
            )
            _write_json(
                root / "reports" / "no_reason_decline_memory_2026-05-05.json",
                {
                    "decision": {
                        "classification": "unknown-reason decline",
                        "memory_effect": "platform/base-rate calibration only",
                        "forbid_inference": ["duplicate", "out_of_scope", "proof_failure"],
                    }
                },
            )

            packet = MOD.build_packet(root)

            self.assertEqual(packet["schema"], "auditooor.memory_audit_packet.v0")
            for key in (
                "objective_snapshot",
                "active_constraints",
                "audit_readiness",
                "top_next_actions",
                "blocked_items",
                "model_handoff_notes",
                "cli_usage",
                "token_savings_assumptions",
            ):
                self.assertIn(key, packet)
            caveats = " ".join(packet["objective_snapshot"]["strict_caveats"])
            self.assertIn("does not claim exploitability", caveats)
            self.assertIn("No-reason declines cannot be learned as pattern false positives", caveats)
            self.assertIn("known_limitations_queue", packet["audit_readiness"])
            self.assertIn("scanner_wiring_truth", packet["audit_readiness"])
            self.assertIn("no_reason_decline_memory", packet["audit_readiness"])
            self.assertEqual(packet["top_next_actions"][0]["id"], "KLBQ-001")
            self.assertTrue(
                any(item["id"] == "scanner_wiring_truth" for item in packet["blocked_items"])
            )

    def test_commit_lifecycle_ledger_is_part_of_handoff_packet(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_json(
                root / "reports" / "commit_lifecycle_ledger_2026-05-05.json",
                {
                    "schema": "auditooor.commit_lifecycle_ledger.v1",
                    "network_used": False,
                    "proof_boundary": "routing memory only",
                    "summary": {
                        "row_count": 33,
                        "queue_count": 1,
                        "state_counts": [{"name": "blocked_short_or_named_ref", "count": 23}],
                        "lane_counts": [{"name": "source_review_only", "count": 5}],
                    },
                    "coverage_limits": ["short refs still need full SHA resolution"],
                    "concrete_queue": [
                        {
                            "item_id": "Q1-corpus-row-artifact",
                            "lane": "source_review_only",
                            "detail": "Materialize one row per reference before claiming lifecycle coverage.",
                        }
                    ],
                },
            )

            packet = MOD.build_packet(root, bounds=MOD.PacketBounds.from_values(max_items=4, max_text=120))

        lifecycle = packet["audit_readiness"]["commit_lifecycle_ledger"]
        self.assertEqual(lifecycle["row_count"], 33)
        self.assertIn("blocked_short_or_named_ref: 23", lifecycle["state_counts"])
        self.assertTrue(
            any(item["id"] == "Q1-corpus-row-artifact" for item in packet["top_next_actions"])
        )
        self.assertTrue(
            any(item["id"] == "commit_lifecycle_coverage_limits" for item in packet["blocked_items"])
        )

    def test_packet_text_masks_absolute_worktree_roots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stale_root = "/Users/wolf/auditooor-worktrees/old-worker-root"
            _write_json(
                root / "reports" / "commit_lifecycle_ledger_2026-05-05.json",
                {
                    "schema": "auditooor.commit_lifecycle_ledger.v1",
                    "summary": {"row_count": 1, "queue_count": 0},
                    "coverage_limits": [
                        f"{stale_root}/reports/source.json still needs source-root refresh"
                    ],
                },
            )

            packet = MOD.build_packet(root, bounds=MOD.PacketBounds.from_values(max_items=4, max_text=180))

        rendered_packet = json.dumps(packet, sort_keys=True)
        self.assertNotIn(stale_root, rendered_packet)
        self.assertIn("[worktree-root:old-worker-root]/reports/source.json", rendered_packet)

    def test_known_limitations_summary_mismatch_fails_closed_and_rows_are_authority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_json(
                root / "reports" / "known_limitations_burndown_queue_2026-05-05.json",
                {
                    "schema": "auditooor.known_limitations_burndown_queue.v1",
                    "implementation_summary": {
                        "implemented_v0": [],
                        "partially_implemented_v0": [],
                        "open": ["KLBQ-008"],
                    },
                    "rows": [
                        {
                            "rank": 1,
                            "id": "KLBQ-008",
                            "implementation_status": "implemented_v0",
                            "owner_lane": "submission finalization / memory recall",
                            "concrete_next_patch": "Stale summary should not create an action.",
                            "verification_status": "pass",
                            "remaining_blockers": [],
                        }
                    ],
                },
            )

            packet = MOD.build_packet(root)

        queue = packet["audit_readiness"]["known_limitations_queue"]
        consistency = queue["summary_consistency"]
        self.assertEqual(queue["counts_source"], "row_level_implementation_status")
        self.assertEqual(queue["implemented_v0"], 1)
        self.assertEqual(queue["open"], 0)
        self.assertEqual(queue["implementation_summary_counts"]["open"], 1)
        self.assertFalse(queue["implementation_summary_trusted"])
        self.assertEqual(consistency["status"], "mismatch_fail_closed")
        self.assertEqual(consistency["mismatches"][0]["id"], "KLBQ-008")
        self.assertEqual(consistency["mismatches"][0]["summary_bucket"], "open")
        self.assertEqual(consistency["mismatches"][0]["row_bucket"], "implemented_v0")
        self.assertFalse(any(action["id"] == "KLBQ-008" for action in packet["top_next_actions"]))
        self.assertTrue(
            any(item["id"] == "known_limitations_summary_consistency" for item in packet["blocked_items"])
        )
        rendered = MOD.render_doc(packet)
        self.assertIn("counts_source=row_level_implementation_status", rendered)
        self.assertIn("implementation_summary_trusted=False", rendered)

    def test_known_limitations_row_partial_status_stays_open_when_summary_says_implemented(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_json(
                root / "reports" / "known_limitations_burndown_queue_2026-05-05.json",
                {
                    "implementation_summary": {
                        "implemented_v0": ["KLBQ-001"],
                        "partially_implemented_v0": [],
                        "open": [],
                    },
                    "rows": [
                        {
                            "rank": 1,
                            "id": "KLBQ-001",
                            "implementation_status": "partially_implemented_v0",
                            "owner_lane": "source replay",
                            "concrete_next_patch": "Wire manifest builder into detector/report generation.",
                            "verification_status": "partial_pass",
                            "remaining_blockers": ["detector/report generation still drops github_ref"],
                        }
                    ],
                },
            )

            packet = MOD.build_packet(root)

        queue = packet["audit_readiness"]["known_limitations_queue"]
        self.assertEqual(queue["implemented_v0"], 0)
        self.assertEqual(queue["partially_implemented_v0"], 1)
        self.assertFalse(queue["implementation_summary_trusted"])
        self.assertEqual(packet["top_next_actions"][0]["id"], "KLBQ-001")
        self.assertTrue(
            any(item["id"] == "known_limitations_summary_consistency" for item in packet["blocked_items"])
        )

    def test_known_limitations_top_actions_prioritize_memory_refresh_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rows = [
                {
                    "rank": 1,
                    "id": "KLBQ-001",
                    "implementation_status": "partially_implemented_v0",
                    "owner_lane": "source replay",
                    "concrete_next_patch": "Preserve historical source refs before checkout.",
                    "verification_status": "partial_pass",
                    "remaining_blockers": ["historical source input still missing"],
                },
                {
                    "rank": 2,
                    "id": "KLBQ-002",
                    "implementation_status": "partially_implemented_v0",
                    "owner_lane": "source replay / memory recall",
                    "concrete_next_patch": "Acquire exact source roots.",
                    "verification_status": "blocked",
                    "remaining_blockers": ["exact source roots absent"],
                },
                {
                    "rank": 3,
                    "id": "KLBQ-005",
                    "implementation_status": "implemented_v0",
                    "owner_lane": "memory recall / exploit discovery",
                    "concrete_next_patch": "Consume scanner wiring remaining rows.",
                    "verification_status": "maintenance",
                    "remaining_blockers": ["scanner rows remain to burn down"],
                },
                {
                    "rank": 6,
                    "id": "KLBQ-006",
                    "implementation_status": "partially_implemented_v0",
                    "owner_lane": "harness precision / detector calibration",
                    "concrete_next_patch": "Produce exact executable proof.",
                    "verification_status": "partial_pass",
                    "remaining_blockers": ["exact proof absent"],
                },
                {
                    "rank": 8,
                    "id": "KLBQ-008",
                    "implementation_status": "implemented_v0",
                    "owner_lane": "submission finalization / memory recall",
                    "concrete_next_patch": "Preserve finalization gating invariant.",
                    "verification_status": "maintenance",
                    "remaining_blockers": [],
                },
            ]
            _write_json(
                root / "reports" / "known_limitations_burndown_queue_2026-05-05.json",
                {
                    "implementation_summary": {
                        "implemented_v0": ["KLBQ-005", "KLBQ-008"],
                        "partially_implemented_v0": ["KLBQ-001", "KLBQ-002", "KLBQ-006"],
                        "open": [],
                    },
                    "rows": rows,
                },
            )

            packet = MOD.build_packet(root, bounds=MOD.PacketBounds.from_values(max_items=5, max_text=160))

        self.assertEqual(
            [action["id"] for action in packet["top_next_actions"]],
            ["KLBQ-001", "KLBQ-006", "KLBQ-002", "KLBQ-005", "KLBQ-008"],
        )

    def test_missing_inputs_are_reported_as_blocked_not_fatal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            packet = MOD.build_packet(root)

            self.assertEqual(packet["schema"], "auditooor.memory_audit_packet.v0")
            self.assertEqual(packet["audit_readiness"], {})
            self.assertTrue(
                any(item["id"] == "input_report_availability" for item in packet["blocked_items"])
            )
            loaded = {item["status"] for item in packet["input_reports"]}
            self.assertEqual(loaded, {"missing"})

    def test_build_packet_prefers_newer_compatible_scanner_truth_over_default_dated_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_scanner_truth(
                root / "reports" / "scanner_wiring_truth_inventory_2026-05-05.json",
                item_count=1,
                wiring_status="dsl_only_or_unverified",
            )
            _write_scanner_truth(
                root / "reports" / "scanner_wiring_truth_inventory_2026-05-08.json",
                item_count=3,
                wiring_status="wired_verified",
            )

            packet = MOD.build_packet(root)

        scanner_truth = packet["audit_readiness"]["scanner_wiring_truth"]
        self.assertEqual(
            scanner_truth["source"],
            "reports/scanner_wiring_truth_inventory_2026-05-08.json",
        )
        self.assertEqual(scanner_truth["item_count"], 3)
        self.assertEqual(
            scanner_truth["wiring_status_counts_in_packet_rows"],
            {"wired_verified": 3},
        )

    def test_cli_writes_json_and_doc_from_temp_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_json(
                root / "reports" / "source_ref_replay_manifest_plan_2026-05-05.json",
                {
                    "implemented": True,
                    "source_replay_performed": False,
                    "network_used": False,
                    "current_statuses": ["immutable_ready", "blocked_named_ref_unresolved"],
                    "next_steps": [{"step": "wire_manifest", "detail": "Wire manifest into detector flow."}],
                    "remaining_limits": [{"limit": "no_network_resolver", "detail": "No remote resolver exists."}],
                },
            )
            json_out = root / "out" / "packet.json"
            doc_out = root / "out" / "packet.md"

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    str(root),
                    "--json-out",
                    str(json_out),
                    "--doc-out",
                    str(doc_out),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, "")
            payload = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.memory_audit_packet.v0")
            self.assertIn("source_ref_replay_manifest", payload["audit_readiness"])
            doc = doc_out.read_text(encoding="utf-8")
            self.assertIn("Memory Audit Packet Status", doc)
            self.assertIn("No-reason declines cannot be learned as pattern false positives", doc)
            self.assertIn("Audit Readiness", doc)
            self.assertIn("make memory-audit-packet", doc)

    def test_cli_prefers_newer_compatible_scanner_truth_over_default_dated_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_scanner_truth(
                root / "reports" / "scanner_wiring_truth_inventory_2026-05-05.json",
                item_count=1,
                wiring_status="dsl_only_or_unverified",
            )
            _write_scanner_truth(
                root / "reports" / "scanner_wiring_truth_inventory_2026-05-08.json",
                item_count=2,
                wiring_status="wired_verified",
            )
            json_out = root / "out" / "packet.json"

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    str(root),
                    "--json-out",
                    str(json_out),
                    "--no-doc",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(json_out.read_text(encoding="utf-8"))

        scanner_truth = payload["audit_readiness"]["scanner_wiring_truth"]
        self.assertEqual(
            scanner_truth["source"],
            "reports/scanner_wiring_truth_inventory_2026-05-08.json",
        )
        self.assertEqual(scanner_truth["item_count"], 2)
        self.assertEqual(
            scanner_truth["wiring_status_counts_in_packet_rows"],
            {"wired_verified": 2},
        )

    def test_custom_bounds_keep_live_packet_small(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rows = []
            for index in range(6):
                rows.append(
                    {
                        "rank": index + 1,
                        "id": f"KLBQ-{index + 1:03d}",
                        "implementation_status": "open",
                        "owner_lane": "memory recall",
                        "concrete_next_patch": "A" * 160,
                        "remaining_blockers": ["B" * 160],
                    }
                )
            _write_json(
                root / "reports" / "known_limitations_burndown_queue_2026-05-05.json",
                {"implementation_summary": {"open": [row["id"] for row in rows]}, "rows": rows},
            )

            packet = MOD.build_packet(root, bounds=MOD.PacketBounds.from_values(max_items=2, max_text=96))

            self.assertLessEqual(len(packet["top_next_actions"]), 2)
            self.assertLessEqual(len(packet["blocked_items"]), 2)
            self.assertEqual(
                packet["token_savings_assumptions"]["bounded_packet_limits"]["max_top_next_actions"],
                2,
            )
            self.assertTrue(packet["top_next_actions"][0]["action"].endswith("..."))

    def test_cli_custom_input_summary_and_fail_on_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            invalid = root / "reports" / "no_reason_decline_memory_2026-05-05.json"
            _write_text(invalid, "{not json")
            json_out = root / "out" / "packet.json"

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    str(root),
                    "--input-report",
                    "reports/no_reason_decline_memory_2026-05-05.json",
                    "--json-out",
                    str(json_out),
                    "--no-doc",
                    "--stdout-format",
                    "summary",
                    "--fail-on-missing-input",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 1)
            self.assertIn("invalid=1", proc.stdout)
            payload = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertEqual(payload["live_report_generation"]["invalid_input_reports"], 1)
            self.assertEqual(
                payload["input_reports"][0]["path"],
                "reports/no_reason_decline_memory_2026-05-05.json",
            )
            self.assertTrue(
                any(item["id"] == "input_report_availability" for item in payload["blocked_items"])
            )


if __name__ == "__main__":
    unittest.main()
