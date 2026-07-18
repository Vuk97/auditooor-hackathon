#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "memory-brief.py"


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("memory_brief", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_module()


def _obj(
    category: str,
    source_path: str,
    *,
    object_type: str = "markdown_note",
    stale: str = "",
    summary: dict | None = None,
) -> dict:
    return {
        "category": category,
        "object_type": object_type,
        "freshness_date": "2026-05-05",
        "source_path": source_path,
        "stale_or_missing_reason": stale,
        "callable_use": f"use {category}",
        "summary_fields": summary
        or {
            "byte_size": 1600,
            "title": source_path,
            "headline_bullets": ["first useful fact", "second useful fact", "third fact omitted"],
            "command_hints": ["python3 tools/example.py"],
        },
    }


def _index() -> dict:
    objects = [
        _obj("current_state", "docs/CURRENT_STATE.md"),
        _obj("model_handoff", "docs/LLM_DELEGATION_MATRIX.md", stale="older_than_2026-05-05"),
        _obj(
            "model_takeover_readiness",
            "reports/model_takeover_readiness_2026-05-05.json",
            object_type="json_report",
            summary={"byte_size": 1500, "schema": "takeover.v1", "counts": {"provider_gates_count": 4}, "samples": []},
        ),
        _obj(
            "model_takeover_provider_handoff",
            "reports/model_takeover_provider_handoff_2026-05-05.json",
            object_type="json_report",
            summary={
                "byte_size": 1600,
                "schema": "provider_handoff.v1",
                "counts": {"providers_count": 3},
                "samples": [{"provider": "kimi", "status": "WARN", "handoff_allowed": True}],
            },
        ),
        _obj(
            "model_handoff",
            "reports/memory_audit_packet_status_2026-05-05.json",
            object_type="json_report",
            summary={
                "byte_size": 2200,
                "schema": "memory_audit_packet.v0",
                "counts": {"top_next_actions_count": 8, "blocked_items_count": 3},
                "samples": [
                    {
                        "id": "KLBQ-001",
                        "owner_lane": "source replay",
                        "next_action": "Preserve historical source refs before checkout.",
                    },
                    {
                        "id": "KLBQ-006",
                        "owner_lane": "harness precision / detector calibration",
                        "next_action": "Produce exact executable proof.",
                    },
                    {
                        "id": "KLBQ-002",
                        "owner_lane": "source replay / memory recall",
                        "next_action": "Acquire exact source roots.",
                    },
                    {
                        "id": "KLBQ-005",
                        "owner_lane": "memory recall / exploit discovery",
                        "next_action": "Consume scanner wiring remaining rows.",
                    },
                    {
                        "id": "KLBQ-008",
                        "owner_lane": "submission finalization / memory recall",
                        "next_action": "Preserve finalization gating invariant.",
                    },
                ],
            },
        ),
        _obj(
            "operational_memory_day_to_day",
            "reports/task_finalization_loop_hardening_2026-05-05.json",
            object_type="json_report",
            summary={
                "byte_size": 1400,
                "schema": "auditooor.task_finalization_loop_hardening_report.v1",
                "counts": {"files_changed_count": 3, "verification_count": 2, "residual_risk_count": 2},
                "samples": [
                    {
                        "id": "task-finalization-ledger-index-retirement-parity",
                        "impact": "Manifest completion audits now enforce the same duplicate and retirement ordering constraints.",
                        "closure": "ledger_index() now skips duplicate task_id rows and rows after a retiring gap/slot closure.",
                    }
                ],
            },
        ),
        _obj("operational_memory_day_to_day", "reports/operational_memory_day_to_day_2026-05-05.json", object_type="json_report"),
        _obj("obsidian_memory_entrypoints", "reports/obsidian_memory_entrypoints_2026-05-05.json", object_type="json_report"),
        _obj(
            "model_handoff",
            "reports/memory_audit_packet_status_2026-05-05.json",
            object_type="json_report",
            summary={
                "byte_size": 1400,
                "schema": "auditooor.memory_audit_packet.v0",
                "counts": {"active_constraints_count": 5, "top_next_actions_count": 8},
                "samples": [],
            },
        ),
        _obj(
            "goal_loop",
            "reports/goal_loop_status_2026-05-05.json",
            object_type="json_report",
            summary={"byte_size": 900, "schema": "goal.v1", "counts": {"loop_phases_count": 8}, "samples": []},
        ),
        _obj(
            "harness_execution",
            "reports/harness_execution_queue_2026-05-05.json",
            object_type="json_report",
            summary={
                "byte_size": 1800,
                "schema": "harness_execution.v0",
                "counts": {"blocked_row_count": 10, "ready_row_count": 0},
                "samples": [
                    {
                        "row_id": "KLBQ-004",
                        "status": "blocked_missing_inputs",
                        "expected_next_action": "add one exact local harness command",
                        "missing_inputs": ["harness_command", "fixture_source"],
                    }
                ],
            },
        ),
        _obj(
            "harness_binding",
            "reports/harness_binding_manifest_status_2026-05-05.json",
            object_type="json_report",
            summary={
                "byte_size": 1200,
                "schema": "harness_binding.v0",
                "counts": {"commands_run_count": 3},
                "samples": [
                    {
                        "command": "python3 -m unittest tools.tests.test_harness_binding_manifest -v",
                        "result": "passed",
                    }
                ],
            },
        ),
        _obj(
            "scanner_truth",
            "reports/scanner_wiring_truth_inventory_2026-05-05.json",
            object_type="json_report",
            summary={
                "byte_size": 12000,
                "schema": "scanner.v1",
                "counts": {"rows_count": 500, "status_counts": {"quarantined_fake": 332, "generated_no_fixture": 63}},
                "samples": [
                    {
                        "row_id": "fake-row",
                        "wiring_status": "quarantined_fake",
                        "suggested_next_action": "exclude from wired memory",
                    }
                ],
            },
        ),
        _obj(
            "rust_xfail_burndown",
            "reports/rust_xfail_burndown_2026-05-05.json",
            object_type="json_report",
            summary={
                "byte_size": 2000,
                "schema": "rust_xfail.v1",
                "counts": {"residual_skip_detectors_count": 13},
                "samples": [{"detector_id": "DRAFT_example"}],
            },
        ),
        _obj("commit_lifecycle", "reports/commit_lifecycle_ledger_2026-05-05.json", object_type="json_report"),
        _obj(
            "commit_mining_source_review",
            "reports/commit_mining_source_review_2026-05-05.json",
            object_type="json_report",
            summary={"byte_size": 1800, "schema": "source_review.v1", "counts": {"source_review_packets_count": 4}, "samples": []},
        ),
        _obj(
            "commit_mining_source_disposition",
            "reports/commit_mining_source_disposition_2026-05-05.json",
            object_type="json_report",
            summary={"byte_size": 1800, "schema": "source_disposition.v1", "counts": {"disposition_queue_count": 4}, "samples": []},
        ),
        _obj(
            "commit_mining_review_task_packet",
            "reports/commit_mining_review_task_packet_2026-05-05.json",
            object_type="json_report",
            summary={
                "byte_size": 1800,
                "schema": "review_task.v1",
                "counts": {"tasks_count": 3},
                "samples": [{"task_id": "review-task-BA-PATCH-01", "status": "queued"}],
            },
        ),
        _obj(
            "commit_mining_next_step_packet",
            "reports/commit_mining_next_step_packet_2026-05-05.json",
            object_type="json_report",
            summary={
                "byte_size": 1800,
                "schema": "next_step.v1",
                "counts": {"files_to_inspect_count": 1},
                "samples": [{"task_id": "scan-task-BA-PATCH-01", "source_row_id": "BA-PATCH-01"}],
            },
        ),
        _obj(
            "base_audit_patch_review",
            "reports/ba_patch_01_source_review_2026-05-05.json",
            object_type="json_report",
            summary={
                "byte_size": 2100,
                "schema": "bounded_source_review.v1",
                "counts": {"observations_count": 4, "commands_run_count": 5},
                "samples": [{"source_row_id": "BA-PATCH-01", "task_id": "scan-task-BA-PATCH-01", "kind": "predicate-correction"}],
            },
        ),
        _obj(
            "base_audit_patch_review",
            "reports/ba_patch_01_proof_packet_plan_2026-05-05.json",
            object_type="json_report",
            summary={
                "byte_size": 1900,
                "schema": "bounded_proof_plan.v1",
                "counts": {"inspect_targets_count": 11, "proof_questions_count": 8},
                "samples": [{"source_row_id": "BA-PATCH-01", "role": "patch_root", "symbol": "AttributesWithParent::is_deposits_only"}],
            },
        ),
        _obj(
            "base_audit_patch_review",
            "reports/ba_patch_01_proof_execution_2026-05-05.json",
            object_type="json_report",
            summary={
                "byte_size": 2200,
                "schema": "bounded_proof_execution.v1",
                "counts": {"observations_count": 3, "commands_run_count": 4},
                "samples": [{"source_row_id": "BA-PATCH-01", "kind": "killed-on-patched-commit", "result": "pass"}],
            },
        ),
        _obj(
            "base_audit_patch_review",
            "reports/ba_patch_01_detector_2026-05-05.json",
            object_type="json_report",
            summary={
                "byte_size": 2400,
                "schema": "detector.v1",
                "counts": {"local_verification_count": 3, "remaining_blockers_count": 4},
                "samples": [{"command": "python3 -m unittest tools.tests.test_base_consensus_patch_scan -v", "result": "PASS"}],
            },
        ),
        _obj(
            "source_replay",
            "reports/detector_gap_regen_provenance_2026-05-05.json",
            object_type="json_report",
            summary={
                "byte_size": 2500,
                "schema": "auditooor.detector_gap_regen_provenance.v1",
                "counts": {
                    "local_artifacts_found_count": 10,
                    "next_commands_count": 4,
                    "commands_run_count": 17,
                },
                "samples": [{"status": "blocked_missing_exact_findings_export", "summary": "exact raw Solodit findings export absent locally"}],
            },
        ),
        _obj(
            "source_replay",
            "docs/DETECTOR_GAP_REGEN_PROVENANCE_2026-05-05.md",
            summary={
                "byte_size": 1900,
                "title": "Detector Gap Regeneration Provenance - 2026-05-05",
                "headline_bullets": ["Fail closed.", "Exact raw Solodit findings export is still missing locally."],
                "command_hints": ["python3 tools/_run_gap_analysis.py <absolute-path-to-solodit-findings-export.json> 98"],
            },
        ),
        _obj(
            "outcome_memory",
            "reports/no_reason_decline_memory_2026-05-05.json",
            object_type="json_report",
            summary={
                "byte_size": 1700,
                "schema": "auditooor.no_reason_decline_memory.v1",
                "counts": {"decline_rows_count": 5, "unknown_reason_count": 2},
                "headline_bullets": [
                    "Unknown or no-reason bug bounty declines should stay explicitly unattributed.",
                    "Use decline memory for calibration, not for invented rejection narratives.",
                ],
                "samples": [{"id": "decline-001", "status": "unknown_reason", "summary": "decline without explicit rationale"}],
                "command_hints": ["python3 tools/outcome-feedback.py --topic declines"],
            },
        ),
        _obj("known_limitations", "docs/KNOWN_LIMITATIONS.md", stale="content_summary_truncated_at_65536_bytes"),
        _obj(
            "known_limitations",
            "reports/known_limitations_dispatch_2026-05-05.json",
            object_type="json_report",
            summary={
                "byte_size": 2100,
                "schema": "known_dispatch.v1",
                "counts": {"dispatch_ready_total": 5, "blocked_total": 2},
                "samples": [
                    {
                        "limitation_id": "KLBQ-006",
                        "current_status": "partially_implemented_v0_partial_pass",
                        "dispatch_lane": "harness_execution",
                        "priority": "P1",
                        "next_action": "Acquire exact reNFT source root and rerun bounded precision evidence.",
                    }
                ],
            },
        ),
        _obj(
            "known_limitations_harness_memory_status",
            "reports/known_limitations_harness_memory_status_2026-05-05.json",
            object_type="json_report",
            summary={
                "byte_size": 1800,
                "schema": "known_status.v1",
                "counts": {"open_focus_row_count": 3, "verified_focus_row_count": 2},
                "samples": [
                    {
                        "id": "KLBQ-007",
                        "current_status": "partially_implemented_v0_partial_pass",
                        "next_action": "Run bounded memory refresh.",
                        "next_action_status": "actionable_now_with_blocked_followups",
                        "actionable_now_commands": ["python3 tools/memory-brief.py --bootstrap --print-json"],
                        "blocked_command_templates": [
                            {
                                "command": "python3 tools/rust-detect.py <source-root>",
                                "missing_inputs": ["<source-root>"],
                            }
                        ],
                    }
                ],
            },
        ),
        _obj(
            "known_limitations_harness_memory_status",
            "reports/klbq_006_precision_evidence_2026-05-05.json",
            object_type="json_report",
            summary={
                "byte_size": 2000,
                "schema": "auditooor.klbq_006_precision_evidence.v1",
                "counts": {
                    "combined_synthetic_accounting_by_detector_count": 2,
                    "promotion_ready": False,
                    "verification_claim_allowed": False,
                },
                "headline_bullets": [
                    "KLBQ-006 precision moved forward beyond dedicated fixture smoke, but verification remains blocked.",
                    "Synthetic precision is clean for both Rust detectors, while real-target replay and taxonomy reconciliation remain incomplete.",
                ],
                "samples": [
                    {
                        "id": "r94_loop_safe_fallback_handler_setter_missing_address_guard",
                        "status": "synthetic_precision_clean",
                        "summary": "precision=1.0 recall=1.0 tp=2 fp=0 tn=4 fn=0",
                    }
                ],
                "command_hints": ["rg -n \"setFallbackHandler\" <renft-source-root>"],
            },
        ),
        _obj(
            "known_limitations_harness_memory_status",
            "reports/klbq_006_real_source_anchors_2026-05-05.json",
            object_type="json_report",
            summary={
                "byte_size": 2100,
                "schema": "auditooor.klbq006_real_source_anchors.v1",
                "counts": {"candidate_renft_roots": 0, "possible_renft_source_hits": 0},
                "headline_bullets": [
                    "KLBQ-006 exact real-source replay remains blocked by absent local reNFT source anchors.",
                    "The local tree has reference and sibling base clues, but no exact #30522 file/line or checkout anchor.",
                ],
                "samples": [
                    {
                        "id": "KLBQ-006",
                        "status": "exact_source_absent",
                        "summary": "exact_renft_source_root=absent; real_source_anchors=absent; exact_finding_github_blob_anchors=absent; renft_base_github_blob_anchors=present",
                    }
                ],
                "command_hints": ["python3 tools/klbq006-real-source-anchors.py --root <local-root>"],
            },
        ),
        _obj(
            "known_limitations_harness_memory_status",
            "reports/klbq_006_taxonomy_reconciliation_2026-05-05.json",
            object_type="json_report",
            summary={
                "byte_size": 2200,
                "schema": "auditooor.klbq_006_taxonomy_reconciliation.v1",
                "counts": {"verification_claim_allowed": False},
                "headline_bullets": [
                    "KLBQ-006 taxonomy reconciliation is decided locally, but the limitation remains open.",
                    "Canonical leaf family is `safe-fallback-handler-setter-missing-address-guard`, with `input-validation` retained as a parent/alias only.",
                ],
                "samples": [
                    {
                        "id": "KLBQ-006",
                        "status": "canonical_decision_packet_complete_klbq_open",
                        "summary": "canonical_leaf_family=safe-fallback-handler-setter-missing-address-guard; parent_class=input-validation; preferred_accounting_key=safe-fallback-handler-setter-missing-address-guard",
                    }
                ],
                "command_hints": ["git -C <renft-source-root> rev-parse HEAD"],
            },
        ),
        _obj("source_mirror", "reports/source_mirror_queue_2026-05-05.json", object_type="json_report"),
        _obj(
            "next_loops",
            "reports/next_50_loops_2026-05-05.json",
            object_type="json_report",
            summary={"byte_size": 1700, "counts": {"phases_count": 6, "thresholds_count": 6}, "samples": []},
        ),
        _obj(
            "next_loops",
            "reports/g1_next_work_packets_2026-05-05.json",
            object_type="json_report",
            summary={"byte_size": 1600, "schema": "auditooor.g1_next_work_packets.v1", "counts": {"packets_count": 3}, "samples": []},
        ),
    ]
    categories = sorted({obj["category"] for obj in objects})
    return {
        "schema": "auditooor.shared_memory_index.v1",
        "generated_date": "2026-05-05",
        "memory_object_count": len(objects),
        "categories": categories,
        "category_coverage": {
            category: {
                "object_count": sum(1 for obj in objects if obj["category"] == category),
                "present_count": sum(1 for obj in objects if obj["category"] == category),
                "fresh_count": sum(1 for obj in objects if obj["category"] == category and not obj["stale_or_missing_reason"]),
                "missing_count": 0,
            }
            for category in categories
        },
        "memory_objects": objects,
    }


class MemoryBriefTest(unittest.TestCase):
    def test_agent_bootstrap_packet_extracts_takeover_guardrails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "reports").mkdir()
            goal_loop = {
                "goal_policy": {
                    "status": "active_continuous_loop",
                    "terminal_completion_allowed": False,
                    "loop_back_phase": "recall_memory",
                    "reason": "Global continuation loops back through memory after each bounded slice.",
                }
            }
            declines = {
                "decision": {
                    "classification": "unknown-reason decline",
                    "memory_effect": "platform/base-rate calibration only",
                    "forbid_inference": ["duplicate", "out_of_scope", "proof_failure"],
                }
            }
            entrypoints = {
                "memory_root": "/Users/wolf/auditooor-worktrees/continuation-plan-update",
            }
            next_50 = {"branch": "continuation-plan", "phases": [{"name": "merge_confidence", "goal": "keep docs scoped", "exit_criteria": ["clean cross-links"]}]}
            g1_next = {
                "branch": "continuation-plan",
                "worktree": "/Users/wolf/auditooor-worktrees/continuation-plan-update",
                "packets": [
                    {
                        "packet_id": "G1-NWP-001",
                        "title": "Source replay for liquidation and value-flow rows",
                        "primary_next_work": "source_replay_evidence",
                        "blocked_until": ["Exact vulnerable source roots are available."],
                    },
                    {
                        "packet_id": "G1-NWP-002",
                        "title": "Taxonomy updates for missing state/input binding subclasses",
                        "primary_next_work": "taxonomy_update",
                        "blocked_until": ["Concrete taxonomy subclasses are added or confirmed."],
                    },
                    {
                        "packet_id": "G1-NWP-003",
                        "title": "Existing R94 fallback handler calibration",
                        "primary_next_work": "calibration_promotion",
                        "blocked_until": ["Exact reNFT source anchors are available."],
                    },
                ],
                "top_priorities": [
                    {"title": "Source replay for #36418, #38333, and #33463"},
                    {"title": "Calibration decision for #30522"},
                ],
            }
            for name, payload in {
                "goal_loop_status_2026-05-05.json": goal_loop,
                "no_reason_decline_memory_2026-05-05.json": declines,
                "obsidian_memory_entrypoints_2026-05-05.json": entrypoints,
                "next_50_loops_2026-05-05.json": next_50,
                "g1_next_work_packets_2026-05-05.json": g1_next,
            }.items():
                (root / "reports" / name).write_text(json.dumps(payload), encoding="utf-8")

            packet = MOD.build_agent_bootstrap_packet(_index(), root=root, provider="minimax", task="takeover")

        self.assertEqual(packet["schema"], MOD.BOOTSTRAP_PACKET_SCHEMA)
        self.assertEqual(packet["provider"], "minimax")
        self.assertEqual(packet["active_checkpoint_policy"]["status"], "active_continuous_loop")
        self.assertFalse(packet["active_checkpoint_policy"]["terminal_completion_allowed"])
        self.assertEqual(packet["bug_bounty_decline_policy"]["classification"], "unknown-reason decline")
        self.assertIn("duplicate", packet["bug_bounty_decline_policy"]["forbid_inference"])
        self.assertEqual(packet["live_state_source_order"][0]["source_path"], "docs/CURRENT_STATE.md")
        self.assertEqual(packet["live_state_source_order"][1]["source_path"], "reports/memory_audit_packet_status_2026-05-05.json")
        self.assertEqual(packet["live_state_source_order"][3]["source_path"], "reports/shared_memory_index_2026-05-05.json")
        self.assertEqual(packet["branch_worktree_safety_warning"]["branch"], "continuation-plan")
        self.assertIn("continuation-plan-update", packet["branch_worktree_safety_warning"]["worktree"])
        self.assertEqual(
            [item["category"] for item in packet["next_work_categories"]],
            ["source_replay_evidence", "taxonomy_update", "calibration_promotion"],
        )
        self.assertGreater(packet["rough_packet_tokens"], 0)

    def test_agent_bootstrap_packet_blocks_stale_live_state_sources(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "reports").mkdir()
            for name, payload in {
                "goal_loop_status_2026-05-05.json": {
                    "goal_policy": {
                        "status": "active_continuous_loop",
                        "terminal_completion_allowed": False,
                    }
                },
                "no_reason_decline_memory_2026-05-05.json": {
                    "decision": {
                        "classification": "unknown-reason decline",
                        "memory_effect": "platform/base-rate calibration only",
                        "forbid_inference": [],
                    }
                },
                "obsidian_memory_entrypoints_2026-05-05.json": {"memory_root": str(root)},
                "next_50_loops_2026-05-05.json": {"branch": "agent-q"},
                "g1_next_work_packets_2026-05-05.json": {
                    "packets": [{"primary_next_work": "memory", "title": "memory bootstrap"}]
                },
            }.items():
                (root / "reports" / name).write_text(json.dumps(payload), encoding="utf-8")

            index = json.loads(json.dumps(_index()))
            for obj in index["memory_objects"]:
                if obj["source_path"] == "docs/CURRENT_STATE.md":
                    obj["stale_or_missing_reason"] = "older_than_2026-05-05"
                    break

            packet = MOD.build_agent_bootstrap_packet(index, root=root)

        current_state = packet["live_state_source_order"][0]
        self.assertEqual(current_state["source_path"], "docs/CURRENT_STATE.md")
        self.assertFalse(current_state["live_state_allowed"])
        self.assertTrue(
            any(
                "docs/CURRENT_STATE.md: older_than_2026-05-05; do not treat as live bootstrap state"
                in flag
                for flag in packet["fail_closed_flags"]
            )
        )
        self.assertIn("(stale_or_limited, not-live)", MOD.render_query_markdown(packet))

    def test_audit_handoff_maps_to_handoff_sources_only(self) -> None:
        brief = MOD.build_brief(_index(), "audit_handoff", provider="claude", task="handoff")

        self.assertEqual(brief["category"], "audit_handoff")
        self.assertEqual(brief["provider"], "claude")
        self.assertIn("current_state", brief["source_categories"])
        self.assertIn("model_handoff", brief["source_categories"])
        self.assertIn("model_takeover_readiness", brief["source_categories"])
        self.assertIn("model_takeover_provider_handoff", brief["source_categories"])
        self.assertIn("operational_memory_day_to_day", brief["source_categories"])
        self.assertIn("obsidian_memory_entrypoints", brief["source_categories"])
        self.assertNotIn("scanner_truth", brief["objects_by_source_category"])
        self.assertIn("docs/CURRENT_STATE.md", brief["source_paths"])
        self.assertIn("reports/model_takeover_readiness_2026-05-05.json", brief["source_paths"])
        self.assertIn("reports/model_takeover_provider_handoff_2026-05-05.json", brief["source_paths"])
        self.assertIn("reports/task_finalization_loop_hardening_2026-05-05.json", brief["source_paths"])
        task_finalization_report = [
            obj for obj in brief["objects_by_source_category"]["operational_memory_day_to_day"]
            if obj["source_path"] == "reports/task_finalization_loop_hardening_2026-05-05.json"
        ][0]
        self.assertEqual(task_finalization_report["samples"][0]["id"], "task-finalization-ledger-index-retirement-parity")
        self.assertIn("duplicate", task_finalization_report["samples"][0]["impact"])
        self.assertIn("duplicate task_id rows", task_finalization_report["samples"][0]["closure"])
        self.assertTrue(any("LLM_DELEGATION_MATRIX" in flag for flag in brief["fail_closed_flags"]))

    def test_scanner_truth_keeps_counts_samples_and_token_estimate(self) -> None:
        brief = MOD.build_brief(_index(), "scanner_truth", max_objects_per_source_category=1)
        selected = brief["objects_by_source_category"]["scanner_truth"][0]

        self.assertEqual(selected["counts"]["rows_count"], 500)
        self.assertEqual(selected["counts"]["status_counts"]["quarantined_fake"], 332)
        self.assertEqual(selected["samples"][0]["wiring_status"], "quarantined_fake")
        self.assertEqual(
            brief["objects_by_source_category"]["rust_xfail_burndown"][0]["counts"]["residual_skip_detectors_count"],
            13,
        )
        self.assertGreater(brief["rough_source_tokens_if_opened"], brief["rough_brief_tokens"])
        self.assertGreater(brief["rough_token_savings"], 0)

    def test_commit_lifecycle_includes_source_review_and_disposition(self) -> None:
        brief = MOD.build_brief(_index(), "commit_lifecycle", max_objects_per_source_category=4)

        self.assertIn("commit_mining_source_review", brief["source_categories"])
        self.assertIn("commit_mining_source_disposition", brief["source_categories"])
        self.assertIn("commit_mining_review_task_packet", brief["source_categories"])
        self.assertIn("commit_mining_next_step_packet", brief["source_categories"])
        self.assertIn("base_audit_patch_review", brief["source_categories"])
        self.assertEqual(
            brief["objects_by_source_category"]["commit_mining_source_review"][0]["counts"]["source_review_packets_count"],
            4,
        )
        self.assertEqual(
            brief["objects_by_source_category"]["commit_mining_source_disposition"][0]["counts"]["disposition_queue_count"],
            4,
        )
        self.assertEqual(
            brief["objects_by_source_category"]["commit_mining_review_task_packet"][0]["counts"]["tasks_count"],
            3,
        )
        self.assertEqual(
            brief["objects_by_source_category"]["commit_mining_next_step_packet"][0]["samples"][0]["task_id"],
            "scan-task-BA-PATCH-01",
        )
        base_patch_objects = brief["objects_by_source_category"]["base_audit_patch_review"]
        source_review_obj = [
            obj for obj in base_patch_objects
            if obj["source_path"] == "reports/ba_patch_01_source_review_2026-05-05.json"
        ][0]
        proof_plan_obj = [
            obj for obj in base_patch_objects
            if obj["source_path"] == "reports/ba_patch_01_proof_packet_plan_2026-05-05.json"
        ][0]
        proof_execution_obj = [
            obj for obj in base_patch_objects
            if obj["source_path"] == "reports/ba_patch_01_proof_execution_2026-05-05.json"
        ][0]
        detector_obj = [
            obj for obj in base_patch_objects
            if obj["source_path"] == "reports/ba_patch_01_detector_2026-05-05.json"
        ][0]
        self.assertEqual(
            source_review_obj["counts"]["observations_count"],
            4,
        )
        self.assertEqual(
            proof_plan_obj["samples"][0]["symbol"],
            "AttributesWithParent::is_deposits_only",
        )
        self.assertEqual(
            proof_execution_obj["samples"][0]["kind"],
            "killed-on-patched-commit",
        )
        self.assertEqual(
            detector_obj["counts"]["local_verification_count"],
            3,
        )
        self.assertEqual(detector_obj["samples"][0]["result"], "PASS")

    def test_known_limitations_includes_harness_memory_status(self) -> None:
        brief = MOD.build_brief(_index(), "known_limitations", max_objects_per_source_category=4)

        self.assertIn("known_limitations", brief["source_categories"])
        self.assertIn("known_limitations_harness_memory_status", brief["source_categories"])
        harness_objects = brief["objects_by_source_category"]["known_limitations_harness_memory_status"]
        self.assertEqual(harness_objects[0]["counts"]["open_focus_row_count"], 3)
        self.assertEqual(
            [obj["source_path"] for obj in harness_objects],
            [
                "reports/known_limitations_harness_memory_status_2026-05-05.json",
                "reports/klbq_006_precision_evidence_2026-05-05.json",
                "reports/klbq_006_real_source_anchors_2026-05-05.json",
                "reports/klbq_006_taxonomy_reconciliation_2026-05-05.json",
            ],
        )
        self.assertEqual(harness_objects[1]["samples"][0]["status"], "synthetic_precision_clean")
        self.assertEqual(harness_objects[2]["samples"][0]["status"], "exact_source_absent")
        self.assertIn("Canonical leaf family", harness_objects[3]["key_points"][1])
        self.assertEqual(harness_objects[0]["samples"][0]["next_action_status"], "actionable_now_with_blocked_followups")
        self.assertEqual(
            harness_objects[0]["samples"][0]["actionable_now_commands"],
            ["python3 tools/memory-brief.py --bootstrap --print-json"],
        )
        self.assertEqual(
            harness_objects[0]["samples"][0]["blocked_command_templates"][0]["missing_inputs"],
            ["<source-root>"],
        )

    def test_source_mirror_includes_detector_gap_regen_provenance_report(self) -> None:
        brief = MOD.build_brief(_index(), "source_mirror", max_objects_per_source_category=4)

        source_replay_paths = [obj["source_path"] for obj in brief["objects_by_source_category"]["source_replay"]]
        self.assertIn("reports/detector_gap_regen_provenance_2026-05-05.json", source_replay_paths)
        self.assertIn("docs/DETECTOR_GAP_REGEN_PROVENANCE_2026-05-05.md", source_replay_paths)
        provenance_obj = [
            obj for obj in brief["objects_by_source_category"]["source_replay"]
            if obj["source_path"] == "reports/detector_gap_regen_provenance_2026-05-05.json"
        ][0]
        self.assertEqual(provenance_obj["counts"]["next_commands_count"], 4)
        self.assertEqual(provenance_obj["samples"][0]["status"], "blocked_missing_exact_findings_export")

    def test_missing_expected_source_category_fails_closed(self) -> None:
        index = _index()
        index["memory_objects"] = [
            obj for obj in index["memory_objects"] if obj["category"] != "obsidian_memory_entrypoints"
        ]
        index["category_coverage"].pop("obsidian_memory_entrypoints", None)
        brief = MOD.build_brief(index, "audit_handoff")

        self.assertEqual(brief["objects_by_source_category"]["obsidian_memory_entrypoints"], [])
        self.assertTrue(
            any("obsidian_memory_entrypoints: no indexed objects selected" in flag for flag in brief["fail_closed_flags"])
        )

    def test_report_contains_supported_categories_and_contract(self) -> None:
        report = MOD.build_report(_index(), categories=["known_limitations", "source_mirror"], generated_at="2026-05-05T00:00:00+00:00")

        self.assertEqual(report["schema"], MOD.SCHEMA)
        self.assertEqual(report["selected_categories"], ["known_limitations", "source_mirror"])
        self.assertIn("audit_handoff", report["supported_categories"])
        self.assertEqual(len(report["briefs"]), 2)
        self.assertGreater(report["total_rough_brief_tokens"], 0)
        self.assertIn("Open source_paths only", " ".join(report["contract"]))

    def test_query_packet_scanner_wiring_prefers_scanner_sources(self) -> None:
        packet = MOD.build_query_packet(_index(), "scanner wiring", provider="kimi", task="bounded lookup")

        self.assertEqual(packet["schema"], MOD.QUERY_PACKET_SCHEMA)
        self.assertEqual(packet["provider"], "kimi")
        self.assertEqual(packet["recognized_topic"], "scanner wiring")
        self.assertIn("scanner_truth", packet["matched_source_categories"])
        self.assertIn("scanner_truth", packet["expected_source_categories"])
        self.assertIn("scanner_truth", packet["suggested_brief_categories"])
        self.assertTrue(packet["sources"])
        self.assertEqual(packet["sources"][0]["category"], "scanner_truth")
        self.assertEqual(packet["sources"][0]["source_path"], "reports/scanner_wiring_truth_inventory_2026-05-05.json")
        self.assertTrue(any(reason.startswith("source_category=scanner_truth") for reason in packet["sources"][0]["match_reasons"]))

    def test_query_packet_commit_mining_includes_review_packets(self) -> None:
        packet = MOD.build_query_packet(_index(), "commit mining")

        self.assertIn("commit_lifecycle", packet["suggested_brief_categories"])
        self.assertIn("source_mirror", packet["suggested_brief_categories"])
        source_paths = [source["source_path"] for source in packet["sources"]]
        self.assertIn("reports/commit_mining_review_task_packet_2026-05-05.json", source_paths)
        self.assertIn("reports/commit_mining_next_step_packet_2026-05-05.json", source_paths)

    def test_query_packet_bug_bounty_declines_hits_outcome_memory(self) -> None:
        packet = MOD.build_query_packet(_index(), "bug bounty declines")

        self.assertEqual(packet["matched_source_categories"], ["outcome_memory"])
        self.assertEqual(packet["sources"][0]["counts"]["unknown_reason_count"], 2)
        self.assertEqual(packet["sources"][0]["samples"][0]["status"], "unknown_reason")

    def test_query_packet_agent_bootstrap_uses_special_mode(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "reports").mkdir()
            (root / "reports" / "goal_loop_status_2026-05-05.json").write_text(
                json.dumps({"goal_policy": {"status": "active_continuous_loop", "terminal_completion_allowed": False}}),
                encoding="utf-8",
            )
            (root / "reports" / "no_reason_decline_memory_2026-05-05.json").write_text(
                json.dumps({"decision": {"classification": "unknown-reason decline", "memory_effect": "platform/base-rate calibration only", "forbid_inference": []}}),
                encoding="utf-8",
            )
            (root / "reports" / "obsidian_memory_entrypoints_2026-05-05.json").write_text(
                json.dumps({"memory_root": "/Users/wolf/auditooor-worktrees/continuation-plan-update"}),
                encoding="utf-8",
            )
            (root / "reports" / "next_50_loops_2026-05-05.json").write_text(
                json.dumps({"branch": "continuation-plan"}),
                encoding="utf-8",
            )
            (root / "reports" / "g1_next_work_packets_2026-05-05.json").write_text(
                json.dumps({"packets": [{"primary_next_work": "source_replay_evidence", "title": "replay"}]}),
                encoding="utf-8",
            )

            packet = MOD.build_query_packet(_index(), "agent bootstrap", root=root)

        self.assertEqual(packet["schema"], MOD.BOOTSTRAP_PACKET_SCHEMA)
        self.assertEqual(packet["query"], "agent bootstrap")
        self.assertEqual(packet["suggested_brief_categories"], ["audit_handoff"])

    def test_bootstrap_packet_prefers_report_paths_and_priority_actions(self) -> None:
        packet = MOD.build_bootstrap_packet(
            _index(),
            provider="codex",
            task="low context handoff",
            generated_at="2026-05-05T00:00:00+00:00",
        )

        self.assertEqual(packet["schema"], MOD.MEMORY_BOOTSTRAP_PACKET_SCHEMA)
        self.assertEqual(packet["provider"], "codex")
        self.assertEqual(packet["priority_order"], ["MEMORY", "HARNESS", "KNOWN LIMITATION BURNDOWN"])
        self.assertEqual(packet["priority_lane_mapping"]["MEMORY"], ["memory_handoff"])
        self.assertIn("reports/memory_audit_packet_status_2026-05-05.json", packet["read_first_report_paths"])
        self.assertIn("reports/harness_execution_queue_2026-05-05.json", packet["read_first_report_paths"])
        self.assertNotIn("docs/CURRENT_STATE.md", packet["read_first_report_paths"])
        self.assertNotIn("docs/KNOWN_LIMITATIONS.md", packet["read_first_report_paths"])
        self.assertEqual(
            [action["id"] for action in packet["priority_actions"][:5]],
            ["KLBQ-001", "KLBQ-006", "KLBQ-002", "KLBQ-005", "KLBQ-008"],
        )
        self.assertTrue(any(action["id"] == "KLBQ-006" for action in packet["priority_actions"]))
        self.assertTrue(any(action["id"] == "KLBQ-004" for action in packet["priority_actions"]))
        harness_action = [action for action in packet["priority_actions"] if action["id"] == "KLBQ-007"][0]
        self.assertEqual(harness_action["next_action_status"], "actionable_now_with_blocked_followups")
        self.assertEqual(harness_action["actionable_now_commands"][0], "python3 tools/memory-brief.py --bootstrap --print-json")
        self.assertEqual(harness_action["blocked_command_templates"][0]["missing_inputs"], ["<source-root>"])
        self.assertEqual(packet["closed_limitation"]["id"], "memory-bootstrap-broad-doc-reread")
        self.assertGreater(packet["rough_packet_tokens"], 0)

    def test_cli_writes_json_and_markdown_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "reports").mkdir()
            (root / "docs").mkdir()
            (root / "reports" / "shared_memory_index_2026-05-05.json").write_text(
                json.dumps(_index()),
                encoding="utf-8",
            )

            rc = MOD.main(
                [
                    "--root",
                    str(root),
                    "--category",
                    "scanner_truth",
                    "--provider",
                    "kimi",
                    "--task",
                    "scanner handoff",
                ]
            )

            self.assertEqual(rc, 0)
            report_path = root / "reports" / "memory_brief_2026-05-05.json"
            doc_path = root / "docs" / "MEMORY_BRIEF_2026-05-05.md"
            self.assertTrue(report_path.exists())
            self.assertTrue(doc_path.exists())
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["selected_categories"], ["scanner_truth"])
            self.assertEqual(report["provider"], "kimi")
            self.assertIn("scanner_truth", doc_path.read_text(encoding="utf-8"))

    def test_query_cli_prints_topic_packet_without_writing_default_brief_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "reports").mkdir()
            (root / "reports" / "shared_memory_index_2026-05-05.json").write_text(
                json.dumps(_index()),
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--root",
                    str(root),
                    "--query",
                    "scanner wiring",
                ],
                check=True,
                text=True,
                capture_output=True,
            )

            self.assertIn("# Memory Topic Packet - scanner wiring", proc.stdout)
            self.assertIn("reports/scanner_wiring_truth_inventory_2026-05-05.json", proc.stdout)
            self.assertFalse((root / "reports" / "memory_brief_2026-05-05.json").exists())
            self.assertFalse((root / "docs" / "MEMORY_BRIEF_2026-05-05.md").exists())

    def test_agent_bootstrap_cli_prints_compact_bootstrap_packet(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "reports").mkdir()
            (root / "reports" / "shared_memory_index_2026-05-05.json").write_text(
                json.dumps(_index()),
                encoding="utf-8",
            )
            (root / "reports" / "goal_loop_status_2026-05-05.json").write_text(
                json.dumps({"goal_policy": {"status": "active_continuous_loop", "terminal_completion_allowed": False, "loop_back_phase": "recall_memory", "reason": "loop"}}),
                encoding="utf-8",
            )
            (root / "reports" / "no_reason_decline_memory_2026-05-05.json").write_text(
                json.dumps({"decision": {"classification": "unknown-reason decline", "memory_effect": "platform/base-rate calibration only", "forbid_inference": ["duplicate"]}}),
                encoding="utf-8",
            )
            (root / "reports" / "obsidian_memory_entrypoints_2026-05-05.json").write_text(
                json.dumps({"memory_root": "/Users/wolf/auditooor-worktrees/continuation-plan-update"}),
                encoding="utf-8",
            )
            (root / "reports" / "next_50_loops_2026-05-05.json").write_text(
                json.dumps({"branch": "continuation-plan"}),
                encoding="utf-8",
            )
            (root / "reports" / "g1_next_work_packets_2026-05-05.json").write_text(
                json.dumps({"branch": "continuation-plan", "worktree": "/Users/wolf/auditooor-worktrees/continuation-plan-update", "packets": [{"primary_next_work": "source_replay_evidence", "title": "replay"}]}),
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--root",
                    str(root),
                    "--agent-bootstrap",
                ],
                check=True,
                text=True,
                capture_output=True,
            )

            self.assertIn("# Agent Bootstrap Packet", proc.stdout)
            self.assertIn("## Active Checkpoint Policy", proc.stdout)
            self.assertIn("## Next-Work Categories", proc.stdout)
            self.assertFalse((root / "reports" / "memory_brief_2026-05-05.json").exists())

    def test_bootstrap_cli_prints_packet_without_writing_default_brief_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "reports").mkdir()
            (root / "reports" / "shared_memory_index_2026-05-05.json").write_text(
                json.dumps(_index()),
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--root",
                    str(root),
                    "--bootstrap",
                ],
                check=True,
                text=True,
                capture_output=True,
            )

            self.assertIn("# Memory Bootstrap - 2026-05-05", proc.stdout)
            self.assertIn("reports/memory_audit_packet_status_2026-05-05.json", proc.stdout)
            self.assertIn("memory-bootstrap-broad-doc-reread", proc.stdout)
            self.assertFalse((root / "reports" / "memory_brief_2026-05-05.json").exists())
            self.assertFalse((root / "docs" / "MEMORY_BRIEF_2026-05-05.md").exists())


if __name__ == "__main__":
    unittest.main()
