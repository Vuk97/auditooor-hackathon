#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "shared-memory-index.py"


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("shared_memory_index", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_module()


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class SharedMemoryIndexTest(unittest.TestCase):
    def _seed_minimal_tree(self, root: Path) -> None:
        (root / "docs").mkdir(parents=True)
        (root / "reports").mkdir(parents=True)
        (root / "docs" / "CURRENT_STATE.md").write_text(
            "# Current State\n\n"
            "**Last updated:** 2026-05-05\n\n"
            "## Headline State\n\n"
            "- PR #605 remains the continuation branch.\n"
            "- Do not mark the global objective complete.\n"
            "\n```bash\nmake vault-refresh\npython3 tools/shared-memory-index.py\n```\n",
            encoding="utf-8",
        )
        (root / "docs" / "NEXT_50_LOOPS_2026-05-05.md").write_text(
            "# Next 50 Loops\n\n## Queue\n\n- Run bounded memory preflight first.\n",
            encoding="utf-8",
        )
        (root / "docs" / "LOOP_ITER_999_PLAN.md").write_text(
            "# Loop Iter 999 Plan\n\n- Controlled glob fixture.\n",
            encoding="utf-8",
        )
        (root / "reports" / "scanner_wiring_truth_inventory_2026-05-05.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.scanner_wiring_truth_inventory.v1",
                    "item_count": 2,
                    "status_counts": {"generated_no_fixture": 1, "quarantined_fake": 1},
                    "rows": [
                        {
                            "row_id": "SWT-1",
                            "title": "Fake scanner row",
                            "status": "blocked",
                            "wiring_status": "quarantined_fake",
                            "suggested_next_action": "exclude from wired memory",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        (root / "reports" / "scanner_worker_active_claims_2026-05-05.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.scanner_worker_active_claims.v1",
                    "updated_at": "2026-05-06T05:54:12Z",
                    "active_claims": [
                        {
                            "agent_id": "agent-1",
                            "row_id": "perp_max_pnl_bypass_via_partial_close",
                            "status": "active",
                        },
                        {
                            "agent_id": "agent-2",
                            "row_id": "perp_limit_stop_order_short_circuit_validation",
                            "status": "completed",
                        },
                    ],
                    "summary": {"active": 1, "completed": 1},
                }
            ),
            encoding="utf-8",
        )
        (root / "reports" / "harness_failures.jsonl").write_text(
            json.dumps({"status": "open", "title": "forge std missing"}) + "\n",
            encoding="utf-8",
        )
        (root / "docs" / "OPERATIONAL_MEMORY_DAY_TO_DAY_2026-05-05.md").write_text(
            "# Operational Memory Day To Day - 2026-05-05\n\n"
            "- Start from lane blockers before dispatch.\n",
            encoding="utf-8",
        )
        (root / "reports" / "operational_memory_day_to_day_2026-05-05.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.operational_memory_day_to_day.v2",
                    "summary": {"lane_count": 1, "global_blocker_count": 1},
                    "lanes": [
                        {
                            "lane_id": "memory_brief_index",
                            "title": "Memory Brief + Index",
                            "dispatch_blockers": ["memory text is routing context"],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        (root / "reports" / "task_finalization_loop_hardening_2026-05-05.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.task_finalization_loop_hardening_report.v1",
                    "gap_closed": {
                        "id": "task-finalization-ledger-index-retirement-parity",
                        "impact": "Manifest completion audits now use the same task_id and gap-retirement ordering constraints as ledger validation.",
                        "risk_before": "A conflicted or hand-edited ledger could be invalid while still letting continuation logic treat a terminal manifest row as finalized.",
                        "closure": "ledger_index() now skips duplicate task_id rows and rows after a retiring gap/slot closure.",
                    },
                    "files_changed": [
                        "tools/task-finalization-ledger.py",
                        "tools/tests/test_task_finalization_ledger.py",
                    ],
                    "verification": [
                        {
                            "command": "python3 -m unittest tools.tests.test_task_finalization_ledger",
                            "exit_code": 0,
                        }
                    ],
                    "residual_risk": [
                        "This change hardens the task-finalization audit surface only.",
                    ],
                }
            ),
            encoding="utf-8",
        )
        (root / "docs" / "DETECTOR_GAP_REGEN_PROVENANCE_2026-05-05.md").write_text(
            "# Detector Gap Regeneration Provenance - 2026-05-05\n\n"
            "## Outcome\n\n"
            "- Fail closed.\n"
            "- Exact raw Solodit findings export is still missing locally.\n"
            "\n```sh\npython3.13 tools/detector-blindspot-scan.py --data /tmp/findings.json --max-findings 98\n```\n",
            encoding="utf-8",
        )
        (root / "reports" / "detector_gap_regen_provenance_2026-05-05.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.detector_gap_regen_provenance.v1",
                    "status": "blocked_missing_exact_findings_export",
                    "regenerated": False,
                    "fail_closed": True,
                    "target_report": "reports/detector_gap.json",
                    "target_report_row_count": 98,
                    "safe_regeneration_possible": False,
                    "local_artifacts_found": [
                        {"path": "reports/detector_gap.json", "kind": "derived_report"}
                    ],
                    "next_commands": [
                        "python3.13 tools/detector-blindspot-scan.py --data /tmp/findings.json --max-findings 98"
                    ],
                    "commands_run": [
                        "git rev-list --all --objects | rg 'solodit.*json|findings_raw|detector_gap.json'"
                    ],
                }
            ),
            encoding="utf-8",
        )
        (root / "docs" / "MODEL_TAKEOVER_PROVIDER_HANDOFF_2026-05-05.md").write_text(
            "# Model Takeover Provider Handoff - 2026-05-05\n\n- Providers remain bounded handoff only.\n",
            encoding="utf-8",
        )
        (root / "reports" / "model_takeover_provider_handoff_2026-05-05.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.model_takeover_provider_handoff.v1",
                    "fail_closed": False,
                    "providers": {
                        "kimi": {
                            "status": "WARN",
                            "handoff_allowed": True,
                            "readiness_estimate_percent": 88,
                            "takeover_posture": "bounded_warn_handoff_only",
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        (root / "docs" / "KNOWN_LIMITATIONS_HARNESS_MEMORY_STATUS_2026-05-05.md").write_text(
            "# Known Limitations Harness Memory Status - 2026-05-05\n\n- KLBQ rows stay evidence-gated.\n",
            encoding="utf-8",
        )
        (root / "reports" / "known_limitations_harness_memory_status_2026-05-05.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.known_limitations_harness_memory_status.v1",
                    "summary": {"open_focus_row_count": 1, "verified_focus_row_count": 1},
                    "open_focus_rows": [
                        {
                            "id": "KLBQ-007",
                            "current_status": "partially_implemented_v0_partial_pass",
                            "open": True,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        (root / "reports" / "klbq_006_precision_evidence_2026-05-05.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.klbq_006_precision_evidence.v1",
                    "limitation_id": "KLBQ-006",
                    "status": "moved_forward_not_verified",
                    "promotion_ready": False,
                    "verification_claim_allowed": False,
                    "summary": {
                        "added_synthetic_precision_corpus": True,
                        "taxonomy_reconciled": False,
                    },
                    "combined_synthetic_accounting_by_detector": [
                        {
                            "detector_id": "r94_loop_safe_fallback_handler_setter_missing_address_guard",
                            "true_positive_count": 2,
                            "false_positive_count": 0,
                            "true_negative_count": 4,
                            "false_negative_count": 0,
                            "precision": 1.0,
                            "recall": 1.0,
                        }
                    ],
                    "next_commands": [
                        "rg -n \"setFallbackHandler\" <renft-source-root>",
                        "python3 tools/rust-detect.py <renft-source-root> --only r94_loop_safe_fallback_handler_setter_missing_address_guard",
                    ],
                }
            ),
            encoding="utf-8",
        )
        (root / "reports" / "klbq_006_real_source_anchors_2026-05-05.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.klbq006_real_source_anchors.v1",
                    "limitation_id": "KLBQ-006",
                    "classification": {
                        "exact_renft_source_root": "absent",
                        "real_source_anchors": "absent",
                        "exact_finding_github_blob_anchors": "absent",
                        "renft_base_github_blob_anchors": "present",
                    },
                    "summary": {
                        "candidate_renft_roots": 0,
                        "possible_renft_source_hits": 0,
                    },
                    "commands_to_reproduce": [
                        "python3 tools/klbq006-real-source-anchors.py --root <local-root>",
                    ],
                }
            ),
            encoding="utf-8",
        )
        (root / "reports" / "klbq_006_taxonomy_reconciliation_2026-05-05.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.klbq_006_taxonomy_reconciliation.v1",
                    "limitation_id": "KLBQ-006",
                    "status": "canonical_decision_packet_complete_klbq_open",
                    "taxonomy_decision": {
                        "canonical_leaf_family": "safe-fallback-handler-setter-missing-address-guard",
                        "parent_class": "input-validation",
                        "preferred_accounting_key": "safe-fallback-handler-setter-missing-address-guard",
                    },
                    "reconciled_accounting": {
                        "closure_posture": "open",
                        "promotion_posture": "hold",
                        "repo_wide_metadata_updated": False,
                    },
                    "exact_next_commands": [
                        "git -C <renft-source-root> rev-parse HEAD",
                    ],
                }
            ),
            encoding="utf-8",
        )

    def test_index_has_all_categories_required_fields_and_missing_sources(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._seed_minimal_tree(root)
            index = MOD.build_index(root, current_date="2026-05-05")

        self.assertEqual(index["schema"], MOD.SCHEMA)
        self.assertEqual(set(index["categories"]), set(MOD.CATEGORIES))
        self.assertIn("operational_memory_day_to_day", index["categories"])
        self.assertIn("model_takeover_provider_handoff", index["categories"])
        self.assertIn("known_limitations_harness_memory_status", index["categories"])
        self.assertIn("commit_mining_review_task_packet", index["categories"])
        self.assertIn("commit_mining_next_step_packet", index["categories"])
        self.assertIn("base_audit_patch_review", index["categories"])
        self.assertIn("rust_xfail_burndown", index["categories"])
        self.assertIn("commit_mining_source_disposition", index["categories"])
        self.assertTrue(index["memory_objects"])
        self.assertGreater(index["category_coverage"]["current_state"]["present_count"], 0)
        self.assertGreater(index["category_coverage"]["scanner_truth"]["present_count"], 0)
        self.assertEqual(index["category_coverage"]["scanner_burndown"]["present_count"], 1)
        self.assertEqual(index["category_coverage"]["operational_memory_day_to_day"]["present_count"], 3)
        self.assertEqual(index["category_coverage"]["model_takeover_provider_handoff"]["present_count"], 2)
        self.assertEqual(index["category_coverage"]["known_limitations_harness_memory_status"]["present_count"], 5)
        self.assertEqual(index["category_coverage"]["source_replay"]["present_count"], 2)
        self.assertEqual(index["category_coverage"]["commit_mining_review_task_packet"]["missing_count"], 2)
        self.assertEqual(index["category_coverage"]["commit_mining_next_step_packet"]["missing_count"], 2)
        self.assertEqual(index["category_coverage"]["base_audit_patch_review"]["object_count"], 0)
        self.assertEqual(index["category_coverage"]["rust_xfail_burndown"]["missing_count"], 2)
        self.assertGreater(index["category_coverage"]["known_limitations"]["missing_count"], 0)

        required = {
            "object_type",
            "freshness_date",
            "source_path",
            "summary_fields",
            "callable_use",
            "stale_or_missing_reason",
        }
        for obj in index["memory_objects"]:
            self.assertTrue(required.issubset(obj))

        missing = [
            obj for obj in index["memory_objects"]
            if obj["source_path"] == "docs/KNOWN_LIMITATIONS.md"
        ][0]
        self.assertEqual(missing["object_type"], "missing_source")
        self.assertEqual(missing["stale_or_missing_reason"], "missing_source")
        detector_gap_doc = [
            obj for obj in index["memory_objects"]
            if obj["source_path"] == "docs/DETECTOR_GAP_REGEN_PROVENANCE_2026-05-05.md"
        ][0]
        detector_gap_report = [
            obj for obj in index["memory_objects"]
            if obj["source_path"] == "reports/detector_gap_regen_provenance_2026-05-05.json"
        ][0]
        self.assertEqual(detector_gap_doc["category"], "source_replay")
        self.assertEqual(detector_gap_doc["summary_fields"]["headline_bullets"][0], "Fail closed.")
        self.assertEqual(detector_gap_report["summary_fields"]["counts"]["local_artifacts_found_count"], 1)
        self.assertEqual(detector_gap_report["summary_fields"]["counts"]["next_commands_count"], 1)
        self.assertEqual(detector_gap_report["summary_fields"]["counts"]["commands_run_count"], 1)
        precision_report = [
            obj for obj in index["memory_objects"]
            if obj["source_path"] == "reports/klbq_006_precision_evidence_2026-05-05.json"
        ][0]
        self.assertEqual(precision_report["category"], "known_limitations_harness_memory_status")
        self.assertEqual(precision_report["summary_fields"]["samples"][0]["id"], "r94_loop_safe_fallback_handler_setter_missing_address_guard")
        self.assertIn("Synthetic precision is clean", precision_report["summary_fields"]["headline_bullets"][1])
        anchor_report = [
            obj for obj in index["memory_objects"]
            if obj["source_path"] == "reports/klbq_006_real_source_anchors_2026-05-05.json"
        ][0]
        self.assertEqual(anchor_report["summary_fields"]["samples"][0]["status"], "exact_source_absent")
        self.assertIn("exact_renft_source_root=absent", anchor_report["summary_fields"]["headline_bullets"][2])
        taxonomy_report = [
            obj for obj in index["memory_objects"]
            if obj["source_path"] == "reports/klbq_006_taxonomy_reconciliation_2026-05-05.json"
        ][0]
        self.assertIn("Canonical leaf family", taxonomy_report["summary_fields"]["headline_bullets"][1])
        self.assertEqual(taxonomy_report["summary_fields"]["samples"][0]["id"], "KLBQ-006")
        active_claims_report = [
            obj for obj in index["memory_objects"]
            if obj["source_path"] == "reports/scanner_worker_active_claims_2026-05-05.json"
        ][0]
        self.assertEqual(active_claims_report["category"], "scanner_burndown")
        self.assertEqual(active_claims_report["summary_fields"]["active_claim_count"], 1)
        self.assertEqual(active_claims_report["summary_fields"]["completed_claim_count"], 1)
        self.assertEqual(
            active_claims_report["summary_fields"]["samples"][0]["row_id"],
            "perp_max_pnl_bypass_via_partial_close",
        )
        self.assertIn(
            "scanner-worker-next-rows.py",
            active_claims_report["summary_fields"]["command_hints"][1],
        )
        task_finalization_report = [
            obj for obj in index["memory_objects"]
            if obj["source_path"] == "reports/task_finalization_loop_hardening_2026-05-05.json"
        ][0]
        self.assertEqual(task_finalization_report["category"], "operational_memory_day_to_day")
        self.assertEqual(task_finalization_report["summary_fields"]["counts"]["files_changed_count"], 2)
        self.assertEqual(task_finalization_report["summary_fields"]["samples"][0]["id"], "task-finalization-ledger-index-retirement-parity")
        self.assertEqual(
            task_finalization_report["summary_fields"]["samples"][0]["closure"],
            "ledger_index() now skips duplicate task_id rows and rows after a retiring gap/slot closure.",
        )

    def test_operational_packet_json_samples_use_packet_lists(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "reports").mkdir()
            rel = "reports/commit_mining_source_review_2026-05-05.json"
            (root / rel).write_text(
                json.dumps(
                    {
                        "schema": "auditooor.commit_mining_source_review.v1",
                        "source_review_packets": [
                            {
                                "task_id": "scan-task-1",
                                "status": "source_review_packet_emitted",
                                "source_row_id": "BA-PATCH-01",
                                "blockers": [],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            obj = MOD.summarize_source(
                root,
                rel,
                "commit_mining_source_review",
                "use source-review packets",
                "2026-05-05",
            )

        self.assertEqual(obj["object_type"], "json_report")
        self.assertEqual(obj["summary_fields"]["counts"]["source_review_packets_count"], 1)
        self.assertEqual(obj["summary_fields"]["samples"][0]["task_id"], "scan-task-1")
        self.assertEqual(obj["summary_fields"]["samples"][0]["status"], "source_review_packet_emitted")

    def test_source_disposition_samples_use_disposition_queue(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "reports").mkdir()
            rel = "reports/commit_mining_source_disposition_2026-05-05.json"
            (root / rel).write_text(
                json.dumps(
                    {
                        "schema": "auditooor.commit_mining_source_disposition.v1",
                        "disposition_queue": [
                            {
                                "disposition_id": "source-disposition-1",
                                "task_id": "scan-task-1",
                                "status": "queued",
                                "action_type": "narrow_consensus_patch_review",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            obj = MOD.summarize_source(
                root,
                rel,
                "commit_mining_source_disposition",
                "use source disposition queue",
                "2026-05-05",
            )

        self.assertEqual(obj["object_type"], "json_report")
        self.assertEqual(obj["summary_fields"]["counts"]["disposition_queue_count"], 1)
        self.assertEqual(obj["summary_fields"]["samples"][0]["task_id"], "scan-task-1")
        self.assertEqual(obj["summary_fields"]["samples"][0]["status"], "queued")

    def test_base_audit_patch_review_glob_discovers_ba_patch_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "docs").mkdir()
            (root / "reports").mkdir()
            (root / "docs" / "BA_PATCH_01_SOURCE_REVIEW_2026-05-05.md").write_text(
                "# BA-PATCH-01 Source Review\n\n- Bounded to local source review only.\n",
                encoding="utf-8",
            )
            (root / "reports" / "ba_patch_01_source_review_2026-05-05.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.bounded_advisory_source_review.v1",
                        "source_row_id": "BA-PATCH-01",
                        "task_id": "scan-task-BA-PATCH-01",
                        "commands_run": [
                            {
                                "command": "git show --stat --summary",
                                "result": "bounded review succeeded",
                            }
                        ],
                        "observations": [
                            {
                                "id": "obs-1",
                                "kind": "predicate-correction",
                                "summary": "Checks every transaction buffer instead of only the first row.",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (root / "docs" / "BA_PATCH_01_PROOF_PACKET_PLAN_2026-05-05.md").write_text(
                "# BA-PATCH-01 Proof Packet Plan\n\n- Scaffold only.\n",
                encoding="utf-8",
            )
            (root / "reports" / "ba_patch_01_proof_packet_plan_2026-05-05.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.bounded_proof_packet_plan.v1",
                        "source_row_id": "BA-PATCH-01",
                        "inspect_targets": [
                            {
                                "path": "/tmp/base/crates/consensus/protocol/src/attributes.rs",
                                "role": "patch_root",
                                "symbol": "AttributesWithParent::is_deposits_only",
                            }
                        ],
                        "proof_questions": ["Does the classifier match caller expectations?"],
                    }
                ),
                encoding="utf-8",
            )
            (root / "docs" / "BA_PATCH_01_PROOF_EXECUTION_2026-05-05.md").write_text(
                "# BA-PATCH-01 Proof Execution\n\n- No submission claim.\n",
                encoding="utf-8",
            )
            (root / "reports" / "ba_patch_01_proof_execution_2026-05-05.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.bounded_proof_execution.v1",
                        "source_row_id": "BA-PATCH-01",
                        "posture": "NOT_SUBMIT_READY",
                        "commands_run": [
                            {
                                "command": "cargo test -p base-protocol --lib is_deposits_only",
                                "result": "pass",
                            }
                        ],
                        "observations": [
                            {
                                "id": "proof-1",
                                "kind": "killed-on-patched-commit",
                                "summary": "Detector hit is absent on the patched commit.",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (root / "docs" / "BA_PATCH_01_DETECTOR_2026-05-05.md").write_text(
                "# BA-PATCH-01 Detectorization\n\n- Durable regression detector only.\n",
                encoding="utf-8",
            )
            (root / "reports" / "ba_patch_01_detector_2026-05-05.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.ba_patch_01_detector.v1",
                        "source_row_id": "BA-PATCH-01",
                        "detector": {
                            "pattern_id": "base_deposits_only_option_iter_first_tx_only",
                            "target_symbol": "AttributesWithParent::is_deposits_only",
                            "status": "durable_regression_detector",
                            "submission_posture": "NOT_SUBMIT_READY",
                        },
                        "local_verification": [
                            {
                                "command": "python3 -m unittest tools.tests.test_base_consensus_patch_scan -v",
                                "result": "PASS: 7 tests passed",
                            }
                        ],
                        "remaining_blockers": [
                            {
                                "id": "runtime_unexpected_payload_status_trigger_missing",
                                "classification": "impact_proof_blocker",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            index = MOD.build_index(root, current_date="2026-05-05")

        self.assertEqual(index["category_coverage"]["base_audit_patch_review"]["present_count"], 8)
        objects = [obj for obj in index["memory_objects"] if obj["category"] == "base_audit_patch_review"]
        self.assertEqual(len(objects), 8)
        review_json = [
            obj for obj in objects
            if obj["source_path"] == "reports/ba_patch_01_source_review_2026-05-05.json"
        ][0]
        plan_json = [
            obj for obj in objects
            if obj["source_path"] == "reports/ba_patch_01_proof_packet_plan_2026-05-05.json"
        ][0]
        execution_json = [
            obj for obj in objects
            if obj["source_path"] == "reports/ba_patch_01_proof_execution_2026-05-05.json"
        ][0]
        detector_json = [
            obj for obj in objects
            if obj["source_path"] == "reports/ba_patch_01_detector_2026-05-05.json"
        ][0]
        self.assertEqual(review_json["summary_fields"]["counts"]["observations_count"], 1)
        self.assertEqual(review_json["summary_fields"]["samples"][0]["kind"], "predicate-correction")
        self.assertEqual(review_json["summary_fields"]["samples"][0]["summary"], "Checks every transaction buffer instead of only the first row.")
        self.assertEqual(plan_json["summary_fields"]["counts"]["inspect_targets_count"], 1)
        self.assertEqual(plan_json["summary_fields"]["samples"][0]["role"], "patch_root")
        self.assertEqual(plan_json["summary_fields"]["samples"][0]["symbol"], "AttributesWithParent::is_deposits_only")
        self.assertEqual(execution_json["summary_fields"]["counts"]["observations_count"], 1)
        self.assertEqual(execution_json["summary_fields"]["counts"]["commands_run_count"], 1)
        self.assertEqual(execution_json["summary_fields"]["samples"][0]["kind"], "killed-on-patched-commit")
        self.assertEqual(detector_json["summary_fields"]["counts"]["local_verification_count"], 1)
        self.assertEqual(detector_json["summary_fields"]["counts"]["remaining_blockers_count"], 1)
        self.assertEqual(detector_json["summary_fields"]["samples"][0]["result"], "PASS: 7 tests passed")

    def test_provider_handoff_samples_use_provider_map(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "reports").mkdir()
            rel = "reports/model_takeover_provider_handoff_2026-05-05.json"
            (root / rel).write_text(
                json.dumps(
                    {
                        "schema": "auditooor.model_takeover_provider_handoff.v1",
                        "providers": {
                            "claude": {
                                "display_name": "Claude",
                                "status": "WARN",
                                "handoff_allowed": True,
                                "readiness_estimate_percent": 88,
                                "takeover_posture": "bounded_warn_handoff_only",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            obj = MOD.summarize_source(
                root,
                rel,
                "model_takeover_provider_handoff",
                "use provider handoff",
                "2026-05-05",
            )

        self.assertEqual(obj["object_type"], "json_report")
        self.assertEqual(obj["summary_fields"]["counts"]["providers_count"], 1)
        self.assertEqual(obj["summary_fields"]["samples"][0]["provider"], "claude")
        self.assertEqual(obj["summary_fields"]["samples"][0]["status"], "WARN")

    def test_stale_worktree_references_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "reports").mkdir()
            rel = "reports/memory_audit_packet_status_2026-05-05.json"
            (root / rel).write_text(
                json.dumps(
                    {
                        "schema": "auditooor.memory_audit_packet.v0",
                        "repo_root": "/Users/wolf/auditooor-worktrees/continuation-plan-update",
                        "top_next_actions": [
                            {
                                "id": "KLBQ-001",
                                "owner_lane": "source replay",
                                "next_action": "Preserve source refs.",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            obj = MOD.summarize_source(
                root,
                rel,
                "model_handoff",
                "use memory packet",
                "2026-05-05",
            )

        self.assertIn("summary_contains_non_selected_worktree_root", obj["stale_or_missing_reason"])
        guard = obj["summary_fields"]["stale_source_guard"]
        self.assertEqual(guard["status"], "fail_closed")
        self.assertFalse(guard["trusted_handoff_state"])
        self.assertIn("[worktree-root:continuation-plan-update]", guard["stale_roots"])
        self.assertNotIn(
            "/Users/wolf/auditooor-worktrees/continuation-plan-update",
            json.dumps(obj, sort_keys=True),
        )
        self.assertEqual(obj["summary_fields"]["samples"][0]["id"], "KLBQ-001")

    def test_known_limitations_status_samples_open_focus_rows_and_summary_counts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "reports").mkdir()
            rel = "reports/known_limitations_harness_memory_status_2026-05-05.json"
            (root / rel).write_text(
                json.dumps(
                    {
                        "schema": "auditooor.known_limitations_harness_memory_status.v1",
                        "summary": {
                            "open_focus_row_count": 2,
                            "lane_counts": {"memory_handoff": 2},
                            "open_rows_with_actionable_now_commands": 1,
                        },
                        "open_focus_rows": [
                            {
                                "id": "KLBQ-007",
                                "current_status": "partially_implemented_v0_partial_pass",
                                "dispatch_lane": "memory_handoff",
                                "next_action": "Run the memory refresh command.",
                                "next_action_status": "actionable_now_with_blocked_followups",
                                "actionable_now_commands": ["python3 tools/memory-brief.py --bootstrap --print-json"],
                                "blocked_command_templates": [
                                    {
                                        "command": "python3 tools/rust-detect.py <source-root>",
                                        "missing_inputs": ["<source-root>"],
                                        "unblock_criteria": ["Exact local source root is declared."],
                                    }
                                ],
                                "open": True,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            obj = MOD.summarize_source(
                root,
                rel,
                "known_limitations_harness_memory_status",
                "use harness memory status",
                "2026-05-05",
            )

        self.assertEqual(obj["summary_fields"]["counts"]["open_focus_rows_count"], 1)
        self.assertEqual(obj["summary_fields"]["counts"]["open_focus_row_count"], 2)
        self.assertEqual(obj["summary_fields"]["counts"]["lane_counts"]["memory_handoff"], 2)
        self.assertEqual(obj["summary_fields"]["samples"][0]["id"], "KLBQ-007")
        self.assertEqual(obj["summary_fields"]["samples"][0]["open"], True)
        self.assertEqual(
            obj["summary_fields"]["current_priority_order"],
            ["MEMORY", "HARNESS", "KNOWN LIMITATION BURNDOWN"],
        )
        self.assertEqual(
            obj["summary_fields"]["current_priority_lanes"],
            ["memory_handoff", "harness_execution", "known_limitations_burndown"],
        )
        self.assertEqual(
            obj["summary_fields"]["samples"][0]["next_action_status"],
            "actionable_now_with_blocked_followups",
        )
        self.assertEqual(
            obj["summary_fields"]["samples"][0]["actionable_now_commands"],
            ["python3 tools/memory-brief.py --bootstrap --print-json"],
        )
        self.assertEqual(
            obj["summary_fields"]["samples"][0]["blocked_command_templates"][0]["missing_inputs"],
            ["<source-root>"],
        )

    def test_commit_review_and_next_step_packets_are_sampled(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "reports").mkdir()
            review_rel = "reports/commit_mining_review_task_packet_2026-05-05.json"
            next_rel = "reports/commit_mining_next_step_packet_2026-05-05.json"
            (root / review_rel).write_text(
                json.dumps(
                    {
                        "schema": "auditooor.commit_mining_review_task_packet.v1",
                        "summary": {"emitted_task_count": 1},
                        "tasks": [{"task_id": "review-task-BA-PATCH-01", "status": "queued"}],
                    }
                ),
                encoding="utf-8",
            )
            (root / next_rel).write_text(
                json.dumps(
                    {
                        "schema": "auditooor.commit_mining_next_step_packet.v1",
                        "files_to_inspect": [{"path": "crates/consensus/protocol/src/attributes.rs"}],
                        "selected_row": {
                            "task_id": "scan-task-BA-PATCH-01",
                            "status": "queued",
                            "source_row_id": "BA-PATCH-01",
                        },
                    }
                ),
                encoding="utf-8",
            )

            review_obj = MOD.summarize_source(
                root,
                review_rel,
                "commit_mining_review_task_packet",
                "use review tasks",
                "2026-05-05",
            )
            next_obj = MOD.summarize_source(
                root,
                next_rel,
                "commit_mining_next_step_packet",
                "use next step",
                "2026-05-05",
            )

        self.assertEqual(review_obj["summary_fields"]["counts"]["tasks_count"], 1)
        self.assertEqual(review_obj["summary_fields"]["samples"][0]["task_id"], "review-task-BA-PATCH-01")
        self.assertEqual(next_obj["summary_fields"]["samples"][0]["task_id"], "scan-task-BA-PATCH-01")
        self.assertEqual(next_obj["summary_fields"]["samples"][0]["source_row_id"], "BA-PATCH-01")

    def test_json_summary_extracts_counts_and_samples(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._seed_minimal_tree(root)
            obj = MOD.summarize_source(
                root,
                "reports/scanner_wiring_truth_inventory_2026-05-05.json",
                "scanner_truth",
                "use scanner truth",
                "2026-05-05",
            )

        summary = obj["summary_fields"]
        self.assertEqual(obj["object_type"], "json_report")
        self.assertEqual(summary["schema"], "auditooor.scanner_wiring_truth_inventory.v1")
        self.assertEqual(summary["counts"]["item_count"], 2)
        self.assertEqual(summary["counts"]["rows_count"], 1)
        self.assertEqual(summary["counts"]["status_counts"]["quarantined_fake"], 1)
        self.assertEqual(summary["samples"][0]["wiring_status"], "quarantined_fake")

    def test_build_index_prefers_newer_compatible_scanner_truth_source(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._seed_minimal_tree(root)
            _write_json(
                root / "reports" / "scanner_wiring_truth_inventory_2026-05-08.json",
                {
                    "schema": "auditooor.scanner_wiring_truth_inventory.v1",
                    "item_count": 3,
                    "rows": [
                        {"scanner_id": f"fresh-{index}", "wiring_status": "wired_verified"}
                        for index in range(3)
                    ],
                },
            )
            _write_json(
                root / "reports" / "scanner_wiring_truth_inventory_2026-05-09.json",
                {
                    "schema": "auditooor.other_report.v1",
                    "item_count": 99,
                    "rows": [{"scanner_id": "wrong-schema"}],
                },
            )

            index = MOD.build_index(root, current_date="2026-05-08")

        scanner_truth = [
            obj
            for obj in index["memory_objects"]
            if obj["category"] == "scanner_truth"
            and obj["source_path"].startswith("reports/scanner_wiring_truth_inventory")
        ]
        self.assertEqual(len(scanner_truth), 1)
        self.assertEqual(
            scanner_truth[0]["source_path"],
            "reports/scanner_wiring_truth_inventory_2026-05-08.json",
        )
        self.assertEqual(scanner_truth[0]["summary_fields"]["counts"]["item_count"], 3)
        self.assertEqual(scanner_truth[0]["summary_fields"]["counts"]["rows_count"], 3)

    def test_build_index_prefers_newer_compatible_scanner_burndown_source(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._seed_minimal_tree(root)
            _write_json(
                root / "reports" / "scanner_wiring_burndown_queue_2026-05-05.json",
                {
                    "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                    "unique_action_count": 1,
                    "actions": [{"action_id": "old-action", "title": "Old action"}],
                },
            )
            _write_json(
                root / "reports" / "scanner_wiring_burndown_queue_2026-05-08.json",
                {
                    "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                    "unique_action_count": 2,
                    "actions": [
                        {"action_id": "fresh-action-1", "title": "Fresh action 1"},
                        {"action_id": "fresh-action-2", "title": "Fresh action 2"},
                    ],
                },
            )
            _write_json(
                root / "reports" / "scanner_wiring_burndown_queue_l22_2026-05-09.json",
                {
                    "schema": "auditooor.scanner_wiring_burndown_queue_l22.v1",
                    "unique_action_count": 99,
                    "actions": [{"action_id": "wrong-schema"}],
                },
            )

            index = MOD.build_index(root, current_date="2026-05-08")

        scanner_burndown = [
            obj
            for obj in index["memory_objects"]
            if obj["category"] == "scanner_burndown"
            and obj["source_path"].startswith("reports/scanner_wiring_burndown_queue")
        ]
        self.assertEqual(len(scanner_burndown), 1)
        self.assertEqual(
            scanner_burndown[0]["source_path"],
            "reports/scanner_wiring_burndown_queue_2026-05-08.json",
        )
        self.assertEqual(scanner_burndown[0]["summary_fields"]["counts"]["unique_action_count"], 2)

    def test_large_json_is_not_deep_parsed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "reports").mkdir()
            rel = "reports/scanner_wiring_truth_inventory_2026-05-05.json"
            rows = [{"title": f"row {idx}", "status": "blocked"} for idx in range(200)]
            (root / rel).write_text(json.dumps({"schema": "x", "rows": rows}), encoding="utf-8")

            obj = MOD.summarize_source(
                root,
                rel,
                "scanner_truth",
                "use scanner truth",
                "2026-05-05",
                max_json_parse_bytes=200,
            )

        self.assertEqual(obj["summary_fields"]["parse_mode"], "skipped_large_json")
        self.assertIn("json_parse_skipped_above_200_bytes", obj["stale_or_missing_reason"])
        self.assertNotIn("samples", obj["summary_fields"])

    def test_cli_writes_json_and_markdown_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._seed_minimal_tree(root)
            rc = MOD.main(
                [
                    "--root",
                    str(root),
                    "--output",
                    "reports/shared_memory_index_2026-05-05.json",
                    "--markdown-output",
                    "docs/SHARED_MEMORY_INDEX_2026-05-05.md",
                ]
            )
            self.assertEqual(rc, 0)
            report = root / "reports" / "shared_memory_index_2026-05-05.json"
            doc = root / "docs" / "SHARED_MEMORY_INDEX_2026-05-05.md"
            self.assertTrue(report.exists())
            self.assertTrue(doc.exists())
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], MOD.SCHEMA)
            self.assertIn("Shared Memory Index", doc.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
