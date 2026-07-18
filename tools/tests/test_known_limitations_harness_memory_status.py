from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "known-limitations-harness-memory-status.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("known_limitations_harness_memory_status", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


class KnownLimitationsHarnessMemoryStatusTests(unittest.TestCase):
    def test_scanner_defaults_choose_latest_local_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reports = root / "reports"
            reports.mkdir()
            _write_json(
                reports / "scanner_wiring_burndown_queue_2026-05-05.json",
                {
                    "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                    "actions": [{"row_id": "old"}],
                },
            )
            _write_json(
                reports / "scanner_wiring_burndown_queue_2026-05-08-postfix.json",
                {
                    "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                    "actions": [{"row_id": "new"}],
                },
            )
            _write_json(
                reports / "scanner_wiring_burndown_queue_2026-05-08-l24.json",
                {
                    "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                    "actionable_row_count": 2,
                    "top_action_count": 1,
                    "actions": [{"row_id": "l24"}],
                },
            )
            _write_json(
                reports / "scanner_wiring_burndown_queue_l22_enhanced_2026-05-08.json",
                {"schema": "auditooor.scanner_wiring_burndown_queue_l22.v1", "ranked_queue": []},
            )
            _write_json(
                reports / "scanner_worker_active_claims_2026-05-05.json",
                {"schema": "old"},
            )
            _write_json(
                reports / "scanner_worker_active_claims_2026-05-08.json",
                {"schema": "new"},
            )
            _write_json(
                reports / "commit_mining_source_disposition_2026-05-05.json",
                {"schema": "old"},
            )
            _write_json(
                reports / "commit_mining_source_disposition_2026-05-08.json",
                {"schema": "new"},
            )

            scanner_queue = MOD.default_scanner_burndown_queue_path(root)
            active_claims = MOD.default_scanner_worker_active_claims_path(root)
            commit_mining = MOD.default_commit_mining_source_disposition_path(root)

        self.assertEqual(scanner_queue.name, "scanner_wiring_burndown_queue_2026-05-08-l24.json")
        self.assertEqual(active_claims.name, "scanner_worker_active_claims_2026-05-08.json")
        self.assertEqual(commit_mining.name, "commit_mining_source_disposition_2026-05-08.json")

    def test_scanner_snapshot_marks_claimed_and_local_evidence_slots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "reports").mkdir()
            subprocess.run(["git", "init", "-b", "klbq-test"], cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (root / "detectors" / "fixtures" / "dirty_row").mkdir(parents=True)
            (root / "detectors" / "fixtures" / "dirty_row" / "positive.sol").write_text("// old\n", encoding="utf-8")
            (root / "detectors" / "fixtures" / "evidence_row").mkdir(parents=True)
            _write_json(root / "detectors" / "fixtures" / "evidence_row" / "row_smoke.json", {"result": "pass"})
            (root / "tools" / "tests").mkdir(parents=True)
            (root / "tools" / "tests" / "test_evidence_row.py").write_text("# proof\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Auditooor Test",
                    "-c",
                    "user.email=auditooor@example.invalid",
                    "commit",
                    "-m",
                    "baseline",
                ],
                cwd=root,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            (root / "detectors" / "fixtures" / "dirty_row" / "positive.sol").write_text("// dirty\n", encoding="utf-8")
            queue_path = root / "reports" / "scanner_wiring_burndown_queue_2026-05-05.json"
            _write_json(
                queue_path,
                {
                    "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                    "actionable_row_count": 2,
                    "top_action_count": 2,
                    "top_action_lane_counts": {"add_fixture_or_proof": 2},
                    "actions": [
                        {
                            "rank": 1,
                            "lane": "add_fixture_or_proof",
                            "row_id": "dirty_row",
                            "backend": "solidity",
                            "source_paths": ["detectors/fixtures/dirty_row/positive.sol"],
                            "suggested_commands": [],
                        },
                        {
                            "rank": 2,
                            "lane": "add_fixture_or_proof",
                            "row_id": "evidence_row",
                            "backend": "solidity",
                            "source_paths": [],
                            "suggested_commands": [],
                        },
                    ],
                },
            )

            snapshot, issues = MOD._scanner_burndown_snapshot(root, queue_path)

        self.assertEqual(issues, [])
        self.assertEqual(
            snapshot["worker_slot_coordination_counts"],
            {"claimed_dirty_worktree": 1, "local_evidence_present_refresh_needed": 1},
        )
        self.assertEqual(snapshot["assignable_worker_slot_count"], 0)
        self.assertEqual(snapshot["skipped_worker_slot_count"], 2)
        self.assertTrue(
            snapshot["scanner_coordination_guidance"]["refresh_inventory_before_more_detector_assignments"]
        )
        self.assertEqual(
            snapshot["scanner_coordination_guidance"]["do_not_redispatch_statuses"],
            ["claimed_dirty_worktree", "local_evidence_present_refresh_needed"],
        )
        self.assertEqual(snapshot["next_worker_slots"], [])
        slots = {slot["row_id"]: slot for slot in snapshot["skipped_worker_slots"]}
        self.assertEqual(slots["dirty_row"]["local_coordination_status"], "claimed_dirty_worktree")
        self.assertEqual(
            slots["dirty_row"]["matching_dirty_paths"],
            ["detectors/fixtures/dirty_row/positive.sol"],
        )
        self.assertEqual(slots["evidence_row"]["local_coordination_status"], "local_evidence_present_refresh_needed")
        self.assertIn("tools/tests/test_evidence_row.py", slots["evidence_row"]["local_evidence_paths"])

    def test_scanner_active_claims_snapshot_reports_live_owned_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            claims_path = root / "reports" / "scanner_worker_active_claims_2026-05-05.json"
            _write_json(
                claims_path,
                {
                    "schema": "auditooor.scanner_worker_active_claims.v1",
                    "updated_at": "2026-05-06T07:09:56Z",
                    "active_claims": [
                        {
                            "agent_id": "agent-active",
                            "row_id": "r74_oracle_no_l2_sequencer_grace_window",
                            "status": "active",
                        },
                        {
                            "agent_id": "agent-done",
                            "row_id": "r74_input_withdrawal_fee_dos_precision",
                            "status": "completed",
                        },
                    ],
                    "summary": {"active": 1, "completed": 1},
                },
            )

            snapshot, issues = MOD._scanner_active_claims_snapshot(root, claims_path)

        self.assertEqual(issues, [])
        self.assertTrue(snapshot["present"])
        self.assertEqual(snapshot["active"], 1)
        self.assertEqual(snapshot["completed"], 1)
        self.assertEqual(
            snapshot["active_claims"],
            [
                {
                    "agent_id": "agent-active",
                    "row_id": "r74_oracle_no_l2_sequencer_grace_window",
                    "status": "active",
                }
            ],
        )
        self.assertIn("coordination memory", snapshot["strict_caveat"])

    def test_emit_outputs_can_probe_without_touching_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "reports" / "status.json"
            docs = root / "docs" / "status.md"

            written = MOD._emit_outputs(
                output_path=output,
                docs_path=docs,
                report={"schema": "test"},
                markdown="# status\n",
                write_outputs=False,
            )

            self.assertEqual(written, [])
            self.assertFalse(output.exists())
            self.assertFalse(docs.exists())

            written = MOD._emit_outputs(
                output_path=output,
                docs_path=docs,
                report={"schema": "test"},
                markdown="# status\n",
                write_outputs=True,
            )

            self.assertEqual(written, [str(output), str(docs)])
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), {"schema": "test"})
            self.assertEqual(docs.read_text(encoding="utf-8"), "# status\n")

    def test_scanner_snapshot_skips_claimed_slots_and_fills_assignable_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "reports").mkdir()
            subprocess.run(["git", "init", "-b", "klbq-test"], cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (root / "detectors" / "fixtures" / "claimed_row").mkdir(parents=True)
            (root / "detectors" / "fixtures" / "claimed_row" / "positive.sol").write_text("// old\n", encoding="utf-8")
            (root / "detectors" / "fixtures" / "evidence_row").mkdir(parents=True)
            _write_json(root / "detectors" / "fixtures" / "evidence_row" / "smoke.json", {"result": "pass"})
            (root / "tools" / "tests").mkdir(parents=True)
            (root / "tools" / "tests" / "test_evidence_row.py").write_text("# proof\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Auditooor Test",
                    "-c",
                    "user.email=auditooor@example.invalid",
                    "commit",
                    "-m",
                    "baseline",
                ],
                cwd=root,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            (root / "detectors" / "fixtures" / "claimed_row" / "positive.sol").write_text("// dirty\n", encoding="utf-8")
            queue_path = root / "reports" / "scanner_wiring_burndown_queue_2026-05-05.json"
            _write_json(
                queue_path,
                {
                    "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                    "actionable_row_count": 7,
                    "top_action_count": 7,
                    "top_action_lane_counts": {"add_fixture_or_proof": 7},
                    "actions": [
                        {
                            "rank": 1,
                            "lane": "add_fixture_or_proof",
                            "row_id": "claimed_row",
                            "backend": "solidity",
                            "source_paths": ["detectors/fixtures/claimed_row/positive.sol"],
                            "suggested_commands": [],
                        },
                        {
                            "rank": 2,
                            "lane": "add_fixture_or_proof",
                            "row_id": "evidence_row",
                            "backend": "solidity",
                            "source_paths": [],
                            "suggested_commands": [],
                        },
                        *[
                            {
                                "rank": rank,
                                "lane": "add_fixture_or_proof",
                                "row_id": f"fresh_row_{rank}",
                                "backend": "solidity",
                                "source_paths": [],
                                "suggested_commands": [],
                            }
                            for rank in range(3, 8)
                        ],
                    ],
                },
            )

            snapshot, issues = MOD._scanner_burndown_snapshot(root, queue_path)

        self.assertEqual(issues, [])
        self.assertEqual(snapshot["assignable_worker_slot_count"], 5)
        self.assertEqual(snapshot["skipped_worker_slot_count"], 2)
        self.assertTrue(
            snapshot["scanner_coordination_guidance"]["refresh_inventory_before_more_detector_assignments"]
        )
        self.assertEqual(
            snapshot["scanner_coordination_guidance"]["do_not_redispatch_sample_row_ids"],
            ["claimed_row", "evidence_row"],
        )
        self.assertEqual(snapshot["worker_slots_scanned"], 7)
        self.assertEqual(
            [slot["row_id"] for slot in snapshot["next_worker_slots"]],
            ["fresh_row_3", "fresh_row_4", "fresh_row_5", "fresh_row_6", "fresh_row_7"],
        )
        self.assertEqual(
            [slot["row_id"] for slot in snapshot["skipped_worker_slots"]],
            ["claimed_row", "evidence_row"],
        )
        self.assertEqual(snapshot["skipped_worker_slots"][0]["skip_reason"], "claimed_dirty_worktree")
        self.assertEqual(snapshot["skipped_worker_slots"][1]["skip_reason"], "local_evidence_present_refresh_needed")

    def test_build_status_report_applies_narrow_local_refreshes_for_004_006_007_008_010(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "reports").mkdir()
            (root / "docs").mkdir()
            (root / "tools" / "tests").mkdir(parents=True)
            (root / "tools").mkdir(exist_ok=True)

            _write_json(
                root / "reports" / "fallback_handler_address_guard_calibration_2026-05-05.json",
                {
                    "packet_name": "fallback_handler_address_guard_calibration",
                    "status": "calibration_only",
                    "promotion_ready": False,
                    "registry_backed_detector": {
                        "verified": True,
                        "smoke": {
                            "positive_hits": 1,
                            "negative_hits": 0,
                            "result": "pass",
                        },
                    },
                    "adjacent_sibling_detector": {
                        "smoke": {
                            "positive_hits": 1,
                            "negative_hits": 0,
                            "result": "pass",
                        },
                    },
                    "promotion_posture": "calibration_only_hold",
                    "promotion_blockers": [
                        "taxonomy/coverage metadata is still split between the generic input-validation assignment and the more specific safe-fallback-handler-setter-missing-address-guard class",
                        "evidence is still limited to dedicated fixture smoke rather than broader clean-corpus or real-target precision validation",
                    ],
                },
            )
            _write_json(
                root / "reports" / "klbq_006_precision_evidence_2026-05-05.json",
                {
                    "limitation_id": "KLBQ-006",
                    "status": "moved_forward_not_verified",
                    "summary": {
                        "added_synthetic_precision_corpus": True,
                        "bounded_synthetic_precision_passes": True,
                        "real_target_source_replay_passes": False,
                        "taxonomy_reconciled": False,
                    },
                    "missing_or_insufficient_inputs": [
                        "Exact reNFT source checkout for Solodit #30522 is not local.",
                        "No real-source file/line anchors for the vulnerable guard path are recorded.",
                        "No ground-truthed real-target clean corpus has been run for this detector family.",
                        "Taxonomy/accounting metadata is still split between input-validation and safe-fallback-handler-setter-missing-address-guard.",
                    ],
                    "next_commands": [
                        "rg -n \"setFallbackHandler|fallbackHandler|checkTransaction|check_transaction|f08a0323\" <renft-source-root>",
                        "python3 tools/rust-detect.py <renft-source-root> --only r94_loop_safe_fallback_handler_setter_missing_address_guard --log /tmp/klbq006_renft_r94.log",
                    ],
                },
            )
            _write_json(
                root / "reports" / "klbq_006_real_source_anchors_2026-05-05.json",
                {
                    "finding_id": "30522",
                    "classification": {
                        "exact_finding_github_blob_anchors": "absent",
                        "exact_renft_source_root": "present",
                        "real_source_anchors": "present",
                    },
                },
            )
            _write_json(
                root / "reports" / "klbq_006_terminal_boundary_2026-05-05.json",
                {
                    "schema": "auditooor.klbq_006_terminal_boundary.v1",
                    "limitation_id": "KLBQ-006",
                    "promotion_ready": False,
                    "verification_claim_allowed": False,
                    "rust_detector_boundary": {
                        "state": "terminal_inapplicable",
                        "reason": "source_language_mismatch_solidity_root_without_rust_files",
                        "can_interpret_detector_absence_as_clean_result": False,
                    },
                    "taxonomy_reconciliation": {
                        "canonical_leaf_family": "safe-fallback-handler-setter-missing-address-guard",
                        "parent_class": "input-validation",
                        "input_validation_usage": "parent_or_alias_only",
                    },
                    "exact_next_commands": [
                        "python3 tools/klbq006-terminal-boundary.py --renft-root /tmp/re-nft",
                    ],
                },
            )
            _write_json(
                root / "reports" / "klbq_006_solidity_replay_status_2026-05-05.json",
                {
                    "schema": "auditooor.klbq_006_solidity_replay_status.v1",
                    "limitation_id": "KLBQ-006",
                    "finding_id": "30522",
                    "status": "source_aware_replay_commands_consumed_fail_closed",
                    "promotion_ready": False,
                    "verification_claim_allowed": False,
                    "exact_next_command": (
                        "python3 tools/klbq006-real-source-anchors.py --root /tmp/re-nft "
                        "--root /tmp/ws --out reports/klbq_006_real_source_anchors_2026-05-05.json --max-files 100000"
                    ),
                    "source_citation_acquisition": {
                        "state": "blocked_pending_exact_30522_source_citation",
                        "missing_inputs": ["exact Solodit #30522 source report or source-spec row"],
                        "exact_next_commands": [
                            "python3 tools/klbq006-real-source-anchors.py --root /tmp/re-nft --root /tmp/ws --out reports/klbq_006_real_source_anchors_2026-05-05.json --max-files 100000",
                            "rg -n \"Solodit\\s+#30522\" detectors docs reports reference",
                        ],
                    },
                    "foundry_dependency_unblock": {
                        "state": "blocked_uninitialized_or_empty_submodules",
                        "declared_submodule_count": 7,
                        "uninitialized_or_empty_submodule_count": 7,
                        "network_unblock_command": "git -C /tmp/re-nft submodule update --init --recursive",
                        "rerun_exact_proof_command_after_dependencies": (
                            "forge test --root /tmp/re-nft --match-path "
                            "test/unit/Guard/CheckTransaction.t.sol --match-test "
                            "test_Reverts_CheckTransaction_Gnosis_SetFallbackHandler -vvv"
                        ),
                        "offline_fallback_requires_exact_submodule_commits": True,
                    },
                    "command_consumption": {"consumed_command_count": 7},
                    "replay_gate": {"fail_closed": True},
                },
            )
            (root / "docs" / "KLBQ_006_PRECISION_EVIDENCE_2026-05-05.md").write_text(
                "synthetic precision evidence\n",
                encoding="utf-8",
            )
            (root / "docs" / "KLBQ_006_REAL_SOURCE_ANCHORS_2026-05-05.md").write_text(
                "exact real-source replay still blocked\n",
                encoding="utf-8",
            )
            (root / "docs" / "KLBQ_006_SOLIDITY_REPLAY_STATUS_2026-05-05.md").write_text(
                "solidity replay status\n",
                encoding="utf-8",
            )
            (root / "docs" / "HARNESS_FAILURE_MEMORY.md").write_text(
                "\n".join(
                    [
                        "KLBQ-007 adds a minimal per-occurrence event contract beside the aggregate root report.",
                        "docs/schemas/harness_failure_event.v1.json",
                        "docs/schemas/harness_failure_event_summary.v1.json",
                        "When `--from-events` is supplied with `--events-report`, the aggregate reports/harness_failures.jsonl rows are materialized from validated event rows.",
                        "The event validator and summary materializer remain available through the explicit CLI paths.",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "tools" / "harness-failure-memory.py").write_text(
                "\n".join(
                    [
                        'parser.add_argument("--from-events", action="store_true",',
                        '                    help="materialize aggregate root report from validated --events-report rows")',
                        'errors.append(f"cannot materialize aggregate for unknown root_cause_id {root_cause_id}: missing seeded metadata")',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "tools" / "tests" / "test_harness_failure_memory.py").write_text(
                "\n".join(
                    [
                        "def test_cli_validate_events_writes_summary():",
                        "    pass",
                        "def test_cli_from_events_materializes_aggregate_report_and_notes():",
                        "    pass",
                        '"--from-events"',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "docs" / "TASK_FINALIZATION_LEDGER.md").write_text(
                "python3 tools/task-finalization-ledger.py audit-manifest --manifest x\n",
                encoding="utf-8",
            )
            (root / "tools" / "memory-next-loop-dispatcher.py").write_text(
                "\n".join(
                    [
                        '"skip_reason": "slot_reuse_blocked_pending_finalization"',
                        "lacks a valid task-finalization ledger row",
                        "next_slot_id(inflight_slots, workpacks, blocked_slot_ids)",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "tools" / "tests" / "test_memory_next_loop_dispatcher.py").write_text(
                "\n".join(
                    [
                        "def test_terminal_manifest_row_without_finalization_blocks_slot_reuse():",
                        "    pass",
                        'self.assertEqual([slot["slot_id"] for slot in payload["slots"]], ["slot-3"])',
                        "def test_valid_finalization_clears_terminal_manifest_slot_for_reuse():",
                        "    pass",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "docs" / "KNOWN_LIMITATIONS.md").write_text(
                "\n".join(
                    [
                        "Impact-first gates | Reduced, not resolved",
                        "harness-scaffold",
                        "source-proof-record",
                        "pre-submit Check #32",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "tools" / "source-proof-record.py").write_text(
                'impact_contract_preflight\nbuild_source_proof_preflight\nroute="source-proof"\n',
                encoding="utf-8",
            )
            (root / "tools" / "harness-scaffold-emitter.py").write_text(
                "\n".join(
                    [
                        "impact_contract_preflight",
                        "harness_impact_preflight",
                        'route="harness-scaffold"',
                        "BINDING_MANIFEST_FILENAME",
                        "write_attempt_and_binding_manifest",
                        "write_binding_manifest",
                        "binding_manifest_path",
                        "binding_status",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "tools" / "harness-binding-manifest.py").write_text(
                "status_refresh\nready_executable_binding\n",
                encoding="utf-8",
            )
            (root / "tools" / "exploit-memory-brief.py").write_text(
                'impact_contract_preflight\n_exploit_memory_preflight\nroute="exploit-memory"\nplanning-artifact-advisory-bypass\n',
                encoding="utf-8",
            )
            (root / "tools" / "tests" / "test_source_proof_record.py").write_text(
                "impact_contract_preflight\nsource-proof\n",
                encoding="utf-8",
            )
            (root / "tools" / "tests" / "test_harness_scaffold_emitter.py").write_text(
                "\n".join(
                    [
                        "impact_contract_preflight",
                        "harness-scaffold",
                        "TestBindingManifestEmission",
                        "test_ready_scaffold_writes_ready_binding_manifest",
                        "test_blocked_attempt_writes_blocked_binding_manifest",
                        "test_idempotent_rerun_backfills_missing_binding_manifest",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "tools" / "tests" / "test_harness_binding_manifest.py").write_text(
                "test_klbq_004_status_refresh_row_can_be_exact_without_harness_inputs\nstatus_refresh\n",
                encoding="utf-8",
            )
            (root / "tools" / "tests" / "test_exploit_memory_brief.py").write_text(
                "impact_contract_preflight\nexploit-memory\n",
                encoding="utf-8",
            )
            (root / "tools" / "tests" / "test_pre_submit_impact_contract_check.py").write_text(
                "impact-contract-missing\nimpact-contract-explicit\n",
                encoding="utf-8",
            )
            (root / "tools" / "tests" / "test_agent_output_synthesizer_impact_contract.py").write_text(
                "impact-contract-missing\ncandidate_finding\n",
                encoding="utf-8",
            )

            _write_json(
                root / "reports" / "known_limitations_burndown_queue_2026-05-05.json",
                {
                    "schema": "auditooor.known_limitations_burndown_queue.v1",
                    "date": "2026-05-05",
                    "rows": [
                        {
                            "id": "KLBQ-004",
                            "implementation_status": "partially_implemented_v0",
                            "owner_lane": "harness precision",
                            "status_notes": "producer/scaffold route did not emit manifest",
                            "blocked_until": [
                                "producer/scaffold route emits the binding manifest directly",
                            ],
                        },
                        {
                            "id": "KLBQ-006",
                            "implementation_status": "partially_implemented_v0",
                            "owner_lane": "harness precision / detector calibration",
                            "blocked_until": [
                                "The local calibration packet still reports promotion_ready=false and status=calibration_only."
                            ],
                        },
                        {
                            "id": "KLBQ-007",
                            "owner_lane": "memory recall / harness precision",
                            "blocked_until": [
                                "event schema exists",
                                "aggregate report is generated from events",
                            ],
                        },
                        {
                            "id": "KLBQ-008",
                            "owner_lane": "submission finalization / memory recall",
                            "blocked_until": ["slot refill checks canonical finalization coverage"],
                        },
                        {
                            "id": "KLBQ-010",
                            "owner_lane": "submission finalization / exploit discovery",
                            "blocked_until": [
                                "strict impact-contract preflight is wired to filing and promotion routes"
                            ],
                        },
                    ],
                },
            )
            _write_json(
                root / "reports" / "known_limitations_dispatch_2026-05-05.json",
                {
                    "schema": "auditooor.known_limitations_dispatch.v1",
                    "date": "2026-05-05",
                    "work_items": [
                        {
                            "limitation_id": "KLBQ-004",
                            "dispatch_lane": "blocked_needs_user_input",
                            "current_status": "partially_implemented_v0_partial_pass",
                            "blocker": "queue probe still classifies KLBQ-004 as blocked_vague_plan",
                            "dispatch_ready": False,
                            "expected_loop_cost": 1,
                        },
                        {
                            "limitation_id": "KLBQ-006",
                            "dispatch_lane": "harness_execution",
                            "current_status": "open_blocked",
                            "blocker": "The local calibration packet still reports promotion_ready=false and status=calibration_only.",
                            "dispatch_ready": True,
                            "expected_loop_cost": 1,
                        },
                        {
                            "limitation_id": "KLBQ-007",
                            "dispatch_lane": "memory_handoff",
                            "current_status": "open_blocked",
                            "blocker": "Awaiting: event schema exists",
                            "dispatch_ready": True,
                            "expected_loop_cost": 2,
                        },
                        {
                            "limitation_id": "KLBQ-008",
                            "dispatch_lane": "memory_handoff",
                            "current_status": "open_blocked",
                            "blocker": "Awaiting: slot refill checks canonical finalization coverage",
                            "dispatch_ready": True,
                            "expected_loop_cost": 1,
                        },
                        {
                            "limitation_id": "KLBQ-010",
                            "dispatch_lane": "memory_handoff",
                            "current_status": "open_blocked",
                            "blocker": "Awaiting: strict impact-contract preflight is wired to filing and promotion routes",
                            "dispatch_ready": True,
                            "expected_loop_cost": 2,
                        },
                    ],
                },
            )
            _write_json(
                root / "reports" / "impact_contract_preflight_status_2026-05-05.json",
                {
                    "schema": "auditooor.impact_contract_preflight_status.v1",
                    "limitation_id": "KLBQ-010",
                    "implementation_status": "implemented_verified_local_evidence",
                    "open": False,
                    "dispatch_ready": False,
                    "expected_loop_cost": 0,
                    "not_submission_evidence": True,
                    "closed_benefit": "Route coverage is locally verified.",
                    "verification_commands": [
                        "python3 -m unittest tools.tests.test_impact_contract_preflight_status -v",
                        "python3 -m json.tool reports/impact_contract_preflight_status_2026-05-05.json",
                    ],
                    "evidence_paths": [
                        "tools/impact-contract-preflight.py",
                        "tools/tests/test_impact_contract_preflight_status.py",
                    ],
                },
            )
            (root / "docs" / "IMPACT_CONTRACT_PREFLIGHT_STATUS_2026-05-05.md").write_text(
                "local-only impact contract status\n",
                encoding="utf-8",
            )

            report = MOD.build_status_report(
                root,
                root / "reports" / "known_limitations_burndown_queue_2026-05-05.json",
                root / "reports" / "known_limitations_dispatch_2026-05-05.json",
            )

        rows = {
            row["id"]: row
            for row in (
                report["open_focus_rows"]
                + report["verified_focus_rows"]
                + report["related_harness_memory_rows"]
            )
        }
        self.assertEqual(rows["KLBQ-004"]["current_status"], "implemented_verified_local_evidence")
        self.assertFalse(rows["KLBQ-004"]["open"])
        self.assertEqual(rows["KLBQ-004"]["blockers"], [])
        self.assertEqual(rows["KLBQ-004"]["expected_loop_cost"], 0)
        self.assertIn(
            "python3 -m unittest tools.tests.test_harness_scaffold_emitter tools.tests.test_harness_binding_manifest -v",
            rows["KLBQ-004"]["verification_commands"],
        )
        self.assertEqual(rows["KLBQ-004"]["next_action_status"], "completed_local_evidence")
        self.assertIn(
            "python3 -m unittest tools.tests.test_harness_scaffold_emitter tools.tests.test_harness_binding_manifest -v",
            rows["KLBQ-004"]["actionable_now_commands"],
        )
        self.assertIn("harness_binding_manifest.json", rows["KLBQ-004"]["status_notes"])
        self.assertEqual(rows["KLBQ-006"]["current_status"], "partially_implemented_v0_partial_pass")
        self.assertTrue(rows["KLBQ-006"]["open"])
        self.assertEqual(rows["KLBQ-006"]["next_action_status"], "actionable_now_with_blocked_followups")
        self.assertNotIn(
            "The local calibration packet still reports promotion_ready=false and status=calibration_only.",
            rows["KLBQ-006"]["blockers"],
        )
        self.assertTrue(any("Canonical KLBQ-006 taxonomy is reconciled locally" in blocker for blocker in rows["KLBQ-006"]["blockers"]))
        self.assertTrue(any("Exact Solodit #30522 GitHub blob" in blocker for blocker in rows["KLBQ-006"]["blockers"]))
        self.assertTrue(any("Synthetic calibration evidence is clean" in blocker for blocker in rows["KLBQ-006"]["blockers"]))
        self.assertTrue(any("Rust detector replay is terminally inapplicable" in blocker for blocker in rows["KLBQ-006"]["blockers"]))
        self.assertTrue(any("Solidity replay status consumes the terminal-boundary commands" in blocker for blocker in rows["KLBQ-006"]["blockers"]))
        self.assertTrue(any("Foundry dependencies remain uninitialized or empty" in blocker for blocker in rows["KLBQ-006"]["blockers"]))
        self.assertIn("bounded 4-file Rust corpus", rows["KLBQ-006"]["status_notes"])
        self.assertIn("pinned local reNFT mirror", rows["KLBQ-006"]["status_notes"])
        self.assertIn("machine-readable terminal boundary", rows["KLBQ-006"]["status_notes"])
        self.assertIn("cannot be counted as pass", rows["KLBQ-006"]["status_notes"])
        self.assertIn("companion Solidity replay-status packet", rows["KLBQ-006"]["status_notes"])
        self.assertIn("advances the next exact command", rows["KLBQ-006"]["status_notes"])
        self.assertIn("Run the machine-recorded source-citation acquisition command", rows["KLBQ-006"]["next_action"])
        self.assertIn("python3 tools/klbq006-real-source-anchors.py --root /tmp/re-nft", rows["KLBQ-006"]["next_action"])
        self.assertIn("exact #30522 source metadata/blob citation is still absent", rows["KLBQ-006"]["next_action"])
        self.assertIn("Foundry dependency unblock remains queued", rows["KLBQ-006"]["next_action"])
        self.assertIn(
            "python3 -m json.tool reports/klbq_006_precision_evidence_2026-05-05.json",
            rows["KLBQ-006"]["verification_commands"],
        )
        self.assertIn(
            "python3 -m json.tool reports/klbq_006_precision_evidence_2026-05-05.json",
            rows["KLBQ-006"]["actionable_now_commands"],
        )
        self.assertIn(
            "python3 -m json.tool reports/klbq_006_terminal_boundary_2026-05-05.json",
            rows["KLBQ-006"]["verification_commands"],
        )
        self.assertIn(
            "python3 -m json.tool reports/klbq_006_solidity_replay_status_2026-05-05.json",
            rows["KLBQ-006"]["verification_commands"],
        )
        self.assertIn(
            "python3 -m unittest tools.tests.test_klbq006_terminal_boundary tools.tests.test_klbq006_solidity_replay_status -v",
            rows["KLBQ-006"]["verification_commands"],
        )
        self.assertIn(
            "reports/klbq_006_real_source_anchors_2026-05-05.json",
            rows["KLBQ-006"]["evidence_paths"],
        )
        self.assertIn(
            "reports/klbq_006_terminal_boundary_2026-05-05.json",
            rows["KLBQ-006"]["evidence_paths"],
        )
        self.assertIn(
            "reports/klbq_006_solidity_replay_status_2026-05-05.json",
            rows["KLBQ-006"]["evidence_paths"],
        )
        blocked_commands = {
            blocked["command"]
            for blocked in rows["KLBQ-006"]["blocked_command_templates"]
        }
        self.assertIn(
            "python3 tools/klbq006-real-source-anchors.py --root /tmp/re-nft --root /tmp/ws --out reports/klbq_006_real_source_anchors_2026-05-05.json --max-files 100000",
            blocked_commands,
        )
        self.assertIn("git -C /tmp/re-nft submodule update --init --recursive", blocked_commands)
        self.assertIn(
            "forge test --root /tmp/re-nft --match-path test/unit/Guard/CheckTransaction.t.sol --match-test test_Reverts_CheckTransaction_Gnosis_SetFallbackHandler -vvv",
            blocked_commands,
        )
        self.assertEqual(rows["KLBQ-007"]["current_status"], "implemented_verified_local_evidence")
        self.assertEqual(rows["KLBQ-007"]["next_action_status"], "completed_local_evidence")
        self.assertFalse(rows["KLBQ-007"]["dispatch_ready"])
        self.assertEqual(rows["KLBQ-007"]["expected_loop_cost"], 0)
        self.assertIsNone(rows["KLBQ-007"]["scheduled_loop"])
        self.assertEqual(rows["KLBQ-007"]["blockers"], [])
        self.assertFalse(rows["KLBQ-007"]["open"])
        self.assertEqual(
            rows["KLBQ-007"]["verification_commands"],
            ["python3 -m unittest tools.tests.test_harness_failure_memory -v"],
        )
        self.assertEqual(
            rows["KLBQ-007"]["evidence_paths"],
            [
                "docs/HARNESS_FAILURE_MEMORY.md",
                "docs/schemas/harness_failure_event.v1.json",
                "docs/schemas/harness_failure_event_summary.v1.json",
                "tools/harness-failure-memory.py",
                "tools/tests/test_harness_failure_memory.py",
            ],
        )
        self.assertIn("explicit --from-events aggregate materialization path", rows["KLBQ-007"]["status_notes"])
        self.assertEqual(rows["KLBQ-008"]["current_status"], "implemented_verified_local_evidence")
        self.assertEqual(rows["KLBQ-008"]["next_action_status"], "completed_local_evidence")
        self.assertFalse(rows["KLBQ-008"]["open"])
        self.assertEqual(rows["KLBQ-008"]["blockers"], [])
        self.assertEqual(rows["KLBQ-010"]["current_status"], "implemented_verified_local_evidence")
        self.assertEqual(rows["KLBQ-010"]["next_action_status"], "completed_local_evidence")
        self.assertFalse(rows["KLBQ-010"]["open"])
        self.assertEqual(rows["KLBQ-010"]["expected_loop_cost"], 0)
        self.assertEqual(rows["KLBQ-010"]["blockers"], [])
        self.assertEqual(
            rows["KLBQ-010"]["local_status_packet"],
            "reports/impact_contract_preflight_status_2026-05-05.json",
        )
        self.assertIn(
            "python3 -m unittest tools.tests.test_impact_contract_preflight_status -v",
            rows["KLBQ-010"]["verification_commands"],
        )
        self.assertIn(
            "reports/impact_contract_preflight_status_2026-05-05.json",
            rows["KLBQ-010"]["evidence_paths"],
        )
        self.assertIn("not exploit proof", rows["KLBQ-010"]["status_notes"])
        self.assertGreaterEqual(report["summary"]["open_rows_with_actionable_now_commands"], 1)
        blocked_lookup = {row["id"]: row for row in report["blocked_or_missing_rows"]}
        self.assertNotIn("KLBQ-007", blocked_lookup)
        self.assertNotIn("KLBQ-008", blocked_lookup)

    def test_build_status_report_tracks_open_focus_rows_and_related_blocked_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "reports").mkdir()
            (root / "docs").mkdir()
            for rel in (
                "docs/HARNESS_FAILURE_MEMORY.md",
                "reports/harness_failures.jsonl",
                "reports/fallback_handler_address_guard_calibration_2026-05-05.json",
                "reports/g1_source_root_locator_2026-05-05.json",
            ):
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture\n", encoding="utf-8")

            _write_json(
                root / "reports" / "known_limitations_burndown_queue_2026-05-05.json",
                {
                    "schema": "auditooor.known_limitations_burndown_queue.v1",
                    "date": "2026-05-05",
                    "worktree": str(root),
                    "branch": "continuation-plan",
                    "rows": [
                        {
                            "rank": 2,
                            "id": "KLBQ-002",
                            "implementation_status": "partially_implemented_v0",
                            "owner_lane": "source replay / memory recall",
                            "concrete_next_patch": "Acquire exact local source roots.",
                            "remaining_blockers": ["local source roots are absent"],
                            "source_refs": ["reports/g1_source_root_locator_2026-05-05.json"],
                            "not_submission_evidence": True,
                        },
                        {
                            "rank": 6,
                            "id": "KLBQ-006",
                            "implementation_status": "partially_implemented_v0",
                            "owner_lane": "harness precision / detector calibration",
                            "concrete_next_patch": "Run broader bounded precision.",
                            "remaining_blockers": ["promotion_ready=false"],
                            "local_evidence": ["reports/fallback_handler_address_guard_calibration_2026-05-05.json"],
                            "not_submission_evidence": True,
                        },
                        {
                            "rank": 7,
                            "id": "KLBQ-007",
                            "owner_lane": "memory recall / harness precision",
                            "concrete_next_patch": "Add event rows.",
                            "blocked_until": ["event schema exists", "aggregate report is generated from events"],
                            "source_refs": ["docs/HARNESS_FAILURE_MEMORY.md", "reports/harness_failures.jsonl"],
                            "not_submission_evidence": True,
                        },
                    ],
                },
            )
            _write_json(
                root / "reports" / "known_limitations_dispatch_2026-05-05.json",
                {
                    "schema": "auditooor.known_limitations_dispatch.v1",
                    "date": "2026-05-05",
                    "worktree": str(root),
                    "branch": "continuation-plan",
                    "work_items": [
                        {
                            "limitation_id": "KLBQ-006",
                            "current_status": "partially_implemented_v0_partial_pass",
                            "blocker": "promotion_ready=false",
                            "dispatch_lane": "harness_execution",
                            "next_action": "Run broader bounded precision.",
                            "evidence_paths": ["reports/fallback_handler_address_guard_calibration_2026-05-05.json"],
                            "missing_evidence_paths": [],
                            "priority": "P1",
                            "expected_loop_cost": 1,
                            "dispatch_ready": True,
                            "owner_lane": "harness precision / detector calibration",
                        },
                        {
                            "limitation_id": "KLBQ-007",
                            "current_status": "open_blocked",
                            "blocker": "Awaiting: event schema exists",
                            "dispatch_lane": "memory_handoff",
                            "next_action": "Add event rows.",
                            "evidence_paths": ["docs/HARNESS_FAILURE_MEMORY.md", "reports/harness_failures.jsonl"],
                            "missing_evidence_paths": [],
                            "priority": "P2",
                            "expected_loop_cost": 2,
                            "dispatch_ready": True,
                            "owner_lane": "memory recall / harness precision",
                        },
                        {
                            "limitation_id": "KLBQ-002",
                            "current_status": "partially_implemented_v0_pass_with_real_blockers_remaining",
                            "blocker": "local source roots are absent",
                            "dispatch_lane": "blocked_needs_source",
                            "next_action": "Acquire exact local source roots.",
                            "evidence_paths": ["reports/g1_source_root_locator_2026-05-05.json"],
                            "missing_evidence_paths": [],
                            "priority": "P2",
                            "expected_loop_cost": 1,
                            "dispatch_ready": False,
                            "owner_lane": "source replay / memory recall",
                        },
                    ],
                },
            )
            _write_json(
                root / "reports" / "fallback_handler_address_guard_calibration_2026-05-05.json",
                {
                    "packet_name": "fallback_handler_address_guard_calibration",
                    "status": "calibration_only",
                    "promotion_ready": False,
                    "registry_backed_detector": {
                        "verified": True,
                        "smoke": {"positive_hits": 1, "negative_hits": 0, "result": "pass"},
                    },
                    "adjacent_sibling_detector": {
                        "smoke": {"positive_hits": 1, "negative_hits": 0, "result": "pass"},
                    },
                    "promotion_posture": "calibration_only_hold",
                    "promotion_blockers": [
                        "taxonomy/coverage metadata is still split between the generic input-validation assignment and the more specific safe-fallback-handler-setter-missing-address-guard class",
                        "evidence is still limited to dedicated fixture smoke rather than broader clean-corpus or real-target precision validation",
                    ],
                },
            )
            _write_json(
                root / "reports" / "klbq_006_precision_evidence_2026-05-05.json",
                {
                    "limitation_id": "KLBQ-006",
                    "status": "moved_forward_not_verified",
                    "summary": {
                        "added_synthetic_precision_corpus": True,
                        "bounded_synthetic_precision_passes": True,
                        "real_target_source_replay_passes": False,
                        "taxonomy_reconciled": False,
                    },
                    "missing_or_insufficient_inputs": [
                        "Exact reNFT source checkout for Solodit #30522 is not local.",
                        "No real-source file/line anchors for the vulnerable guard path are recorded.",
                        "No ground-truthed real-target clean corpus has been run for this detector family.",
                    ],
                    "next_commands": [
                        "rg -n \"setFallbackHandler|fallbackHandler|checkTransaction|check_transaction|f08a0323\" <renft-source-root>",
                    ],
                },
            )
            _write_json(
                root / "reports" / "klbq_006_real_source_anchors_2026-05-05.json",
                {
                    "finding_id": "30522",
                    "classification": {
                        "exact_renft_source_root": "absent",
                        "real_source_anchors": "absent",
                    },
                },
            )
            _write_json(
                root / "reports" / "g1_source_root_locator_2026-05-05.json",
                {
                    "findings": [
                        {
                            "finding_id": "38333",
                            "title": "USDs stability can be compromised",
                            "source_root_status": "cluster_inferred_candidate_no_local_root",
                            "confirmation_level": "cluster_inferred_only",
                            "local_source_checkout_found": False,
                            "local_source_root": None,
                            "candidate_repo": "https://github.com/the-standard/smart-vault",
                            "candidate_commit": "c6837d4a296fe8a6e4bb5e0280a66d6eb8a40361",
                            "candidate_source_root": "contracts",
                            "confidence": "low",
                            "blockers": ["Exact #38333 row has no local GitHub URL or commit."],
                        },
                        {
                            "finding_id": "36418",
                            "title": "Decreasing position size via leverage update",
                            "source_root_status": "unresolved_local_absent",
                            "confirmation_level": "unresolved_no_candidate",
                            "local_source_checkout_found": False,
                            "local_source_root": None,
                            "candidate_repo": None,
                            "candidate_commit": None,
                            "candidate_source_root": None,
                            "confidence": "low",
                            "blockers": ["No local GitHub URL, commit, tag, or checkout found."],
                        },
                        {
                            "finding_id": "33463",
                            "title": "Missing enough exogenous collateral check",
                            "source_root_status": "cluster_inferred_candidate_no_local_root",
                            "confirmation_level": "cluster_inferred_only",
                            "local_source_checkout_found": False,
                            "local_source_root": None,
                            "candidate_repo": "https://github.com/code-423n4/2024-04-dyad",
                            "candidate_commit": "cd48c684a58158de444b24854ffd8f07d046c31b",
                            "candidate_source_root": "src",
                            "confidence": "low",
                            "blockers": ["Exact #33463 row has no local GitHub source URL or commit."],
                        },
                    ],
                },
            )
            _write_json(
                root / "reports" / "scanner_wiring_burndown_queue_2026-05-05.json",
                {
                    "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                    "actionable_row_count": 4,
                    "top_action_count": 2,
                    "top_action_lane_counts": {"wire_backend_executor": 1, "add_fixture_or_proof": 1},
                    "lane_counts": {"wire_backend_executor": 1, "add_fixture_or_proof": 3},
                    "status_counts": {"backend_executor_missing_or_tbd": 1, "generated_no_fixture": 3},
                    "blocker_counts": {"clean_or_negative_fixture_missing": 3},
                    "actions": [
                        {
                            "rank": 1,
                            "lane": "wire_backend_executor",
                            "row_id": "go-backend-executor",
                            "scanner_id": "go-backend-executor",
                            "backend": "go",
                            "wiring_status": "backend_executor_missing_or_tbd",
                            "proof_status": "no_known_executor_signal_found",
                            "suggested_next_action": "add or document the go backend executor route before claiming scanner coverage",
                            "blockers": ["go_executor_missing_or_unknown"],
                            "suggested_commands": [
                                {
                                    "command": "rg -n go tools Makefile detectors",
                                    "reason": "Check whether a backend runner already exists under another name.",
                                }
                            ],
                            "claim_guard": "Do not claim detector readiness without proof.",
                        },
                        {
                            "rank": 2,
                            "lane": "add_fixture_or_proof",
                            "row_id": "inflation_attack_on_zero_total_stake_staking_v2",
                            "scanner_id": "inflation_attack_on_zero_total_stake_staking_v2",
                            "backend": "move",
                            "wiring_status": "generated_no_fixture",
                            "proof_status": "source_shape_only",
                            "suggested_next_action": "materialize vulnerable/clean fixtures before counting as wired",
                            "blockers": ["positive_or_vulnerable_fixture_missing", "clean_or_negative_fixture_missing"],
                            "source_paths": ["detectors/move_wave2/inflation_attack_on_zero_total_stake_staking_v2.py"],
                            "suggested_commands": [
                                {
                                    "command": "sed -n '1,220p' detectors/move_wave2/inflation_attack_on_zero_total_stake_staking_v2.py",
                                    "reason": "Inspect detector source.",
                                }
                            ],
                            "claim_guard": "Do not claim detector readiness without proof.",
                        },
                    ],
                },
            )
            _write_json(
                root / "reports" / "commit_mining_source_disposition_2026-05-05.json",
                {
                    "schema": "auditooor.commit_mining_source_disposition.v1",
                    "summary": {
                        "queued_actionable_count": 0,
                        "completed_next_step_count": 4,
                        "source_packets_emitted": 4,
                        "source_packets_seen": 4,
                        "blocked_no_op_count": 0,
                        "action_counts": {
                            "broad_import_triage": 1,
                            "narrow_consensus_patch_review": 2,
                            "prover_service_review": 1,
                        },
                    },
                    "disposition_queue": [
                        {
                            "queue_index": 1,
                            "status": "completed_next_step_emitted",
                            "source_row_id": "BA-HIST-01",
                            "task_id": "scan-task-BA-HIST-01",
                            "target": "Base Azul",
                            "repo_identity": "github.com/base/base",
                            "action_type": "broad_import_triage",
                            "priority": "low",
                            "packet_status": "source_review_packet_emitted",
                            "next_action": "Next-step packet already emitted; do not re-queue unless this source-review slice is reopened.",
                            "proof_boundary": "source-review routing only",
                            "completed_next_step_evidence": [
                                {
                                    "evidence_path": "reports/commit_mining_next_step_packet_2026-05-05.json",
                                    "source_ref": "abc123:reports/commit_mining_next_step_packet_2026-05-05.json",
                                }
                            ],
                        }
                    ],
                },
            )
            (root / "docs" / "KLBQ_006_PRECISION_EVIDENCE_2026-05-05.md").write_text(
                "synthetic precision evidence\n",
                encoding="utf-8",
            )
            (root / "docs" / "KLBQ_006_REAL_SOURCE_ANCHORS_2026-05-05.md").write_text(
                "exact real-source replay still blocked\n",
                encoding="utf-8",
            )

            report = MOD.build_status_report(
                root,
                root / "reports" / "known_limitations_burndown_queue_2026-05-05.json",
                root / "reports" / "known_limitations_dispatch_2026-05-05.json",
            )

        self.assertEqual(report["integration_status"], "open_rows_present")
        self.assertFalse(report["closure_claim"]["allowed"])
        self.assertEqual(report["summary"]["focus_row_count"], 2)
        self.assertEqual(report["summary"]["open_focus_row_count"], 2)
        self.assertEqual(report["summary"]["related_harness_memory_row_count"], 1)
        self.assertEqual(report["summary"]["scanner_burndown_actionable_row_count"], 4)
        self.assertEqual(
            report["summary"]["scanner_burndown_top_action_lane_counts"],
            {"wire_backend_executor": 1, "add_fixture_or_proof": 1},
        )
        self.assertEqual(report["scanner_burndown_snapshot"]["status"], "open_actions_present")
        self.assertEqual(report["scanner_burndown_snapshot"]["top_actions"][0]["row_id"], "go-backend-executor")
        self.assertEqual(
            report["scanner_burndown_snapshot"]["top_actions"][1]["suggested_commands"][0]["command"],
            "sed -n '1,220p' detectors/move_wave2/inflation_attack_on_zero_total_stake_staking_v2.py",
        )
        self.assertEqual(report["summary"]["scanner_worker_slot_cap"], 11)
        self.assertEqual(report["summary"]["scanner_worker_slot_count"], 2)
        worker_slot = report["scanner_burndown_snapshot"]["next_worker_slots"][0]
        self.assertEqual(worker_slot["task_kind"], "end_to_end_scanner_burndown_closure")
        self.assertEqual(worker_slot["row_id"], "go-backend-executor")
        self.assertIn("workers implement; coordinator reviews", worker_slot["coordination_rules"][0])
        self.assertIn(
            "Prefer end-to-end implementation workers",
            report["execution_priority_policy"]["agent_usage"],
        )
        self.assertEqual(report["summary"]["commit_mining_queued_actionable_count"], 0)
        self.assertEqual(report["summary"]["commit_mining_completed_next_step_count"], 4)
        self.assertEqual(report["summary"]["commit_mining_source_packets_emitted"], 4)
        self.assertEqual(
            report["commit_mining_source_disposition_snapshot"]["status"],
            "completed_next_steps_only",
        )
        self.assertEqual(
            report["commit_mining_source_disposition_snapshot"]["top_dispositions"][0]["source_row_id"],
            "BA-HIST-01",
        )
        self.assertIn(
            "commit-mining disposition rows are source-review routing/accounting only",
            " ".join(report["strict_caveats"]).lower(),
        )
        self.assertGreaterEqual(report["summary"]["open_rows_with_actionable_now_commands"], 1)
        self.assertEqual({row["id"] for row in report["open_focus_rows"]}, {"KLBQ-006", "KLBQ-007"})
        klbq_006_row = next(row for row in report["open_focus_rows"] if row["id"] == "KLBQ-006")
        self.assertIn("Provide the exact local reNFT source root", klbq_006_row["next_action"])
        related = report["related_harness_memory_rows"][0]
        self.assertEqual(related["id"], "KLBQ-002")
        self.assertEqual(related["dispatch_lane"], "blocked_needs_source")
        self.assertEqual(related["current_status"], "partially_implemented_v0_source_roots_actionable_blocked")
        self.assertIn("Do not dispatch source replay", related["next_action"])
        actionability = related["agent_actionability"]
        self.assertEqual(actionability["decision"], "blocked_exact_source_roots_missing")
        self.assertFalse(actionability["can_dispatch_local_replay"])
        self.assertFalse(actionability["can_dispatch_detector_design"])
        self.assertTrue(actionability["can_dispatch_source_acquisition"])
        self.assertEqual(actionability["missing_finding_ids"], ["38333", "36418", "33463"])
        self.assertEqual(actionability["source_root_rows"][0]["candidate_source_root"], "contracts")
        self.assertEqual(actionability["source_root_rows"][2]["candidate_repo"], "https://github.com/code-423n4/2024-04-dyad")
        self.assertIn("docs/PROJECT_SOURCE_ROOTS.md", actionability["read_first"])
        self.assertEqual(report["summary"]["agent_actionability_row_count"], 1)
        self.assertEqual(report["agent_actionability_rows"][0]["decision"], "blocked_exact_source_roots_missing")
        blocked_lookup = {row["id"]: row for row in report["blocked_or_missing_rows"]}
        self.assertTrue(any("Exact reNFT source root" in issue for issue in blocked_lookup["KLBQ-006"]["issues"]))
        self.assertTrue(any("event schema exists" in issue for issue in blocked_lookup["KLBQ-007"]["issues"]))
        self.assertTrue(any("#38333" in issue for issue in blocked_lookup["KLBQ-002"]["issues"]))

    def test_klbq_002_actionability_refresh_does_not_claim_replay_closure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "reports").mkdir()
            (root / "tools" / "tests").mkdir(parents=True)
            (root / "tools" / "source-root-blocker-emitter.py").write_text(
                "\n".join(
                    [
                        "ACTIONABILITY_SCHEMA = 'auditooor.source_root_acquisition_plan.v0'",
                        "'source_root_acquisition_plan'",
                        "'blocked_pending_exact_source_acquisition'",
                        "'local_verification_commands'",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "tools" / "tests" / "test_source_root_blocker_emitter.py").write_text(
                "\n".join(
                    [
                        "'candidate_confirmation_required'",
                        "'exact_reviewed_source_report_or_metadata_for_this_solodit_row'",
                        "'make project-source-root-readiness WS=<workspace> JSON=1'",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            _write_json(
                root / "reports" / "known_limitations_burndown_queue_2026-05-05.json",
                {
                    "schema": "auditooor.known_limitations_burndown_queue.v1",
                    "date": "2026-05-05",
                    "rows": [
                        {
                            "id": "KLBQ-002",
                            "owner_lane": "source replay / memory recall",
                            "remaining_blockers": ["local source roots are absent"],
                            "source_refs": ["reports/g1_source_root_locator_2026-05-05.json"],
                        }
                    ],
                },
            )
            _write_json(
                root / "reports" / "known_limitations_dispatch_2026-05-05.json",
                {
                    "schema": "auditooor.known_limitations_dispatch.v1",
                    "date": "2026-05-05",
                    "work_items": [
                        {
                            "limitation_id": "KLBQ-002",
                            "current_status": "partially_implemented_v0_pass_with_real_blockers_remaining",
                            "blocker": "local source roots are absent",
                            "dispatch_lane": "blocked_needs_source",
                            "next_action": "Acquire exact local source roots.",
                            "evidence_paths": ["reports/g1_source_root_locator_2026-05-05.json"],
                            "missing_evidence_paths": [],
                            "dispatch_ready": False,
                            "owner_lane": "source replay / memory recall",
                        }
                    ],
                },
            )
            _write_json(
                root / "reports" / "g1_source_root_locator_2026-05-06.json",
                {
                    "schema": "auditooor.g1_source_root_locator.v1",
                    "findings": [
                        {
                            "finding_id": "38333",
                            "title": "Standard Smart Vault",
                            "source_root_status": "cluster_inferred_candidate_only",
                            "candidate_source_root": "contracts",
                        },
                        {
                            "finding_id": "36418",
                            "title": "GainsNetwork May",
                            "source_root_status": "blocked_source_absent",
                        },
                        {
                            "finding_id": "33463",
                            "title": "DYAD",
                            "source_root_status": "cluster_inferred_candidate_only",
                            "candidate_repo": "https://github.com/code-423n4/2024-04-dyad",
                        },
                    ],
                },
            )
            _write_json(
                root / "reports" / "solodit_source_replay_readiness_2026-05-06.json",
                {
                    "schema": "auditooor.solodit_source_replay_readiness.v1",
                    "rows": [
                        {
                            "finding_id": "38333",
                            "readiness_status": "blocked_source_absent",
                            "source_replay_blockers": ["exact reviewed source is absent"],
                        }
                    ],
                },
            )
            _write_json(
                root / "reports" / "klbq_002_source_root_actionability_2026-05-06.json",
                {
                    "schema": "auditooor.source_root_acquisition_plan.v0",
                    "row_count": 3,
                    "proof_boundary": "source acquisition only; no replay or promotion claim",
                    "promotion_claim_allowed": False,
                },
            )
            _write_json(
                root / "reports" / "klbq_002_source_root_actionability_2026-05-07.json",
                {
                    "schema": "auditooor.source_root_acquisition_plan.v99",
                    "row_count": 999,
                    "proof_boundary": "malformed newer report should be ignored",
                    "promotion_claim_allowed": True,
                },
            )

            report = MOD.build_status_report(
                root,
                root / "reports" / "known_limitations_burndown_queue_2026-05-05.json",
                root / "reports" / "known_limitations_dispatch_2026-05-05.json",
            )

        related = report["related_harness_memory_rows"][0]
        self.assertEqual(related["id"], "KLBQ-002")
        self.assertEqual(related["current_status"], "partially_implemented_v0_actionability_closed_source_absent")
        self.assertTrue(related["open"])
        self.assertFalse(report["closure_claim"]["allowed"])
        self.assertIn("source_root_acquisition_plan", related["next_action"])
        self.assertTrue(any("Exact local source roots" in blocker for blocker in related["blockers"]))
        self.assertTrue(any("test_source_root_blocker_emitter" in command for command in related["verification_commands"]))
        self.assertEqual(
            related["source_root_acquisition_report"]["path"],
            "reports/klbq_002_source_root_actionability_2026-05-06.json",
        )
        self.assertEqual(related["source_root_acquisition_report"]["row_count"], 3)
        self.assertFalse(related["source_root_acquisition_report"]["promotion_claim_allowed"])
        self.assertIn(
            "reports/klbq_002_source_root_actionability_2026-05-06.json",
            related["evidence_paths"],
        )
        self.assertIn("reports/g1_source_root_locator_2026-05-06.json", related["evidence_paths"])
        self.assertIn(
            "python3 -m json.tool reports/g1_source_root_locator_2026-05-06.json",
            related["verification_commands"],
        )
        self.assertTrue(
            any(
                command
                == "make source-root-blocker-emitter INPUT=reports/g1_source_root_locator_2026-05-06.json OUT=/tmp/klbq002_source_root_blockers.json"
                for command in related["verification_commands"]
            )
        )
        self.assertTrue(
            any(
                "python3 -m json.tool reports/klbq_002_source_root_actionability_2026-05-06.json" == command
                for command in related["verification_commands"]
            )
        )

    def test_missing_focus_rows_fails_closed_instead_of_claiming_closure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "reports").mkdir()
            _write_json(
                root / "reports" / "known_limitations_burndown_queue_2026-05-05.json",
                {
                    "schema": "auditooor.known_limitations_burndown_queue.v1",
                    "rows": [
                        {
                            "id": "KLBQ-001",
                            "owner_lane": "source replay",
                        }
                    ],
                },
            )
            _write_json(
                root / "reports" / "known_limitations_dispatch_2026-05-05.json",
                {
                    "schema": "auditooor.known_limitations_dispatch.v1",
                    "work_items": [
                        {
                            "limitation_id": "KLBQ-001",
                            "dispatch_lane": "commit_mining",
                            "current_status": "partially_implemented_v0_partial_pass",
                        }
                    ],
                },
            )

            report = MOD.build_status_report(
                root,
                root / "reports" / "known_limitations_burndown_queue_2026-05-05.json",
                root / "reports" / "known_limitations_dispatch_2026-05-05.json",
            )

        self.assertEqual(report["integration_status"], "blocked_missing_inputs")
        self.assertFalse(report["closure_claim"]["allowed"])
        self.assertEqual(report["summary"]["focus_row_count"], 0)
        self.assertTrue(
            any("no harness_execution or memory_handoff rows were found" in item for item in report["missing_inputs"])
        )

    def test_cli_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "reports").mkdir()
            _write_json(
                root / "reports" / "known_limitations_burndown_queue_2026-05-05.json",
                {
                    "schema": "auditooor.known_limitations_burndown_queue.v1",
                    "rows": [
                        {
                            "id": "KLBQ-007",
                            "owner_lane": "memory recall / harness precision",
                            "source_refs": ["reports/harness_failures.jsonl"],
                        }
                    ],
                },
            )
            _write_json(
                root / "reports" / "known_limitations_dispatch_2026-05-05.json",
                {
                    "schema": "auditooor.known_limitations_dispatch.v1",
                    "work_items": [
                        {
                            "limitation_id": "KLBQ-007",
                            "dispatch_lane": "memory_handoff",
                            "current_status": "open_blocked",
                            "blocker": "Awaiting: event schema exists",
                            "dispatch_ready": True,
                            "expected_loop_cost": 2,
                        }
                    ],
                },
            )
            (root / "reports" / "harness_failures.jsonl").write_text("", encoding="utf-8")
            json_out = root / "out" / "packet.json"
            doc_out = root / "out" / "packet.md"

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--burndown",
                    str(root / "reports" / "known_limitations_burndown_queue_2026-05-05.json"),
                    "--dispatch",
                    str(root / "reports" / "known_limitations_dispatch_2026-05-05.json"),
                    "--output",
                    str(json_out),
                    "--docs",
                    str(doc_out),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")
            payload = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], MOD.SCHEMA)
            self.assertEqual(payload["open_focus_rows"], [])
            self.assertEqual(payload["verified_focus_rows"][0]["id"], "KLBQ-007")
            doc = doc_out.read_text(encoding="utf-8")
            self.assertIn("Known Limitations Harness/Memory Status 2026-05-05", doc)
            self.assertIn("Open Focus Rows", doc)
            self.assertIn("No open focus rows present", doc)
            self.assertIn("Closure claim allowed", doc)
            self.assertIn("Executable Next Actions", doc)
            self.assertIn("Next Action", doc)


if __name__ == "__main__":
    unittest.main()
