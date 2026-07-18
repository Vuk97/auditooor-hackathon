#!/usr/bin/env python3
"""Offline tests for tools/memory-retrieval-bootstrap.py."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "memory-retrieval-bootstrap.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("memory_retrieval_bootstrap", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def init_git(path: Path, branch: str) -> None:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-b", branch], cwd=path, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def commit_all(path: Path, message: str) -> None:
    subprocess.run(["git", "add", "."], cwd=path, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Auditooor Test",
            "-c",
            "user.email=auditooor@example.invalid",
            "commit",
            "-m",
            message,
        ],
        cwd=path,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def make_memory_root(root: Path, *, stale_shared_index: bool = False, missing_brief: bool = False) -> tuple[Path, Path]:
    memory = root / "memory-root"
    vault = root / "obsidian-vault"
    init_git(memory, "fresh-memory-root")
    reports = memory / "reports"
    reports.mkdir(parents=True)
    (memory / "tools").mkdir()
    write_text(memory / "Makefile", "vault-status:\nshared-memory-index:\nmemory-brief:\n")
    write_text(memory / "tools" / "model-takeover-handoff.py", "#!/usr/bin/env python3\n")
    write_json(
        reports / "shared_memory_index_2026-05-05.json",
        {
            "schema": "auditooor.shared_memory_index.v1",
            "generated_date": "2026-05-04" if stale_shared_index else "2026-05-05",
            "memory_objects": [],
        },
    )
    if not missing_brief:
        write_json(
            reports / "memory_brief_2026-05-05.json",
            {"schema": "auditooor.memory_brief.v1", "generated_date": "2026-05-05", "briefs": []},
        )
    write_json(
        reports / "scanner_worker_active_claims_2026-05-05.json",
        {
            "schema": "auditooor.scanner_worker_active_claims.v1",
            "updated_at": "2026-05-06T06:21:49Z",
            "active_claims": [
                {
                    "agent_id": "agent-1",
                    "row_id": "preapproval_signature_bypass_meta",
                    "status": "active",
                },
                {
                    "agent_id": "agent-2",
                    "row_id": "position_nft_zero_id_returns_unassigned_slot",
                    "status": "completed",
                },
            ],
            "summary": {"active": 1, "completed": 1},
        },
    )
    write_json(
        reports / "obsidian_memory_entrypoints_2026-05-05.json",
        {
            "schema": "auditooor.obsidian_memory_entrypoints.v1",
            "generated_date": "2026-05-05",
            "memory_root": str(memory),
            "primary_vault": {"path": str(vault), "exists": True},
            "operational_snapshot": {
                "branch": "continuation-plan",
                "current_state": {
                    "goal_status": ["Goal status: `active_continuous_loop`"],
                    "terminal_completion_allowed": False,
                },
                "active_blockers": {"blocked_backlog": ["KLBQ-002", "KLBQ-004"]},
                "next_loop": {
                    "top_ready_now": ["KLBQ-001", "KLBQ-006", "KLBQ-008"],
                    "scheduled_loops": [
                        {
                            "loop_index": 1,
                            "items": ["KLBQ-001", "KLBQ-006", "KLBQ-008"],
                            "lanes": ["harness_execution", "memory_handoff"],
                        }
                    ],
                    "top_gap_candidates": [{"gap_id": "G1-001", "title": "taxonomy"}],
                },
                "pr_605_handoff": {
                    "branch": "continuation-plan",
                    "commands": [
                        "make vault-status",
                        "make shared-memory-index",
                        "make memory-brief",
                        "gh pr list --limit 20",
                        "git fetch origin main",
                    ],
                },
            },
        },
    )
    write_json(
        reports / "known_limitations_harness_memory_status_2026-05-05.json",
        {
            "schema": "auditooor.known_limitations_harness_memory_status.v1",
            "generated_at": "2026-05-05T20:35:03+00:00",
            "worktree": str(memory),
            "branch": "continuation-plan",
            "execution_priority_policy": {
                "priority_order": ["MEMORY", "HARNESS", "KNOWN LIMITATION BURNDOWN"],
                "agent_usage": "Prefer end-to-end implementation workers; coordinator reviews and integrates.",
                "batch_boundary_rule": "Refresh shared memory after a clean worker batch.",
            },
            "scanner_burndown_snapshot": {
                "status": "open_actions_present",
                "next_worker_slots": [
                    {
                        "slot_id": "scanner-slot-1",
                        "row_id": "fixture-gap-row",
                        "lane": "add_fixture_or_proof",
                        "rank": 1,
                        "model_hint": "gpt-5.5/high",
                        "owned_paths": [
                            "detectors/fixtures/fixture-gap-row",
                            "detectors/wave17/fixture_gap_row.py",
                            "tools/tests/test_fixture_gap_row.py",
                        ],
                        "acceptance_criteria": [
                            "positive fixture or runtime proof produces at least one expected detector hit",
                            "clean fixture produces zero hits",
                        ],
                    }
                ],
            },
            "verified_focus_rows": [
                {
                    "id": "KLBQ-007",
                    "current_status": "implemented_verified_local_evidence",
                    "dispatch_lane": "memory_handoff",
                    "next_action": "Add harness-failure event rows.",
                    "verification_commands": ["python3 -m unittest tools.tests.test_harness_failure_memory -v"],
                    "evidence_paths": ["tools/harness-failure-memory.py"],
                    "open": False,
                }
            ],
            "open_focus_rows": [
                {
                    "id": "KLBQ-006",
                    "current_status": "partially_implemented_v0_partial_pass",
                    "dispatch_lane": "harness_execution",
                    "next_action": "Run exact reNFT source-root checks.",
                    "next_action_status": "actionable_now_with_blocked_followups",
                    "actionable_now_commands": ["python3 tools/known-limitations-harness-memory-status.py --output reports/known_limitations_harness_memory_status_2026-05-05.json"],
                    "blocked_command_templates": [
                        {
                            "command": "forge test --root <renft-source-root>",
                            "missing_inputs": ["<renft-source-root>"],
                            "unblock_criteria": ["Exact reNFT source checkout is local."],
                        }
                    ],
                    "blockers": ["Exact source root absent."],
                    "verification_commands": ["python3 -m json.tool reports/klbq_006_precision_evidence_2026-05-05.json"],
                    "open": True,
                }
            ],
            "related_harness_memory_rows": [
                {
                    "id": "KLBQ-002",
                    "current_status": "partially_implemented_v0_pass_with_real_blockers_remaining",
                    "dispatch_lane": "blocked_needs_source",
                    "next_action": "Acquire exact source roots.",
                    "blockers": ["Solodit rows lack exact local source roots."],
                    "open": True,
                },
                {
                    "id": "KLBQ-004",
                    "current_status": "implemented_verified_local_evidence",
                    "dispatch_lane": "docs_state",
                    "next_action": "Preserve exact local harness commands.",
                    "blockers": [],
                    "open": False,
                },
                {
                    "id": "KLBQ-009",
                    "current_status": "implemented_verified",
                    "dispatch_lane": "docs_state",
                    "next_action": "Preserve unknown-reason contract.",
                    "verification_commands": ["python3 -m unittest tools.tests.test_outcome_reweight -v"],
                    "open": False,
                },
            ],
            "commit_mining_source_disposition_snapshot": {
                "status": "completed_next_steps_only",
                "path": "reports/commit_mining_source_disposition_2026-05-05.json",
                "queued_actionable_count": 0,
                "completed_next_step_count": 4,
                "source_packets_emitted": 4,
                "source_packets_seen": 4,
                "blocked_no_op_count": 0,
                "top_dispositions": [
                    {
                        "status": "completed_next_step_emitted",
                        "source_row_id": "BA-HIST-01",
                        "task_id": "scan-task-BA-HIST-01",
                        "target": "Base Azul",
                        "action_type": "broad_import_triage",
                        "packet_status": "source_review_packet_emitted",
                        "next_action": "Next-step packet already emitted; do not re-queue unless this source-review slice is reopened.",
                        "evidence_path": "reports/commit_mining_next_step_packet_2026-05-05.json",
                    }
                ],
                "strict_caveat": "Commit-mining disposition rows are source-review routing/accounting only.",
            },
        },
    )
    write_json(
        reports / "model_takeover_readiness_2026-05-05.json",
        {
            "schema": "auditooor.model_takeover_readiness.v1",
            "generated_at": "2026-05-05T20:19:04+00:00",
            "root": str(memory),
            "categories": {
                "context": {"status": "READY"},
                "limits": {"status": "WARN"},
                "harness": {"status": "WARN"},
            },
        },
    )
    for name in (
        "model_takeover_provider_handoff_2026-05-05.json",
        "goal_loop_status_2026-05-05.json",
        "known_limitations_dispatch_2026-05-05.json",
        "next_50_loops_2026-05-05.json",
    ):
        write_json(reports / name, {"schema": name, "generated_date": "2026-05-05"})

    write_text(
        vault / "DASHBOARD.md",
        '---\ngenerated: "2026-05-04T20:21Z"\nlast_sync: "2026-05-04T20:20Z"\n---\n# Dashboard\n',
    )
    for rel in ("INDEX_active.md", "NEXT_LOOP.md", "dispatch/next_dispatch_manifest.preview.json", "knowledge-gaps/INDEX.md", "harness-failures/INDEX.md"):
        if rel.endswith(".json"):
            write_json(vault / rel, {"dispatchable": False})
        else:
            write_text(vault / rel, "# note\n")
    return memory, vault


class MemoryRetrievalBootstrapTests(unittest.TestCase):
    def test_git_state_ignores_only_self_generated_bootstrap_outputs(self) -> None:
        mod = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "checkout"
            init_git(root, "handoff")
            write_json(root / "reports" / "memory_retrieval_bootstrap_2026-05-05.json", {"old": True})
            write_text(root / "agent_briefs" / "AGENT_BOOTSTRAP_QUERY_2026-05-05.md", "old\n")
            write_text(root / "notes.md", "old\n")
            commit_all(root, "baseline")

            write_json(root / "reports" / "memory_retrieval_bootstrap_2026-05-05.json", {"old": False})
            write_text(root / "agent_briefs" / "AGENT_BOOTSTRAP_QUERY_2026-05-05.md", "new\n")
            state = mod.git_state(
                root,
                ignored_dirty_paths={
                    "reports/memory_retrieval_bootstrap_2026-05-05.json",
                    "agent_briefs/AGENT_BOOTSTRAP_QUERY_2026-05-05.md",
                },
            )

            self.assertFalse(state["dirty"])
            self.assertEqual(state["dirty_path_count"], 0)
            self.assertEqual(state["raw_dirty_path_count"], 2)
            self.assertEqual(state["ignored_self_generated_dirty_path_count"], 2)

            write_text(root / "notes.md", "new\n")
            state = mod.git_state(
                root,
                ignored_dirty_paths={
                    "reports/memory_retrieval_bootstrap_2026-05-05.json",
                    "agent_briefs/AGENT_BOOTSTRAP_QUERY_2026-05-05.md",
                },
            )

            self.assertTrue(state["dirty"])
            self.assertEqual(state["dirty_path_count"], 1)
            self.assertEqual(state["dirty_path_sample"], [" M notes.md"])

    def test_build_packet_extracts_priority_klbq_and_active_boundaries(self) -> None:
        mod = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "checkout"
            root.mkdir()
            memory, vault = make_memory_root(Path(tmp))

            packet = mod.build_packet(root, memory_root=memory, vault_root=vault, generated_at="2026-05-05T00:00:00+00:00")

        self.assertEqual(packet["schema"], "auditooor.memory_retrieval_bootstrap.v1")
        self.assertEqual(packet["memory_source"]["branch"], "fresh-memory-root")
        self.assertEqual(packet["current_priority"]["current_branch_from_memory"], "fresh-memory-root")
        self.assertEqual(packet["current_priority"]["branch_from_obsidian_report"], "continuation-plan")
        self.assertEqual(packet["current_priority"]["branch_from_klbq_status"], "continuation-plan")
        self.assertEqual(packet["current_priority"]["priority_order"], ["MEMORY", "HARNESS", "KNOWN LIMITATION BURNDOWN"])
        self.assertIn(
            "Prefer end-to-end implementation workers",
            packet["current_priority"]["execution_priority_policy"]["agent_usage"],
        )
        self.assertEqual(packet["current_priority"]["scanner_worker_slot_count"], 1)
        self.assertEqual(packet["current_priority"]["scanner_worker_slots"][0]["row_id"], "fixture-gap-row")
        self.assertEqual(packet["current_priority"]["active_scanner_claims"]["active"], 1)
        self.assertEqual(packet["current_priority"]["active_scanner_claims"]["completed"], 1)
        self.assertEqual(
            packet["current_priority"]["active_scanner_claims"]["active_rows"][0]["row_id"],
            "preapproval_signature_bypass_meta",
        )
        self.assertEqual(packet["current_priority"]["top_ready_now"], ["KLBQ-001", "KLBQ-006", "KLBQ-008"])
        self.assertEqual(packet["current_priority"]["blocked_backlog"], ["KLBQ-002"])
        self.assertEqual(packet["current_priority"]["actionable_open_rows"][0]["id"], "KLBQ-006")
        self.assertEqual(packet["commit_mining_source_disposition"]["status"], "completed_next_steps_only")
        self.assertEqual(packet["commit_mining_source_disposition"]["queued_actionable_count"], 0)
        self.assertEqual(packet["commit_mining_source_disposition"]["completed_next_step_count"], 4)
        self.assertEqual(packet["commit_mining_source_disposition"]["source_packets_emitted"], 4)
        self.assertEqual(
            packet["commit_mining_source_disposition"]["top_dispositions"][0]["source_row_id"],
            "BA-HIST-01",
        )
        closed_ids = {row["id"] for row in packet["closed_klbq_states"]}
        self.assertIn("KLBQ-004", closed_ids)
        self.assertIn("KLBQ-007", closed_ids)
        self.assertIn("KLBQ-009", closed_ids)
        open_ids = {row["id"] for row in packet["open_klbq_blocks"]}
        self.assertTrue({"KLBQ-002", "KLBQ-006"}.issubset(open_ids))
        self.assertNotIn("KLBQ-004", open_ids)
        klbq_006 = [row for row in packet["open_klbq_blocks"] if row["id"] == "KLBQ-006"][0]
        self.assertEqual(klbq_006["next_action_status"], "actionable_now_with_blocked_followups")
        self.assertEqual(klbq_006["actionable_now_commands"][0], "python3 tools/known-limitations-harness-memory-status.py --output reports/known_limitations_harness_memory_status_2026-05-05.json")
        self.assertEqual(klbq_006["blocked_command_templates"][0]["missing_inputs"], ["<renft-source-root>"])
        active_guards = [row for row in packet["stale_source_guards"] if row["scope"] == "active_integration_boundary"]
        self.assertEqual({row["evidence"]["id"] for row in active_guards}, {"KLBQ-002"})
        self.assertFalse(any(row["blocking"] for row in active_guards))
        vault_guards = [row for row in packet["stale_source_guards"] if row["scope"] == "obsidian_vault_freshness"]
        self.assertEqual([row["status"] for row in vault_guards], ["ADVISORY"])
        self.assertFalse(any(row["blocking"] for row in vault_guards))
        self.assertEqual(packet["freshness_summary"]["blocking_count"], 0)
        self.assertTrue(any(row["scope"] == "obsidian_branch_mismatch" for row in packet["stale_source_guards"]))
        self.assertTrue(any(row["scope"] == "klbq_branch_mismatch" for row in packet["stale_source_guards"]))
        commands = [row["command"] for row in packet["exact_next_commands"]]
        self.assertTrue(any("model-takeover-handoff.py" in command for command in commands))
        self.assertTrue(any("known-limitations-harness-memory-status.py" in command for command in commands))
        self.assertTrue(any(command.startswith("make -C ") and command.endswith("memory-brief") for command in commands))
        self.assertFalse(any(command.startswith("gh ") or "git fetch" in command for command in commands))
        self.assertTrue(all(row["lane"] in {"memory", "klbq"} for row in packet["exact_next_commands"]))
        self.assertIn("Load this packet first", packet["expected_token_saving_mechanism"])

    def test_scanner_worker_slots_mark_claimed_dirty_rows(self) -> None:
        mod = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "checkout"
            init_git(root, "scanner-work")
            write_text(root / "README.md", "baseline\n")
            write_text(root / "detectors" / "fixtures" / "fixture-gap-row" / "positive.sol", "// old\n")
            commit_all(root, "baseline")
            write_text(root / "detectors" / "fixtures" / "fixture-gap-row" / "positive.sol", "// dirty\n")
            memory, vault = make_memory_root(Path(tmp))

            packet = mod.build_packet(root, memory_root=memory, vault_root=vault)

        self.assertEqual(packet["current_priority"]["scanner_worker_slot_count"], 0)
        self.assertEqual(packet["current_priority"]["skipped_scanner_worker_slot_count"], 1)
        slot = packet["current_priority"]["skipped_scanner_worker_slots"][0]
        self.assertEqual(slot["row_id"], "fixture-gap-row")
        self.assertEqual(slot["local_coordination_status"], "claimed_dirty_worktree")
        self.assertEqual(
            slot["matching_dirty_paths"],
            ["detectors/fixtures/fixture-gap-row/positive.sol"],
        )
        self.assertIn("do not redispatch", slot["coordination_note"])

    def test_scanner_worker_slots_mark_existing_local_evidence_refresh_needed(self) -> None:
        mod = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "checkout"
            root.mkdir()
            write_json(root / "detectors" / "fixtures" / "fixture-gap-row" / "fixture-gap-row_smoke.json", {"result": "pass"})
            write_text(root / "tools" / "tests" / "test_fixture_gap_row.py", "# proof test\n")
            memory, vault = make_memory_root(Path(tmp))

            packet = mod.build_packet(root, memory_root=memory, vault_root=vault)

        self.assertEqual(packet["current_priority"]["scanner_worker_slot_count"], 0)
        self.assertEqual(packet["current_priority"]["skipped_scanner_worker_slot_count"], 1)
        slot = packet["current_priority"]["skipped_scanner_worker_slots"][0]
        self.assertEqual(slot["local_coordination_status"], "local_evidence_present_refresh_needed")
        self.assertIn("detectors/fixtures/fixture-gap-row/fixture-gap-row_smoke.json", slot["local_evidence_paths"])
        self.assertIn("tools/tests/test_fixture_gap_row.py", slot["local_evidence_paths"])

    def test_scanner_selector_summary_and_skipped_slots_are_preserved(self) -> None:
        mod = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "checkout"
            root.mkdir()
            memory, vault = make_memory_root(Path(tmp))
            status_path = memory / "reports" / "known_limitations_harness_memory_status_2026-05-05.json"
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["scanner_burndown_snapshot"]["skipped_worker_slot_count"] = 7
            status["scanner_burndown_snapshot"]["worker_slot_coordination_counts"] = {
                "already_committed": 7,
                "unclaimed_from_local_checkout": 1,
            }
            status["scanner_burndown_snapshot"]["scanner_worker_next_rows"] = {
                "selection": {
                    "selected_count": 1,
                    "candidate_rows_scanned": 8,
                    "skipped_counts": {"already_committed": 7},
                }
            }
            status["scanner_burndown_snapshot"]["skipped_worker_slots"] = [
                {
                    "row_id": "already_closed_row",
                    "rank": 1,
                    "lane": "add_fixture_or_proof",
                    "local_coordination_status": "already_committed",
                    "skip_reason": "already_committed",
                    "committed_after_queue_paths": ["tools/tests/test_already_closed_row.py"],
                    "coordination_note": "row-local evidence paths were committed after the queue baseline",
                }
            ]
            write_json(status_path, status)

            packet = mod.build_packet(root, memory_root=memory, vault_root=vault)

        priority = packet["current_priority"]
        self.assertEqual(priority["skipped_scanner_worker_slot_count"], 7)
        self.assertEqual(priority["skipped_scanner_worker_slots"][0]["row_id"], "already_closed_row")
        self.assertEqual(
            priority["skipped_scanner_worker_slots"][0]["committed_after_queue_paths"],
            ["tools/tests/test_already_closed_row.py"],
        )
        self.assertEqual(
            priority["scanner_worker_slot_coordination_counts"]["already_committed"],
            7,
        )
        self.assertTrue(
            priority["scanner_coordination_guidance"]["refresh_inventory_before_more_detector_assignments"]
        )
        self.assertEqual(
            priority["scanner_coordination_guidance"]["do_not_redispatch_statuses"],
            ["already_committed"],
        )
        self.assertEqual(
            priority["scanner_worker_next_rows"]["selection"]["skipped_counts"],
            {"already_committed": 7},
        )

    def test_stale_and_missing_required_artifacts_fail_closed(self) -> None:
        mod = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "checkout"
            root.mkdir()
            memory, vault = make_memory_root(Path(tmp), stale_shared_index=True, missing_brief=True)

            packet = mod.build_packet(root, memory_root=memory, vault_root=vault)

        guard_map = {(row["scope"], row["status"]) for row in packet["stale_source_guards"]}
        self.assertIn(("required_artifact", "BLOCKED"), guard_map)
        self.assertIn(("artifact_freshness", "BLOCKED"), guard_map)
        self.assertGreater(packet["freshness_summary"]["blocking_count"], 0)
        self.assertTrue(
            any(row["scope"] == "artifact_freshness" and row["blocking"] for row in packet["stale_source_guards"])
        )
        self.assertTrue(any(row["evidence"]["path"] == "reports/memory_brief_2026-05-05.json" for row in packet["stale_source_guards"] if row["scope"] == "required_artifact"))

    def test_latest_artifact_packets_are_used_when_default_filenames_are_missing(self) -> None:
        mod = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "checkout"
            root.mkdir()
            memory, vault = make_memory_root(Path(tmp))
            reports = memory / "reports"
            stems = [
                "shared_memory_index",
                "memory_brief",
                "obsidian_memory_entrypoints",
                "known_limitations_harness_memory_status",
                "model_takeover_readiness",
                "model_takeover_provider_handoff",
                "goal_loop_status",
                "known_limitations_dispatch",
                "next_50_loops",
                "scanner_worker_active_claims",
            ]
            for stem in stems:
                old_path = reports / f"{stem}_2026-05-05.json"
                if not old_path.exists():
                    continue
                payload = json.loads(old_path.read_text(encoding="utf-8"))
                if isinstance(payload, dict):
                    if "generated_date" in payload:
                        payload["generated_date"] = "2026-05-06"
                    elif "date" in payload:
                        payload["date"] = "2026-05-06"
                    elif "generated_at" in payload:
                        payload["generated_at"] = "2026-05-06T00:00:00+00:00"
                    elif "updated_at" in payload:
                        payload["updated_at"] = "2026-05-06T00:00:00+00:00"
                write_json(reports / f"{stem}_2026-05-06.json", payload)
                old_path.unlink()

            packet = mod.build_packet(root, memory_root=memory, vault_root=vault)

        required_artifact_blockers = [
            row
            for row in packet["stale_source_guards"]
            if row["scope"] == "required_artifact" and row["blocking"]
        ]
        required_freshness_blockers = [
            row
            for row in packet["stale_source_guards"]
            if row["scope"] == "artifact_freshness" and row["blocking"]
        ]
        self.assertEqual(required_artifact_blockers, [])
        self.assertEqual(required_freshness_blockers, [])
        inventory_by_key = {row["key"]: row for row in packet["memory_source"]["artifact_inventory"]}
        self.assertEqual(
            inventory_by_key["known_limitations_harness_memory_status"]["path"],
            "reports/known_limitations_harness_memory_status_2026-05-06.json",
        )
        self.assertEqual(
            packet["current_priority"]["active_scanner_claims"]["source_path"],
            "reports/scanner_worker_active_claims_2026-05-06.json",
        )
        self.assertEqual(packet["freshness_summary"]["blocking_count"], 0)

    def test_stale_old_root_metadata_does_not_drive_handoff_branch(self) -> None:
        mod = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "checkout"
            root.mkdir()
            memory, vault = make_memory_root(Path(tmp))
            old_root = Path(tmp) / "continuation-plan-update"
            old_root.mkdir()

            obsidian_path = memory / "reports" / "obsidian_memory_entrypoints_2026-05-05.json"
            obsidian = json.loads(obsidian_path.read_text(encoding="utf-8"))
            obsidian["memory_root"] = str(old_root)
            obsidian["memory_branch"] = "continuation-plan"
            obsidian["operational_snapshot"]["branch"] = "continuation-plan"
            obsidian["operational_snapshot"]["pr_605_handoff"]["branch"] = "continuation-plan"
            write_json(obsidian_path, obsidian)

            klbq_path = memory / "reports" / "known_limitations_harness_memory_status_2026-05-05.json"
            klbq = json.loads(klbq_path.read_text(encoding="utf-8"))
            klbq["worktree"] = str(old_root)
            klbq["branch"] = "continuation-plan"
            write_json(klbq_path, klbq)

            packet = mod.build_packet(root, memory_root=memory, vault_root=vault)

        self.assertEqual(packet["memory_source"]["root"], str(memory.resolve()))
        self.assertEqual(packet["memory_source"]["branch"], "fresh-memory-root")
        self.assertEqual(packet["current_priority"]["current_branch_from_memory"], "fresh-memory-root")
        guard_scopes = {row["scope"] for row in packet["stale_source_guards"]}
        self.assertIn("obsidian_memory_root_mismatch", guard_scopes)
        self.assertIn("obsidian_branch_mismatch", guard_scopes)
        self.assertIn("klbq_worktree_mismatch", guard_scopes)
        self.assertIn("klbq_branch_mismatch", guard_scopes)
        self.assertIn("active_integration_boundary", guard_scopes)

    def test_cli_writes_json_markdown_and_advisory_vault_stale_does_not_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "checkout"
            root.mkdir()
            memory, vault = make_memory_root(Path(tmp))

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--root",
                    str(root),
                    "--memory-root",
                    str(memory),
                    "--vault-root",
                    str(vault),
                    "--fail-on-stale",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0)
            json_out = root / "reports" / "memory_retrieval_bootstrap_2026-05-05.json"
            md_out = root / "agent_briefs" / "AGENT_BOOTSTRAP_QUERY_2026-05-05.md"
            self.assertTrue(json_out.is_file())
            self.assertTrue(md_out.is_file())
            payload = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.memory_retrieval_bootstrap.v1")
            self.assertIn("Agent Bootstrap Query", md_out.read_text(encoding="utf-8"))
            self.assertIn("Scanner Worker Slots", md_out.read_text(encoding="utf-8"))
            self.assertIn("Commit-Mining Source Disposition", md_out.read_text(encoding="utf-8"))
            self.assertTrue(any(row["scope"] == "obsidian_vault_freshness" for row in payload["stale_source_guards"]))
            self.assertEqual(payload["freshness_summary"]["blocking_count"], 0)

    def test_cli_fail_on_stale_returns_two_for_blocking_memory_stale(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "checkout"
            root.mkdir()
            memory, vault = make_memory_root(Path(tmp), missing_brief=True)

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--root",
                    str(root),
                    "--memory-root",
                    str(memory),
                    "--vault-root",
                    str(vault),
                    "--fail-on-stale",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()
