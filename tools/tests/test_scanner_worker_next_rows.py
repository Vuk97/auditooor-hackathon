"""Tests for scanner-worker-next-rows.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "scanner-worker-next-rows.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("scanner_worker_next_rows", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


def _action(row_id: str, rank: int, *, lane: str = "add_fixture_or_proof") -> dict[str, object]:
    return {
        "rank": rank,
        "lane": lane,
        "row_id": row_id,
        "scanner_id": row_id,
        "backend": "solidity",
        "wiring_status": "generated_no_fixture",
        "proof_status": "source_shape_only",
        "source_paths": [
            f"detectors/fixtures/{row_id}/extraction_failure.json",
            f"detectors/wave17/{row_id}.py",
        ],
        "suggested_next_action": "materialize vulnerable/clean fixtures before counting as wired",
        "suggested_commands": [
            {
                "command": f"rg -n {row_id} detectors reference tools/tests",
                "reason": "Locate row artifacts.",
            }
        ],
        "claim_guard": "Do not claim this scanner detects a real exploit until fixture-backed evidence exists.",
    }


class ScannerWorkerNextRowsTests(unittest.TestCase):
    def assertAdvisoryTemplateCommand(self, entry: dict[str, object]) -> None:
        self.assertIs(entry["advisory_only"], True)
        self.assertIs(entry["runnable"], False)
        self.assertIn("Template command", str(entry["execution_boundary"]))

    def test_build_next_rows_skips_dirty_committed_and_complete_local_evidence(self) -> None:
        queue = {
            "schema": "auditooor.scanner_wiring_burndown_queue.v1",
            "actionable_row_count": 6,
            "top_action_count": 6,
            "actions": [
                _action("dirty_row", 1),
                _action("committed_row", 2),
                _action("stale_evidence_row", 3),
                _action("dirty_complete_row", 4),
                _action("partial_row", 5),
                _action("unclaimed_row", 6),
            ],
        }
        state = MOD.LocalState(
            branch="test",
            head="abc123",
            dirty_paths=frozenset(
                {
                    "detectors/fixtures/dirty_row/positive.sol",
                    "detectors/fixtures/dirty_complete_row/positive.sol",
                }
            ),
            existing_paths=frozenset(
                {
                    "detectors/fixtures/dirty_row",
                    "detectors/fixtures/dirty_row/positive.sol",
                    "detectors/fixtures/committed_row",
                    "detectors/fixtures/committed_row/row_smoke.json",
                    "tools/tests/test_committed_row.py",
                    "detectors/fixtures/stale_evidence_row",
                    "detectors/fixtures/stale_evidence_row/row_smoke.json",
                    "tools/tests/test_stale_evidence_row.py",
                    "detectors/fixtures/dirty_complete_row",
                    "detectors/fixtures/dirty_complete_row/clean.sol",
                    "detectors/fixtures/dirty_complete_row/positive.sol",
                    "tools/tests/test_dirty_complete_row.py",
                    "detectors/fixtures/partial_row",
                    "detectors/fixtures/partial_row/extraction_failure.json",
                }
            ),
            committed_after_queue_paths=frozenset(
                {
                    "detectors/fixtures/committed_row/row_smoke.json",
                    "tools/tests/test_committed_row.py",
                }
            ),
            queue_baseline_commit="base123",
        )

        report = MOD.build_next_rows(queue, state=state, limit=2, scan_limit=10)

        self.assertEqual(report["schema"], "auditooor.scanner_worker_next_rows.v1")
        self.assertEqual([row["row_id"] for row in report["rows"]], ["partial_row", "unclaimed_row"])
        self.assertEqual(
            report["selection"]["skipped_counts"],
            {
                "already_committed": 1,
                "claimed_dirty_worktree": 1,
                "local_evidence_present_refresh_needed": 2,
            },
        )
        skipped = {row["row_id"]: row for row in report["skipped_samples"]}
        self.assertEqual(skipped["dirty_row"]["local_coordination_status"], "claimed_dirty_worktree")
        self.assertEqual(skipped["committed_row"]["local_coordination_status"], "already_committed")
        self.assertEqual(
            skipped["stale_evidence_row"]["local_coordination_status"],
            "local_evidence_present_refresh_needed",
        )
        self.assertEqual(
            skipped["dirty_complete_row"]["local_coordination_status"],
            "local_evidence_present_refresh_needed",
        )
        self.assertEqual(report["git_state"]["queue_baseline_commit"], "base123")

    def test_build_next_rows_skips_active_claim_registry_rows(self) -> None:
        queue = {
            "schema": "auditooor.scanner_wiring_burndown_queue.v1",
            "actions": [
                _action("assigned_but_clean_row", 1),
                _action("next_unclaimed_row", 2),
            ],
        }
        state = MOD.LocalState(active_claimed_row_ids=frozenset({"assigned_but_clean_row"}))

        report = MOD.build_next_rows(queue, state=state, limit=1, scan_limit=10)

        self.assertEqual([row["row_id"] for row in report["rows"]], ["next_unclaimed_row"])
        self.assertEqual(report["selection"]["skipped_counts"], {"claimed_active_registry": 1})
        self.assertEqual(report["git_state"]["active_claimed_row_count"], 1)
        skipped = {row["row_id"]: row for row in report["skipped_samples"]}
        self.assertEqual(
            skipped["assigned_but_clean_row"]["local_coordination_status"],
            "claimed_active_registry",
        )
        self.assertIn("active scanner worker claims registry", skipped["assigned_but_clean_row"]["reason"])

    def test_active_claim_with_complete_local_evidence_is_reported_for_reconciliation(self) -> None:
        row_id = "stale_active_row"
        queue = {
            "schema": "auditooor.scanner_wiring_burndown_queue.v1",
            "actions": [
                _action(row_id, 1),
                _action("next_unclaimed_row", 2),
            ],
        }
        state = MOD.LocalState(
            active_claimed_row_ids=frozenset({row_id}),
            existing_paths=frozenset(
                {
                    f"detectors/fixtures/{row_id}/positive.sol",
                    f"detectors/fixtures/{row_id}/clean.sol",
                    f"detectors/fixtures/{row_id}/smoke.json",
                    f"tools/tests/test_{row_id}.py",
                }
            ),
        )

        report = MOD.build_next_rows(queue, state=state, limit=1, scan_limit=10)

        self.assertEqual([row["row_id"] for row in report["rows"]], ["next_unclaimed_row"])
        self.assertEqual(report["selection"]["active_claims_with_local_evidence_count"], 1)
        self.assertEqual(report["active_claims_with_local_evidence"][0]["row_id"], row_id)
        self.assertTrue(report["active_claims_with_local_evidence"][0]["complete_local_evidence"])
        self.assertIn("check worker status", report["active_claims_with_local_evidence"][0]["reason"])

    def test_build_next_rows_skips_completed_claim_registry_rows(self) -> None:
        queue = {
            "schema": "auditooor.scanner_wiring_burndown_queue.v1",
            "actions": [
                _action("completed_without_local_evidence", 1),
                _action("next_unclaimed_row", 2),
            ],
        }
        state = MOD.LocalState(completed_claimed_row_ids=frozenset({"completed_without_local_evidence"}))

        report = MOD.build_next_rows(queue, state=state, limit=1, scan_limit=10)

        self.assertEqual([row["row_id"] for row in report["rows"]], ["next_unclaimed_row"])
        self.assertEqual(report["selection"]["skipped_counts"], {"claimed_completed_registry": 1})
        self.assertEqual(report["git_state"]["completed_claimed_row_count"], 1)
        skipped = {row["row_id"]: row for row in report["skipped_samples"]}
        self.assertEqual(
            skipped["completed_without_local_evidence"]["local_coordination_status"],
            "claimed_completed_registry",
        )
        self.assertIn("recorded complete", skipped["completed_without_local_evidence"]["reason"])

    def test_selected_row_includes_self_contained_worker_prompt(self) -> None:
        queue = {
            "schema": "auditooor.scanner_wiring_burndown_queue.v1",
            "actions": [_action("prompt_ready_row", 1)],
        }
        report = MOD.build_next_rows(queue, state=MOD.LocalState(), limit=1, scan_limit=5)
        row = report["rows"][0]

        self.assertIn("worker_prompt", row)
        self.assertIn("You are not alone in the codebase", row["worker_prompt"])
        self.assertIn("Owned row: prompt_ready_row", row["worker_prompt"])
        self.assertIn("Declared backend: solidity", row["worker_prompt"])
        self.assertIn("tools/tests/test_prompt_ready_row.py", row["worker_prompt"])
        self.assertIn("NOT_SUBMIT_READY", row["worker_prompt"])
        self.assertIn("detectors/run_custom.py", row["worker_prompt"])
        self.assertIn("Hacker-logic handoff", row["worker_prompt"])
        self.assertIn("detector-hit-action-graph", row["worker_prompt"])
        self.assertIn("proof-obligation-queue", row["worker_prompt"])
        self.assertEqual(row["prompt_mode"], "local-only")
        self.assertIn("do not run GitHub commands", row["worker_prompt"])
        self.assertIn("do not commit", row["worker_prompt"])
        self.assertNotIn("git commit --only --", row["worker_prompt"])
        self.assertNotIn("Final response must include commit hash", row["worker_prompt"])
        self.assertIn(
            "no GitHub, network, approval/escalation, or commit commands are required",
            row["acceptance_criteria"],
        )
        handoff = row["hacker_logic_handoff"]
        self.assertIn("proof-obligation work", handoff["purpose"])
        commands = [entry["command"] for entry in handoff["commands"]]
        self.assertIn("make audit WS=<audit-workspace> FORCE=1", commands)
        self.assertTrue(any("DETECTOR=prompt-ready-row" in command for command in commands))
        self.assertTrue(any(command.startswith("make proof-obligation-queue") for command in commands))
        for entry in handoff["commands"]:
            self.assertAdvisoryTemplateCommand(entry)
        self.assertEqual(row["suggested_commands"][0]["command"], "rg -n prompt_ready_row detectors reference tools/tests")
        for entry in row["suggested_commands"]:
            self.assertAdvisoryTemplateCommand(entry)

    def test_worker_prompt_uses_dsl_backend_for_anchor_rows(self) -> None:
        row_id = "anchor_prompt_row"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dsl_dir = root / "reference" / "patterns.dsl"
            dsl_dir.mkdir(parents=True)
            (dsl_dir / "anchor-prompt-row.yaml").write_text(
                "pattern: anchor-prompt-row\nbackend: anchor\n",
                encoding="utf-8",
            )
            queue = {
                "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                "actions": [_action(row_id, 1)],
            }

            report = MOD.build_next_rows(queue, state=MOD.LocalState(), root=root, limit=1, scan_limit=5)

        row = report["rows"][0]
        self.assertEqual(row["backend"], "anchor")
        self.assertIn("Declared backend: anchor", row["worker_prompt"])
        self.assertIn("tools/anchor-detector-runner.py", row["worker_prompt"])
        self.assertNotIn("detectors/run_custom.py", row["worker_prompt"])

    def test_worker_prompt_uses_backend_specific_rust_guidance(self) -> None:
        row = MOD.build_next_rows(
            {
                "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                "actions": [
                    {
                        **_action("rust_prompt_row", 1),
                        "backend": "rust",
                    }
                ],
            },
            state=MOD.LocalState(),
            limit=1,
            scan_limit=5,
        )["rows"][0]

        self.assertEqual(row["backend"], "rust")
        self.assertIn("Declared backend: rust", row["worker_prompt"])
        self.assertIn("tools/rust-detector-runner.py", row["worker_prompt"])
        self.assertIn("tools/rust-source-graph.py", row["worker_prompt"])
        self.assertNotIn("detectors/run_custom.py", row["worker_prompt"])

    def test_commit_prompt_mode_preserves_checkpoint_commit_instructions(self) -> None:
        queue = {
            "schema": "auditooor.scanner_wiring_burndown_queue.v1",
            "actions": [_action("commit_prompt_row", 1)],
        }
        report = MOD.build_next_rows(
            queue,
            state=MOD.LocalState(),
            limit=1,
            scan_limit=5,
            prompt_mode=MOD.PROMPT_MODE_COMMIT,
        )
        row = report["rows"][0]

        self.assertEqual(row["prompt_mode"], "commit")
        self.assertIn("Commit only your owned paths", row["worker_prompt"])
        self.assertIn("git diff --cached --name-only", row["worker_prompt"])
        self.assertIn("git commit --only --", row["worker_prompt"])
        self.assertIn("git show --name-only --oneline HEAD", row["worker_prompt"])
        self.assertIn("commit hash", row["worker_prompt"])
        self.assertIn(
            "pre-commit staged-file check is handled without committing unrelated staged paths",
            row["acceptance_criteria"],
        )

    def test_active_claims_file_marks_assigned_rows_before_dirty_paths_exist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            claims_path = root / "claims.json"
            claims_path.write_text(
                json.dumps(
                    {
                        "active_claims": [
                            {"row_id": "open_claim_row", "agent_id": "agent-1", "status": "active"},
                            {"row_id": "closed_claim_row", "status": "completed"},
                            {"row_id": "failed_claim_row", "status": "failed"},
                            "string_claim_row",
                        ]
                    }
                ),
                encoding="utf-8",
            )

            state = MOD.local_state_from_git(root, root / "reports" / "missing_queue.json", active_claims_path=claims_path)

        self.assertIn("open_claim_row", state.active_claimed_row_ids)
        self.assertIn("string_claim_row", state.active_claimed_row_ids)
        self.assertNotIn("closed_claim_row", state.active_claimed_row_ids)
        self.assertIn("closed_claim_row", state.completed_claimed_row_ids)
        self.assertNotIn("failed_claim_row", state.active_claimed_row_ids)
        self.assertNotIn("failed_claim_row", state.completed_claimed_row_ids)
        self.assertIn("failed_claim_row", state.failed_claimed_row_ids)

    def test_failed_claim_registry_rows_are_cooldown_blocked(self) -> None:
        queue = {
            "schema": "auditooor.scanner_wiring_burndown_queue.v1",
            "actions": [
                _action("failed_claim_row", 1),
                _action("next_unclaimed_row", 2),
            ],
        }
        state = MOD.LocalState(failed_claimed_row_ids=frozenset({"failed_claim_row"}))

        report = MOD.build_next_rows(queue, state=state, limit=1, scan_limit=10)

        self.assertEqual([row["row_id"] for row in report["rows"]], ["next_unclaimed_row"])
        self.assertEqual(report["selection"]["skipped_counts"], {"claimed_failed_registry_cooldown": 1})
        self.assertEqual(report["git_state"]["failed_claimed_row_count"], 1)
        skipped = {row["row_id"]: row for row in report["skipped_samples"]}
        self.assertEqual(
            skipped["failed_claim_row"]["local_coordination_status"],
            "claimed_failed_registry_cooldown",
        )
        self.assertIn("failed scanner worker claim", skipped["failed_claim_row"]["reason"])

    def test_legacy_wave13_broken_proof_layout_counts_as_complete_local_evidence(self) -> None:
        row_id = "legacy_wave13_broken_proof_row"
        queue = {
            "schema": "auditooor.scanner_wiring_burndown_queue.v1",
            "actions": [
                _action(row_id, 1),
                _action("next_unclaimed_row", 2),
            ],
        }
        state = MOD.LocalState(
            existing_paths=frozenset(
                {
                    f"detectors/wave13_broken/{row_id}_clean.sol",
                    f"detectors/wave13_broken/{row_id}_smoke.json",
                    f"detectors/wave13_broken/{row_id}_vulnerable.sol",
                    f"tools/tests/test_{row_id}.py",
                }
            ),
        )

        report = MOD.build_next_rows(queue, state=state, limit=1, scan_limit=10)
        classification = MOD.classify_action(_action(row_id, 1), state)

        self.assertEqual([row["row_id"] for row in report["rows"]], ["next_unclaimed_row"])
        self.assertEqual(report["selection"]["skipped_counts"], {"local_evidence_present_refresh_needed": 1})
        self.assertEqual(classification["status"], "local_evidence_present_refresh_needed")
        self.assertTrue(classification["local_evidence"]["complete_local_evidence"])
        self.assertEqual(
            classification["local_evidence"]["legacy_proof_paths"],
            [
                f"detectors/wave13_broken/{row_id}_clean.sol",
                f"detectors/wave13_broken/{row_id}_smoke.json",
                f"detectors/wave13_broken/{row_id}_vulnerable.sol",
            ],
        )

    def test_complete_local_evidence_is_not_lost_after_many_fixture_matches(self) -> None:
        row_id = "expanded_queue_row"
        queue = {
            "schema": "auditooor.scanner_wiring_burndown_queue.v1",
            "actions": [
                _action(row_id, 1),
                _action("next_unclaimed_row", 2),
            ],
        }
        fixture_noise = {
            f"detectors/fixtures/{row_id}/{index:02d}_support.sol"
            for index in range(16)
        }
        state = MOD.LocalState(
            existing_paths=frozenset(
                {
                    f"detectors/fixtures/{row_id}",
                    f"detectors/fixtures/{row_id}/clean.sol",
                    f"detectors/fixtures/{row_id}/positive.sol",
                    f"detectors/fixtures/{row_id}/smoke.json",
                    f"reference/patterns.dsl/{row_id.replace('_', '-')}.yaml",
                    f"tools/tests/test_{row_id}.py",
                    *fixture_noise,
                }
            ),
        )

        report = MOD.build_next_rows(queue, state=state, limit=1, scan_limit=10)
        classification = MOD.classify_action(_action(row_id, 1), state)

        self.assertEqual([row["row_id"] for row in report["rows"]], ["next_unclaimed_row"])
        self.assertEqual(report["selection"]["skipped_counts"], {"local_evidence_present_refresh_needed": 1})
        self.assertEqual(classification["status"], "local_evidence_present_refresh_needed")
        self.assertIn(f"tools/tests/test_{row_id}.py", classification["local_evidence"]["test_paths"])
        self.assertTrue(classification["local_evidence"]["complete_local_evidence"])

    def test_repo_root_state_requires_valid_smoke_metadata_before_suppressing_row(self) -> None:
        row_id = "stale_smoke_row"
        queue = {
            "schema": "auditooor.scanner_wiring_burndown_queue.v1",
            "actions": [_action(row_id, 1)],
        }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            smoke = root / "detectors" / "fixtures" / row_id / "smoke.json"
            smoke.parent.mkdir(parents=True)
            smoke.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.canonical_detector_fixture_smoke.v1",
                        "fixture_id": row_id,
                        "status": "stale",
                        "positive_hits": 0,
                        "clean_hits": 0,
                    }
                ),
                encoding="utf-8",
            )
            state = MOD.LocalState(
                repo_root=str(root),
                existing_paths=frozenset(
                    {
                        f"detectors/fixtures/{row_id}/clean.sol",
                        f"detectors/fixtures/{row_id}/positive.sol",
                        f"detectors/fixtures/{row_id}/smoke.json",
                        f"tools/tests/test_{row_id}.py",
                    }
                ),
            )

            report = MOD.build_next_rows(queue, state=state, limit=1, scan_limit=10)
            classification = MOD.classify_action(_action(row_id, 1), state)

        self.assertEqual([row["row_id"] for row in report["rows"]], [row_id])
        self.assertEqual(classification["status"], "unclaimed_from_local_checkout")
        self.assertFalse(classification["local_evidence"]["complete_local_evidence"])
        self.assertEqual(
            classification["local_evidence"]["smoke_validation"][f"detectors/fixtures/{row_id}/smoke.json"]["reason"],
            "smoke_json_status_not_pass",
        )

    def test_repo_root_state_accepts_valid_smoke_metadata_as_complete_local_evidence(self) -> None:
        row_id = "valid_smoke_row"
        queue = {
            "schema": "auditooor.scanner_wiring_burndown_queue.v1",
            "actions": [_action(row_id, 1), _action("next_unclaimed_row", 2)],
        }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            smoke = root / "detectors" / "fixtures" / row_id / "smoke.json"
            smoke.parent.mkdir(parents=True)
            smoke.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.canonical_detector_fixture_smoke.v1",
                        "fixture_id": row_id,
                        "status": "passed_vulnerable_clean_smoke",
                        "positive_hits": 1,
                        "clean_hits": 0,
                    }
                ),
                encoding="utf-8",
            )
            state = MOD.LocalState(
                repo_root=str(root),
                existing_paths=frozenset(
                    {
                        f"detectors/fixtures/{row_id}/clean.sol",
                        f"detectors/fixtures/{row_id}/positive.sol",
                        f"detectors/fixtures/{row_id}/smoke.json",
                        f"tools/tests/test_{row_id}.py",
                    }
                ),
            )

            report = MOD.build_next_rows(queue, state=state, limit=1, scan_limit=10)
            classification = MOD.classify_action(_action(row_id, 1), state)

        self.assertEqual([row["row_id"] for row in report["rows"]], ["next_unclaimed_row"])
        self.assertEqual(classification["status"], "local_evidence_present_refresh_needed")
        self.assertTrue(classification["local_evidence"]["complete_local_evidence"])
        self.assertEqual(
            classification["local_evidence"]["valid_smoke_paths"],
            [f"detectors/fixtures/{row_id}/smoke.json"],
        )

    def test_repo_root_state_accepts_passed_smoke_fixture_refs_without_hit_counters(self) -> None:
        row_id = "fixture_ref_smoke_row"
        queue = {
            "schema": "auditooor.scanner_wiring_burndown_queue.v1",
            "actions": [_action(row_id, 1), _action("next_unclaimed_row", 2)],
        }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture_dir = root / "detectors" / "fixtures" / row_id
            fixture_dir.mkdir(parents=True)
            (fixture_dir / "positive.sol").write_text("contract Bad {}", encoding="utf-8")
            (fixture_dir / "clean.sol").write_text("contract Good {}", encoding="utf-8")
            (fixture_dir / "smoke.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.canonical_detector_fixture_smoke.v1",
                        "fixture_id": row_id,
                        "status": "passed_vulnerable_clean_smoke",
                        "positive_fixture": "positive.sol",
                        "clean_fixture": "clean.sol",
                    }
                ),
                encoding="utf-8",
            )
            state = MOD.LocalState(
                repo_root=str(root),
                existing_paths=frozenset(
                    {
                        f"detectors/fixtures/{row_id}/clean.sol",
                        f"detectors/fixtures/{row_id}/positive.sol",
                        f"detectors/fixtures/{row_id}/smoke.json",
                        f"tools/tests/test_{row_id}.py",
                    }
                ),
            )

            report = MOD.build_next_rows(queue, state=state, limit=1, scan_limit=10)
            classification = MOD.classify_action(_action(row_id, 1), state)

        self.assertEqual([row["row_id"] for row in report["rows"]], ["next_unclaimed_row"])
        self.assertEqual(classification["status"], "local_evidence_present_refresh_needed")
        self.assertTrue(classification["local_evidence"]["complete_local_evidence"])
        verdict = classification["local_evidence"]["smoke_validation"][f"detectors/fixtures/{row_id}/smoke.json"]
        self.assertEqual(verdict["reason"], "passed_smoke_metadata_fixture_refs")
        self.assertEqual(verdict["positive_fixture_refs"], [f"detectors/fixtures/{row_id}/positive.sol"])
        self.assertEqual(verdict["clean_fixture_refs"], [f"detectors/fixtures/{row_id}/clean.sol"])

    def test_repo_root_state_rejects_smoke_fixture_refs_outside_row_dir(self) -> None:
        row_id = "fixture_ref_escape_row"
        sibling_id = "sibling_fixture_row"
        queue = {
            "schema": "auditooor.scanner_wiring_burndown_queue.v1",
            "actions": [_action(row_id, 1)],
        }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture_dir = root / "detectors" / "fixtures" / row_id
            sibling_dir = root / "detectors" / "fixtures" / sibling_id
            fixture_dir.mkdir(parents=True)
            sibling_dir.mkdir(parents=True)
            (sibling_dir / "positive.sol").write_text("contract Bad {}", encoding="utf-8")
            (sibling_dir / "clean.sol").write_text("contract Good {}", encoding="utf-8")
            (fixture_dir / "smoke.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.canonical_detector_fixture_smoke.v1",
                        "fixture_id": row_id,
                        "status": "passed_vulnerable_clean_smoke",
                        "positive_fixture": "../sibling_fixture_row/positive.sol",
                        "clean_fixture": "../sibling_fixture_row/clean.sol",
                    }
                ),
                encoding="utf-8",
            )
            state = MOD.LocalState(
                repo_root=str(root),
                existing_paths=frozenset(
                    {
                        f"detectors/fixtures/{row_id}/smoke.json",
                        f"detectors/fixtures/{sibling_id}/positive.sol",
                        f"detectors/fixtures/{sibling_id}/clean.sol",
                        f"tools/tests/test_{row_id}.py",
                    }
                ),
            )

            report = MOD.build_next_rows(queue, state=state, limit=1, scan_limit=10)
            classification = MOD.classify_action(_action(row_id, 1), state)

        self.assertEqual([row["row_id"] for row in report["rows"]], [row_id])
        self.assertFalse(classification["local_evidence"]["complete_local_evidence"])
        verdict = classification["local_evidence"]["smoke_validation"][f"detectors/fixtures/{row_id}/smoke.json"]
        self.assertEqual(verdict["reason"], "smoke_json_fixture_refs_missing")

    def test_repo_root_state_rejects_wrong_schema_and_boolean_hit_counters(self) -> None:
        for row_id, smoke_payload, reason in [
            (
                "missing_schema_smoke_row",
                {
                    "fixture_id": "missing_schema_smoke_row",
                    "status": "passed_vulnerable_clean_smoke",
                    "positive_hits": 1,
                    "clean_hits": 0,
                },
                "smoke_json_schema_mismatch",
            ),
            (
                "boolean_counter_smoke_row",
                {
                    "schema": "auditooor.canonical_detector_fixture_smoke.v1",
                    "fixture_id": "boolean_counter_smoke_row",
                    "status": "passed_vulnerable_clean_smoke",
                    "positive_hits": True,
                    "clean_hits": False,
                },
                "smoke_json_hit_counters_not_integer",
            ),
        ]:
            with self.subTest(row_id=row_id):
                queue = {
                    "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                    "actions": [_action(row_id, 1)],
                }
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    smoke = root / "detectors" / "fixtures" / row_id / "smoke.json"
                    smoke.parent.mkdir(parents=True)
                    smoke.write_text(json.dumps(smoke_payload), encoding="utf-8")
                    state = MOD.LocalState(
                        repo_root=str(root),
                        existing_paths=frozenset(
                            {
                                f"detectors/fixtures/{row_id}/smoke.json",
                                f"tools/tests/test_{row_id}.py",
                            }
                        ),
                    )

                    report = MOD.build_next_rows(queue, state=state, limit=1, scan_limit=10)
                    classification = MOD.classify_action(_action(row_id, 1), state)

                self.assertEqual([row["row_id"] for row in report["rows"]], [row_id])
                self.assertFalse(classification["local_evidence"]["complete_local_evidence"])
                self.assertEqual(
                    classification["local_evidence"]["smoke_validation"][
                        f"detectors/fixtures/{row_id}/smoke.json"
                    ]["reason"],
                    reason,
                )

    def test_repo_root_state_rejects_passed_smoke_missing_fixture_refs_and_hit_counters(self) -> None:
        row_id = "incomplete_ref_smoke_row"
        queue = {
            "schema": "auditooor.scanner_wiring_burndown_queue.v1",
            "actions": [_action(row_id, 1)],
        }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture_dir = root / "detectors" / "fixtures" / row_id
            fixture_dir.mkdir(parents=True)
            (fixture_dir / "positive.sol").write_text("contract Bad {}", encoding="utf-8")
            (fixture_dir / "smoke.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.canonical_detector_fixture_smoke.v1",
                        "fixture_id": row_id,
                        "status": "passed_vulnerable_clean_smoke",
                        "positive_fixture": "positive.sol",
                        "clean_fixture": "missing-clean.sol",
                    }
                ),
                encoding="utf-8",
            )
            state = MOD.LocalState(
                repo_root=str(root),
                existing_paths=frozenset(
                    {
                        f"detectors/fixtures/{row_id}/positive.sol",
                        f"detectors/fixtures/{row_id}/smoke.json",
                        f"tools/tests/test_{row_id}.py",
                    }
                ),
            )

            report = MOD.build_next_rows(queue, state=state, limit=1, scan_limit=10)
            classification = MOD.classify_action(_action(row_id, 1), state)

        self.assertEqual([row["row_id"] for row in report["rows"]], [row_id])
        self.assertEqual(classification["status"], "unclaimed_from_local_checkout")
        self.assertFalse(classification["local_evidence"]["complete_local_evidence"])
        self.assertEqual(
            classification["local_evidence"]["smoke_validation"][f"detectors/fixtures/{row_id}/smoke.json"]["reason"],
            "smoke_json_fixture_refs_missing",
        )

    def test_lane_top_actions_are_deduped_and_scanned_after_global_actions(self) -> None:
        duplicate = _action("same_row", 1)
        queue = {
            "schema": "auditooor.scanner_wiring_burndown_queue.v1",
            "actions": [duplicate],
            "lane_top_actions": {
                "add_fixture_or_proof": [duplicate, _action("lane_only_row", 2)],
            },
        }
        state = MOD.LocalState()

        report = MOD.build_next_rows(queue, state=state, limit=5, scan_limit=5)

        self.assertEqual([row["row_id"] for row in report["rows"]], ["same_row", "lane_only_row"])
        self.assertEqual(report["selection"]["candidate_rows_seen"], 2)

    def test_documentation_only_rows_are_deferred_by_default_after_executable_rows(self) -> None:
        queue = {
            "schema": "auditooor.scanner_wiring_burndown_queue.v1",
            "actions": [
                _action("exec_row", 1),
                _action("docs_row", 2, lane="documentation_only"),
                _action("later_docs_row", 3, lane="documentation_only"),
            ],
        }
        state = MOD.LocalState()

        report = MOD.build_next_rows(queue, state=state, limit=3, scan_limit=10)

        self.assertEqual([row["row_id"] for row in report["rows"]], ["exec_row"])
        self.assertFalse(report["selection"]["include_documentation_only"])
        self.assertEqual(report["selection"]["selected_count"], 1)
        self.assertEqual(report["selection"]["skipped_counts"], {"deferred_documentation_only": 2})
        skipped = {row["row_id"]: row for row in report["skipped_samples"]}
        self.assertEqual(skipped["docs_row"]["local_coordination_status"], "deferred_documentation_only")
        self.assertIn("deferred by default", skipped["docs_row"]["reason"])
        self.assertEqual(skipped["docs_row"]["matching_dirty_paths"], [])
        self.assertEqual(skipped["docs_row"]["committed_after_queue_paths"], [])
        self.assertEqual(skipped["docs_row"]["local_evidence_paths"], [])

    def test_canonical_documentation_only_dsl_overrides_stale_queue_lane(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dsl = root / "reference" / "patterns.dsl" / "docs-alias-row.yaml"
            dsl.parent.mkdir(parents=True)
            dsl.write_text(
                "pattern: docs-alias-row\nstatus: documentation-only\nbackend: solidity\n",
                encoding="utf-8",
            )
            queue = {
                "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                "actions": [
                    _action("docs_alias_row", 1, lane="add_fixture_or_proof"),
                    _action("exec_row", 2),
                ],
            }

            report = MOD.build_next_rows(
                queue,
                state=MOD.LocalState(),
                root=root,
                limit=3,
                scan_limit=10,
            )

            self.assertEqual([row["row_id"] for row in report["rows"]], ["exec_row"])
            self.assertEqual(report["selection"]["skipped_counts"], {"deferred_documentation_only": 1})
            skipped = {row["row_id"]: row for row in report["skipped_samples"]}
            self.assertEqual(skipped["docs_alias_row"]["lane"], "documentation_only")
            self.assertEqual(
                skipped["docs_alias_row"]["local_coordination_status"],
                "deferred_documentation_only",
            )

    def test_escaped_source_paths_cannot_override_backend_lane_or_prompts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside_tmp:
            root = Path(tmp)
            outside = Path(outside_tmp) / "outside-docs-only.yaml"
            outside.write_text(
                "pattern: escaped-row\nstatus: documentation-only\nbackend: anchor\n",
                encoding="utf-8",
            )
            queue = {
                "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                "actions": [
                    {
                        **_action("escaped_row", 1, lane="add_fixture_or_proof"),
                        "source_paths": [
                            str(outside),
                            "../outside-docs-only.yaml",
                            "detectors/fixtures/escaped_row/extraction_failure.json",
                        ],
                    }
                ],
            }

            report = MOD.build_next_rows(queue, state=MOD.LocalState(), root=root, limit=1, scan_limit=10)

        self.assertEqual([row["row_id"] for row in report["rows"]], ["escaped_row"])
        row = report["rows"][0]
        self.assertEqual(row["backend"], "solidity")
        self.assertEqual(row["lane"], "add_fixture_or_proof")
        self.assertNotIn(str(outside), json.dumps(row, sort_keys=True))
        self.assertNotIn("../outside-docs-only.yaml", json.dumps(row, sort_keys=True))
        self.assertIn("detectors/fixtures/escaped_row", row["owned_paths"])

    def test_build_next_rows_rejects_wrong_queue_schema(self) -> None:
        with self.assertRaises(ValueError):
            MOD.build_next_rows(
                {
                    "schema": "auditooor.scanner_wiring_burndown_queue_l22.v1",
                    "actions": [_action("wrong_schema_row", 1)],
                },
                state=MOD.LocalState(),
                limit=1,
            )

    def test_build_next_rows_rejects_malformed_action_rank(self) -> None:
        with self.assertRaisesRegex(ValueError, "non-integer rank"):
            MOD.build_next_rows(
                {
                    "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                    "actions": [
                        {
                            **_action("bad_rank_row", 1),
                            "rank": "not-a-number",
                        }
                    ],
                },
                state=MOD.LocalState(),
                limit=1,
            )

    def test_cli_bad_or_missing_queue_fails_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bad_queue = root / "bad_queue.json"
            bad_queue.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.scanner_wiring_burndown_queue_l22.v1",
                        "actions": [_action("bad_row", 1)],
                    }
                ),
                encoding="utf-8",
            )

            bad_proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--repo-root",
                    str(root),
                    "--queue",
                    str(bad_queue),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(bad_proc.returncode, 2)
            self.assertIn("unsupported scanner queue schema", bad_proc.stderr)
            self.assertNotIn("Traceback", bad_proc.stderr)

            missing_proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--repo-root",
                    str(root),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(missing_proc.returncode, 2)
            self.assertIn("scanner_wiring_burndown_queue_2026-05-05.json", missing_proc.stderr)
            self.assertNotIn("Traceback", missing_proc.stderr)

    def test_include_documentation_only_allows_explicit_docs_pass(self) -> None:
        queue = {
            "schema": "auditooor.scanner_wiring_burndown_queue.v1",
            "actions": [
                _action("exec_row", 1),
                _action("docs_row", 2, lane="documentation_only"),
            ],
        }
        state = MOD.LocalState()

        report = MOD.build_next_rows(
            queue,
            state=state,
            limit=3,
            scan_limit=10,
            include_documentation_only=True,
        )

        self.assertEqual([row["row_id"] for row in report["rows"]], ["exec_row", "docs_row"])
        self.assertTrue(report["selection"]["include_documentation_only"])
        self.assertEqual(report["selection"]["skipped_counts"], {})

    def test_cli_include_documentation_only_flag_selects_docs_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "reports").mkdir()
            queue_path = root / "reports" / "queue.json"
            queue_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                        "actions": [_action("docs_row", 1, lane="documentation_only")],
                    }
                ),
                encoding="utf-8",
            )

            default_proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--repo-root",
                    str(root),
                    "--queue",
                    str(queue_path),
                    "--limit",
                    "1",
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            default_payload = json.loads(default_proc.stdout)
            self.assertEqual(default_payload["rows"], [])
            self.assertEqual(
                default_payload["selection"]["skipped_counts"],
                {"deferred_documentation_only": 1},
            )

            include_proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--repo-root",
                    str(root),
                    "--queue",
                    str(queue_path),
                    "--limit",
                    "1",
                    "--include-documentation-only",
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            include_payload = json.loads(include_proc.stdout)
            self.assertEqual([row["row_id"] for row in include_payload["rows"]], ["docs_row"])

    def test_cli_defaults_to_latest_local_scanner_queue_when_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reports = root / "reports"
            reports.mkdir()
            old_queue = reports / "scanner_wiring_burndown_queue_2026-05-05.json"
            old_queue.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                        "actions": [_action("old_row", 1)],
                    }
                ),
                encoding="utf-8",
            )
            new_queue = reports / "scanner_wiring_burndown_queue_2026-05-08-postfix.json"
            new_queue.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                        "actions": [_action("new_row", 1)],
                    }
                ),
                encoding="utf-8",
            )
            (reports / "scanner_wiring_burndown_queue_2026-05-08-l24.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                        "actionable_row_count": 2,
                        "top_action_count": 1,
                        "actions": [_action("l24_row", 1)],
                    }
                ),
                encoding="utf-8",
            )
            (reports / "scanner_wiring_burndown_queue_l22_enhanced_2026-05-08.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.scanner_wiring_burndown_queue_l22.v1",
                        "ranked_queue": [{"row_id": "incompatible_row"}],
                    }
                ),
                encoding="utf-8",
            )
            (reports / "scanner_worker_active_claims_2026-05-08.json").write_text(
                json.dumps({"active_claims": []}),
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--repo-root",
                    str(root),
                    "--limit",
                    "1",
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            payload = json.loads(proc.stdout)

        self.assertEqual(payload["source_queue_path"], "reports/scanner_wiring_burndown_queue_2026-05-08-l24.json")
        self.assertEqual(payload["active_claims_path"], "reports/scanner_worker_active_claims_2026-05-08.json")
        self.assertEqual([row["row_id"] for row in payload["rows"]], ["l24_row"])

    def test_markdown_is_concise_and_lists_skipped_samples(self) -> None:
        queue = {
            "schema": "auditooor.scanner_wiring_burndown_queue.v1",
            "actions": [_action("dirty_row", 1), _action("next_row", 2)],
        }
        state = MOD.LocalState(dirty_paths=frozenset({"tools/tests/test_dirty_row.py"}))

        markdown = MOD.render_markdown(MOD.build_next_rows(queue, state=state, limit=1, scan_limit=5))

        self.assertIn("# Scanner Worker Next Rows", markdown)
        self.assertIn("`scanner-next-1` `next_row`", markdown)
        self.assertIn("`dirty_row`: `claimed_dirty_worktree`", markdown)
        self.assertIn("Active claims with local evidence", markdown)

    def test_cli_json_and_markdown_run_against_non_git_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "reports").mkdir()
            queue_path = root / "reports" / "queue.json"
            queue_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.scanner_wiring_burndown_queue.v1",
                        "actions": [_action("cli_row", 1)],
                    }
                ),
                encoding="utf-8",
            )

            json_proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--repo-root",
                    str(root),
                    "--queue",
                    str(queue_path),
                    "--limit",
                    "1",
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            payload = json.loads(json_proc.stdout)
            self.assertEqual(payload["rows"][0]["row_id"], "cli_row")
            for entry in payload["rows"][0]["suggested_commands"]:
                self.assertAdvisoryTemplateCommand(entry)
            for entry in payload["rows"][0]["hacker_logic_handoff"]["commands"]:
                self.assertAdvisoryTemplateCommand(entry)

            prompt_proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--repo-root",
                    str(root),
                    "--queue",
                    str(queue_path),
                    "--limit",
                    "1",
                    "--prompt-out-dir",
                    "prompts",
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            prompt_payload = json.loads(prompt_proc.stdout)
            prompt_path = root / prompt_payload["rows"][0]["worker_prompt_path"]
            self.assertTrue(prompt_path.exists())
            prompt_text = prompt_path.read_text(encoding="utf-8")
            self.assertIn("Owned row: cli_row", prompt_text)
            self.assertIn("do not commit", prompt_text)
            self.assertNotIn("git commit --only --", prompt_text)

            commit_prompt_proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--repo-root",
                    str(root),
                    "--queue",
                    str(queue_path),
                    "--limit",
                    "1",
                    "--prompt-mode",
                    "commit",
                    "--prompt-out-dir",
                    "commit-prompts",
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            commit_prompt_payload = json.loads(commit_prompt_proc.stdout)
            commit_prompt_path = root / commit_prompt_payload["rows"][0]["worker_prompt_path"]
            self.assertIn("git commit --only --", commit_prompt_path.read_text(encoding="utf-8"))

            md_proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--repo-root",
                    str(root),
                    "--queue",
                    str(queue_path),
                    "--markdown",
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertIn("# Scanner Worker Next Rows", md_proc.stdout)


if __name__ == "__main__":
    unittest.main()
