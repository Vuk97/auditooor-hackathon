#!/usr/bin/env python3
"""Tests for the recall-to-detector/source-proof queue."""

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
TOOL = ROOT / "tools" / "agent-recall-detector-queue.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("agent_recall_detector_queue", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tool = load_tool()


class AgentRecallDetectorQueueTests(unittest.TestCase):
    def make_ws(self) -> Path:
        ws = Path(tempfile.mkdtemp(prefix="agent_recall_detector_queue_"))
        (ws / ".auditooor").mkdir()
        return ws

    def write_ws_file(self, ws: Path, rel: str, text: str = "line one\nline two\n") -> Path:
        path = ws / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_builds_terminal_routes_from_recall_provider_semantic_and_known_limitations(self):
        ws = self.make_ws()
        audit = ws / ".auditooor"
        (audit / "agent_found_not_detector_found.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "status": "source_proof_required",
                            "agent_output": "agent_outputs/source.md",
                            "candidate_id": "BASE-SOURCE",
                            "claims_detected": ["crates/node/src/engine.rs:40"],
                            "reason": "source proof required",
                            "next_command": "make source-proof-task-queue WS=<workspace>",
                        },
                        {
                            "status": "harness_task_required",
                            "agent_output": "agent_outputs/harness.md",
                            "candidate_id": "BASE-HARNESS",
                            "claims_detected": ["forge replay"],
                            "reason": "harness required",
                            "next_command": "make harness-task-queue WS=<workspace>",
                        },
                        {
                            "status": "detectorized",
                            "agent_output": "agent_outputs/detectorized.md",
                            "claims_detected": ["already detected"],
                        },
                        {
                            "status": "killed_duplicate_or_oos",
                            "agent_output": "agent_outputs/killed.md",
                            "claims_detected": ["duplicate"],
                        },
                        {
                            "status": "blocked_missing_impact_contract",
                            "agent_output": "agent_outputs/blocked.md",
                            "claims_detected": ["critical candidate"],
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        provider = audit / "provider_result_local_verification.json"
        provider.write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "task_id": "P1",
                            "local_status": "source_symbol_confirmed",
                            "classifications": ["local_grep_advisory"],
                            "symbols": ["validate_payload"],
                            "verification_queue": {"next_commands": ["make live-provider-local-verification-queue"]},
                        },
                        {
                            "task_id": "P2",
                            "local_status": "source_file_confirmed",
                            "classifications": ["needs_fixture"],
                            "symbols": ["consume_cache"],
                        },
                        {
                            "task_id": "P3",
                            "local_status": "repo_grep_confirmed",
                            "classifications": ["non_detectorizable"],
                            "symbols": ["operator-only"],
                        },
                    ]
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
                            "task_type": "detector_rewrite_with_fixture_pair",
                            "scanner_inventory_status": "detector_task_routed",
                            "source_component": "Vault.withdraw",
                            "suggested_detector_slug": "vault_withdraw",
                            "next_command": "make semantic-fixture-smoke-gate WS=<workspace>",
                        },
                        {
                            "queue_id": "SSI-Q-002",
                            "task_type": "coverage_to_detector_worklist",
                            "scanner_inventory_status": "coverage_only_relation_unrouted",
                            "source_component": "Router.route",
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        (audit / "known_limitations_burndown.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "limitation_id": "cross-cut-agent-found-behavior-recall",
                            "blocker_category": "open_agent_recall_terminal_routes",
                            "title": "Agent-found behavior recall",
                            "stop_condition_met": False,
                            "next_command": "make agent-recall-detector-queue WS=<workspace>",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        payload = tool.build_queue(ws, limit=50, provider_paths=[provider])
        self.assertEqual(payload["schema"], "auditooor.pr560.agent_recall_detector_queue.v1")
        self.assertEqual(payload["queue_count"], 13)
        self.assertFalse(payload["truncated"])
        states = payload["terminal_state_counts"]
        self.assertEqual(states["source_proof_queue_ready"], 2)
        self.assertEqual(states["local_proof_required"], 1)
        self.assertEqual(states["detectorized_terminal"], 1)
        self.assertEqual(states["killed_duplicate_or_oos"], 1)
        self.assertEqual(states["blocked_missing_impact_contract"], 1)
        self.assertEqual(states["detector_queue_ready"], 2)
        self.assertEqual(states["non_detectorizable_terminal"], 1)
        self.assertEqual(states["blocked_missing_local_smoke"], 1)
        self.assertEqual(states["blocked_known_limitation"], 3)
        self.assertTrue(all(row["advisory_only"] for row in payload["rows"]))
        self.assertTrue(all(row["submission_posture"] == "NOT_SUBMIT_READY" for row in payload["rows"]))
        self.assertTrue(all(row["severity"] == "none" for row in payload["rows"]))

        tasks = tool.build_task_manifest(payload)
        self.assertEqual(tasks["schema"], "auditooor.pr560.agent_recall_detector_tasks.v1")
        self.assertEqual(tasks["task_count"], payload["queue_count"])
        self.assertEqual(tasks["task_type_counts"]["detector_task"], 3)
        self.assertEqual(tasks["task_type_counts"]["source_proof_task"], 2)
        self.assertEqual(tasks["task_type_counts"]["local_proof_task"], 1)
        self.assertEqual(tasks["task_type_counts"]["terminal_blocker"], 7)
        self.assertTrue(all(task["advisory_only"] for task in tasks["tasks"]))
        self.assertTrue(all(task["promotion_allowed"] is False for task in tasks["tasks"]))
        self.assertEqual({task["severity"] for task in tasks["tasks"]}, {"none"})
        self.assertEqual({task["selected_impact"] for task in tasks["tasks"]}, {""})
        detector_task = next(task for task in tasks["tasks"] if task["task_type"] == "detector_task")
        self.assertIn("missing_vulnerable_fixture", detector_task["terminal_blockers"])
        self.assertIn("missing_clean_fixture", detector_task["terminal_blockers"])
        self.assertIn("missing_local_detector_smoke_output", detector_task["terminal_blockers"])
        source_task = next(task for task in tasks["tasks"] if task["task_type"] == "source_proof_task")
        self.assertIn("missing_line_cited_source_proof", source_task["terminal_blockers"])
        self.assertIn("missing_exact_impact_contract", source_task["terminal_blockers"])
        self.assertIn("blocked_missing_citations", source_task["allowed_terminal_decisions"])

    def test_cli_writes_artifacts_and_honors_limit(self):
        ws = self.make_ws()
        audit = ws / ".auditooor"
        (audit / "agent_found_not_detector_found.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {"status": "source_proof_required", "agent_output": f"agent_outputs/{idx}.md"}
                        for idx in range(3)
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
        data = json.loads(proc.stdout)
        self.assertEqual(data["queue_count"], 2)
        self.assertTrue(data["truncated"])
        self.assertTrue((audit / "agent_recall_detector_queue.json").is_file())
        self.assertTrue((audit / "agent_recall_detector_queue.md").is_file())
        self.assertTrue((audit / "agent_recall_detector_tasks.json").is_file())
        self.assertTrue((audit / "agent_recall_detector_tasks.md").is_file())
        tasks = json.loads((audit / "agent_recall_detector_tasks.json").read_text(encoding="utf-8"))
        self.assertEqual(tasks["task_count"], 2)
        self.assertGreaterEqual(tasks["task_type_counts"]["source_proof_task"], 1)
        self.assertTrue(all(task["promotion_allowed"] is False for task in tasks["tasks"]))

    def test_semantic_rows_with_vulnerable_clean_smoke_are_terminalized(self):
        ws = self.make_ws()
        audit = ws / ".auditooor"
        (audit / "agent_found_not_detector_found.json").write_text(json.dumps({"rows": []}), encoding="utf-8")
        (audit / "semantic_scanner_inventory.json").write_text(
            json.dumps(
                {
                    "detector_fixture_task_queue": [
                        {
                            "queue_id": "SSI-Q-001",
                            "task_type": "detector_rewrite_with_fixture_pair",
                            "scanner_inventory_status": "detector_task_routed",
                            "source_component": "Vault.withdraw",
                            "suggested_detector_slug": "vault_withdraw",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (audit / "semantic_detector_smoke_executor.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "argument": "vault-withdraw",
                            "status": "passed_vulnerable_clean_smoke",
                            "positive_fixture": "fixtures/vault_withdraw_vulnerable.sol",
                            "clean_fixture": "fixtures/vault_withdraw_clean.sol",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        self.write_ws_file(ws, "fixtures/vault_withdraw_vulnerable.sol", "contract V { function withdraw() external {} }\n")
        self.write_ws_file(ws, "fixtures/vault_withdraw_clean.sol", "contract C { function withdraw() external {} }\n")
        smoke_path = audit / "semantic_detector_smoke_executor.json"
        newest_fixture = max((ws / "fixtures/vault_withdraw_vulnerable.sol").stat().st_mtime, (ws / "fixtures/vault_withdraw_clean.sol").stat().st_mtime)
        os.utime(smoke_path, (newest_fixture + 1, newest_fixture + 1))
        provider = audit / "provider_result_local_verification.json"
        provider.write_text(json.dumps({"rows": []}), encoding="utf-8")

        payload = tool.build_queue(ws, limit=50, provider_paths=[provider])
        row = payload["rows"][0]
        self.assertEqual(row["terminal_state"], "detectorized_terminal")
        self.assertEqual(row["local_proof_status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(row["smoke_evidence_status"], "passed_vulnerable_clean_smoke")
        tasks = tool.build_task_manifest(payload)
        self.assertGreaterEqual(tasks["task_type_counts"]["terminal_blocker"], 1)
        self.assertEqual(tasks["task_type_counts"]["detector_task"], 0)

    def test_semantic_smoke_matching_accepts_trailing_hyphen_variants(self):
        ws = self.make_ws()
        audit = ws / ".auditooor"
        (audit / "agent_found_not_detector_found.json").write_text(json.dumps({"rows": []}), encoding="utf-8")
        (audit / "semantic_scanner_inventory.json").write_text(
            json.dumps(
                {
                    "detector_fixture_task_queue": [
                        {
                            "queue_id": "SSI-Q-013",
                            "task_type": "detector_rewrite_with_fixture_pair",
                            "scanner_inventory_status": "detector_task_routed",
                            "source_component": "Withdraw.defaultIterations",
                            "suggested_detector_slug": "a_high_value_of_defaultiterations_could_make_the_withdrawal_and",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (audit / "semantic_detector_smoke_executor.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "argument": "a-high-value-of-defaultiterations-could-make-the-withdrawal-and-",
                            "status": "passed_vulnerable_clean_smoke",
                            "positive_fixture": "fixtures/high_value_vulnerable.sol",
                            "clean_fixture": "fixtures/high_value_clean.sol",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        self.write_ws_file(ws, "fixtures/high_value_vulnerable.sol", "contract V { function defaultIterations() external {} }\n")
        self.write_ws_file(ws, "fixtures/high_value_clean.sol", "contract C { function defaultIterations() external {} }\n")
        smoke_path = audit / "semantic_detector_smoke_executor.json"
        newest_fixture = max((ws / "fixtures/high_value_vulnerable.sol").stat().st_mtime, (ws / "fixtures/high_value_clean.sol").stat().st_mtime)
        os.utime(smoke_path, (newest_fixture + 1, newest_fixture + 1))
        provider = audit / "provider_result_local_verification.json"
        provider.write_text(json.dumps({"rows": []}), encoding="utf-8")

        payload = tool.build_queue(ws, limit=50, provider_paths=[provider])

        row = next(row for row in payload["rows"] if row["source_id"] == "ssi-q-013")
        self.assertEqual(row["terminal_state"], "detectorized_terminal")
        self.assertEqual(row["local_proof_status"], "passed_vulnerable_clean_smoke")

    def test_internal_tool_provider_hypotheses_do_not_create_solidity_detector_tasks(self):
        ws = self.make_ws()
        audit = ws / ".auditooor"
        (audit / "agent_found_not_detector_found.json").write_text(json.dumps({"rows": []}), encoding="utf-8")
        (audit / "semantic_scanner_inventory.json").write_text(json.dumps({"detector_fixture_task_queue": []}), encoding="utf-8")
        provider = audit / "provider_result_local_verification.json"
        provider.write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "task_id": "worker-am-006",
                            "evidence_class": "generated_hypothesis",
                            "local_status": "source_symbol_confirmed",
                            "classifications": ["needs_fixture"],
                            "symbols": ["_skip_path"],
                            "source_paths": ["tools/anchor-detector-runner.py"],
                            "source_hits": [{"path": "tools/anchor-detector-runner.py", "matched_symbols": ["_skip_path"]}],
                            "term_hits": {"_skip_path": ["tools/anchor-detector-runner.py", ".auditooor/queue.json"]},
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        payload = tool.build_queue(ws, limit=50, provider_paths=[provider])
        tasks = tool.build_task_manifest(payload)

        row = next(row for row in payload["rows"] if row["source_id"] == "worker-am-006")
        self.assertEqual(row["terminal_state"], "non_detectorizable_terminal")
        self.assertEqual(row["reason"], "provider row targets Auditooor internal tool code, not a smart-contract detector fixture")
        self.assertEqual(tasks["task_type_counts"]["detector_task"], 0)
        self.assertGreaterEqual(tasks["task_type_counts"]["terminal_blocker"], 1)

    def test_full_corpus_proof_separates_detector_closure_from_open_source_work(self):
        ws = self.make_ws()
        audit = ws / ".auditooor"
        (audit / "agent_found_not_detector_found.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {"status": "detectorized", "agent_output": "agent_outputs/done.md"},
                        {"status": "source_proof_required", "agent_output": "agent_outputs/source.md"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        (audit / "semantic_scanner_inventory.json").write_text(json.dumps({"detector_fixture_task_queue": []}), encoding="utf-8")
        provider = audit / "provider_result_local_verification.json"
        provider.write_text(json.dumps({"rows": []}), encoding="utf-8")

        payload = tool.build_queue(ws, limit=100, provider_paths=[provider])
        tasks = tool.build_task_manifest(payload)
        proof = tool.build_full_corpus_proof(payload, tasks)

        self.assertTrue(proof["full_corpus_evaluated"])
        self.assertGreaterEqual(proof["total_candidate_rows"], 2)
        self.assertEqual(proof["source_counts"]["agent_recall"], 2)
        self.assertEqual(proof["detector_recall_closure_status"], "closed_for_current_local_evidence")
        self.assertEqual(proof["full_recall_closure_status"], "reduced_not_closed")
        self.assertEqual(proof["open_actionable_counts"]["source_proof_task"], 1)
        self.assertEqual(len(proof["remaining_open_tasks"]), 1)

    def test_full_corpus_proof_consumes_source_local_closure_artifact(self):
        ws = self.make_ws()
        audit = ws / ".auditooor"
        manifest = ws / "agent_outputs" / "bounded.manifest.json"
        manifest.parent.mkdir()
        manifest.write_text(
            json.dumps(
                {
                    "status": "no-counterexample",
                    "tests_passed": 1,
                    "tests_failed": 0,
                    "advisory": True,
                    "evidence_matrix_contributes": False,
                }
            ),
            encoding="utf-8",
        )
        (audit / "agent_found_not_detector_found.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "status": "source_proof_required",
                            "candidate_id": "SOURCE",
                            "agent_output": "agent_outputs/source.md",
                        },
                        {
                            "status": "harness_task_required",
                            "candidate_id": "LOCAL",
                            "agent_output": str(manifest),
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        (audit / "semantic_scanner_inventory.json").write_text(json.dumps({"detector_fixture_task_queue": []}), encoding="utf-8")
        provider = audit / "provider_result_local_verification.json"
        provider.write_text(json.dumps({"rows": []}), encoding="utf-8")
        (audit / "agent_recall_source_local_proof_closure.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "queue_id": "ARDQ-001",
                            "source_id": "source",
                            "terminal_state": "source_proof_terminal_blocked",
                            "action_lane": "source_proof_terminal_review",
                            "proof_status": "terminal_source_review_recorded",
                            "decision": "blocked_missing_candidate_bound_source_citation",
                            "reason": "no candidate-bound source proof",
                            "next_command": "provide candidate-bound project source",
                            "terminal_blockers": ["no_line_cited_project_source"],
                        },
                        {
                            "queue_id": "ARDQ-002",
                            "source_id": "local",
                            "terminal_state": "local_proof_recorded_terminal",
                            "action_lane": "local_proof_terminal_review",
                            "proof_status": "recorded_no-counterexample",
                            "decision": "local_proof_recorded_no_counterexample",
                            "reason": "bounded manifest exists",
                            "next_command": str(manifest),
                            "terminal_blockers": ["no_exact_impact_contract"],
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )

        payload = tool.build_queue(ws, limit=100, provider_paths=[provider])
        tasks = tool.build_task_manifest(payload)
        proof = tool.build_full_corpus_proof(payload, tasks)

        self.assertEqual(tasks["task_type_counts"]["source_proof_task"], 0)
        self.assertEqual(tasks["task_type_counts"]["local_proof_task"], 0)
        self.assertGreaterEqual(tasks["task_type_counts"]["terminal_blocker"], 2)
        self.assertEqual(proof["open_actionable_rows"], 0)
        self.assertEqual(proof["full_recall_closure_status"], "closed_for_current_local_evidence")
        decisions = {task.get("recall_closure_decision") for task in tasks["tasks"]}
        self.assertIn("local_proof_recorded_no_counterexample", decisions)
        self.assertIn("blocked_missing_candidate_bound_source_citation", decisions)

    def test_cli_full_corpus_writes_proof_artifacts(self):
        ws = self.make_ws()
        audit = ws / ".auditooor"
        (audit / "agent_found_not_detector_found.json").write_text(
            json.dumps({"rows": [{"status": "detectorized", "agent_output": "agent_outputs/done.md"}]}),
            encoding="utf-8",
        )
        (audit / "semantic_scanner_inventory.json").write_text(json.dumps({"detector_fixture_task_queue": []}), encoding="utf-8")
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--workspace",
                str(ws),
                "--full-corpus",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        proof_path = audit / "agent_recall_full_corpus_proof.json"
        self.assertTrue(proof_path.is_file())
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
        self.assertEqual(proof["detector_recall_closure_status"], "closed_for_current_local_evidence")
        self.assertGreaterEqual(proof["terminalized_or_bounded_rows"], 1)

    def test_stale_semantic_smoke_sidecar_does_not_count_as_detectorized(self):
        ws = self.make_ws()
        audit = ws / ".auditooor"
        (audit / "agent_found_not_detector_found.json").write_text(json.dumps({"rows": []}), encoding="utf-8")
        inventory = audit / "semantic_scanner_inventory.json"
        inventory.write_text(
            json.dumps(
                {
                    "detector_fixture_task_queue": [
                        {
                            "queue_id": "SSI-Q-STALE",
                            "task_type": "detector_rewrite_with_fixture_pair",
                            "scanner_inventory_status": "detector_task_routed",
                            "source_component": "Vault.withdraw",
                            "suggested_detector_slug": "vault_withdraw",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        smoke = audit / "semantic_detector_smoke_executor.json"
        smoke.write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "argument": "vault-withdraw",
                            "status": "passed_vulnerable_clean_smoke",
                            "positive_fixture": "fixtures/stale_vulnerable.sol",
                            "clean_fixture": "fixtures/stale_clean.sol",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        self.write_ws_file(ws, "fixtures/stale_vulnerable.sol", "contract V { function withdraw() external {} }\n")
        self.write_ws_file(ws, "fixtures/stale_clean.sol", "contract C { function withdraw() external {} }\n")
        newest_fixture = max((ws / "fixtures/stale_vulnerable.sol").stat().st_mtime, (ws / "fixtures/stale_clean.sol").stat().st_mtime)
        os.utime(smoke, (newest_fixture - 10, newest_fixture - 10))
        provider = audit / "provider_result_local_verification.json"
        provider.write_text(json.dumps({"rows": []}), encoding="utf-8")

        payload = tool.build_queue(ws, limit=50, provider_paths=[provider])
        row = next(row for row in payload["rows"] if row["source_id"] == "ssi-q-stale")

        self.assertEqual(row["terminal_state"], "detector_queue_ready")
        self.assertEqual(row["local_proof_status"], "skipped_coverage_requires_source_recheck")
        self.assertFalse(row["coverage_counted"])
        self.assertIn("stale_sidecar_older_than_referenced_file", row["coverage_skip_reasons"])
        self.assertGreaterEqual(payload["skipped_coverage_count"], 1)

    def test_recall_closure_with_hallucinated_file_line_does_not_close_task(self):
        ws = self.make_ws()
        audit = ws / ".auditooor"
        self.write_ws_file(ws, "contracts/Foo.sol", "contract Foo {\n}\n")
        manifest = self.write_ws_file(ws, "agent_outputs/bounded.manifest.json", json.dumps({"status": "no-counterexample"}))
        (audit / "agent_found_not_detector_found.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "status": "harness_task_required",
                            "candidate_id": "LOCAL",
                            "agent_output": "agent_outputs/local.md",
                            "claims_detected": ["contracts/Foo.sol:1"],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (audit / "semantic_scanner_inventory.json").write_text(json.dumps({"detector_fixture_task_queue": []}), encoding="utf-8")
        provider = audit / "provider_result_local_verification.json"
        provider.write_text(json.dumps({"rows": []}), encoding="utf-8")
        (audit / "agent_recall_source_local_proof_closure.json").write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "queue_id": "ARDQ-001",
                            "source_id": "local",
                            "terminal_state": "local_proof_recorded_terminal",
                            "action_lane": "local_proof_terminal_review",
                            "proof_status": "recorded_no-counterexample",
                            "decision": "local_proof_recorded_no_counterexample",
                            "reason": "bounded manifest exists",
                            "next_command": str(manifest),
                            "source_refs": ["contracts/Foo.sol:99"],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        payload = tool.build_queue(ws, limit=50, provider_paths=[provider])
        tasks = tool.build_task_manifest(payload)
        task = tasks["tasks"][0]
        proof = tool.build_full_corpus_proof(payload, tasks)

        self.assertTrue(task["recall_closure_skipped"])
        self.assertEqual(task["task_type"], "local_proof_task")
        self.assertEqual(task["terminal_state"], "local_proof_required")
        self.assertIn("source_ref_line_out_of_range:99>2", task["coverage_skip_reasons"])
        self.assertEqual(proof["full_recall_closure_status"], "reduced_not_closed")

    def test_provider_malformed_source_ref_routes_to_source_review_not_detector_task(self):
        ws = self.make_ws()
        audit = ws / ".auditooor"
        (audit / "agent_found_not_detector_found.json").write_text(json.dumps({"rows": []}), encoding="utf-8")
        (audit / "semantic_scanner_inventory.json").write_text(json.dumps({"detector_fixture_task_queue": []}), encoding="utf-8")
        provider = audit / "provider_result_local_verification.json"
        provider.write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "task_id": "P-MALFORMED",
                            "local_status": "source_file_confirmed",
                            "classifications": ["needs_fixture"],
                            "source_refs": ["contracts/Foo.sol"],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        payload = tool.build_queue(ws, limit=50, provider_paths=[provider])
        tasks = tool.build_task_manifest(payload)
        row = next(row for row in payload["rows"] if row["source_id"] == "p-malformed")

        self.assertEqual(row["terminal_state"], "source_proof_queue_ready")
        self.assertEqual(tasks["task_type_counts"]["detector_task"], 0)
        self.assertEqual(tasks["task_type_counts"]["source_proof_task"], 1)
        self.assertIn("malformed_source_ref_missing_line", row["coverage_skip_reasons"])

    def test_provider_source_hit_names_hallucinated_function(self):
        ws = self.make_ws()
        audit = ws / ".auditooor"
        self.write_ws_file(ws, "contracts/Foo.sol", "contract Foo { function realFunction() external {} }\n")
        (audit / "agent_found_not_detector_found.json").write_text(json.dumps({"rows": []}), encoding="utf-8")
        (audit / "semantic_scanner_inventory.json").write_text(json.dumps({"detector_fixture_task_queue": []}), encoding="utf-8")
        provider = audit / "provider_result_local_verification.json"
        provider.write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "task_id": "P-SYMBOL",
                            "local_status": "source_symbol_confirmed",
                            "classifications": ["local_grep_advisory"],
                            "source_paths": ["contracts/Foo.sol"],
                            "source_hits": [
                                {
                                    "path": "contracts/Foo.sol",
                                    "matched_symbols": ["phantomFunction"],
                                }
                            ],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        newest_source = (ws / "contracts/Foo.sol").stat().st_mtime
        os.utime(provider, (newest_source + 1, newest_source + 1))

        payload = tool.build_queue(ws, limit=50, provider_paths=[provider])
        row = next(row for row in payload["rows"] if row["source_id"] == "p-symbol")
        skipped = row["skipped_coverage"][0]

        self.assertEqual(row["terminal_state"], "source_proof_queue_ready")
        self.assertEqual(skipped["function"], "phantomFunction")
        self.assertEqual(skipped["reason"], "symbol_not_found_in_file")


if __name__ == "__main__":
    unittest.main()
