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
TOOL = ROOT / "tools" / "candidate-judgment-packet.py"
MAKEFILE = ROOT / "Makefile"


def _load_tool():
    spec = importlib.util.spec_from_file_location("candidate_judgment_packet", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["candidate_judgment_packet"] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def complete_row() -> dict:
    return {
        "lead_id": "EQ-OK",
        "title": "Public withdraw drains user funds",
        "likely_severity": "High",
        "attack_class": "withdrawal-accounting",
        "contract": "Vault",
        "function_name": "withdraw(uint256)",
        "permissionless_action": "Any address calls withdraw(uint256) through VaultRouter.",
        "admin_or_team_dependency": "none",
        "offchain_dependency_status": "none",
        "rubric_row": "Direct theft of any user funds",
        "dupe_triple": "contract=Vault | function=withdraw(uint256) | attack_class=withdrawal-accounting",
        "profit_loss": "attacker receives victim principal; victim loses 100 assets",
        "capital_lock": "no capital lock beyond gas",
        "gas_slippage_time_cost": "single transaction gas only",
        "attacker_actor": "fresh unprivileged account",
        "victim_actor": "third-party depositor",
        "source_refs": ["contracts/Vault.sol:120"],
        "execution_window": "NO_EXECUTION_WINDOW_RELEVANCE: single public call; anchor=contracts/Vault.sol:120",
        "required_evidence_class": "end_to_end_runtime",
        "dupe_risk": "low",
        "mcp_context_ids": ["auditooor.vault_context_pack.v1:test"],
        "lesson_pack_refs": ["auditooor.lesson_pack.v1:test"],
    }


def write_source(path: Path, line_count: int = 140) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"// source line {i}\n" for i in range(1, line_count + 1)), encoding="utf-8")


def write_proof(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("contract ProofHarness {}\n", encoding="utf-8")


def assert_no_workspace_absolute(testcase: unittest.TestCase, payload: dict, workspace: Path) -> None:
    testcase.assertNotIn(str(workspace.resolve()), json.dumps(payload, sort_keys=True))


class CandidateJudgmentPacketTests(unittest.TestCase):
    def test_empty_workspace_emits_valid_schema(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            payload = tool.build_packet(Path(td))
            self.assertEqual(payload["schema"], tool.SCHEMA)
            self.assertEqual(payload["summary"]["packets_emitted"], 0)
            self.assertTrue(payload["advisory_only"])
            self.assertFalse(payload["promotion_authority"])

    def test_exploit_queue_entries_row_emits_packet_when_queue_empty(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [], "entries": [complete_row()]})
            payload = tool.build_packet(ws)
            self.assertEqual(payload["summary"]["queue_rows_seen"], 1)
            self.assertEqual(payload["summary"]["packets_emitted"], 1)
            self.assertEqual(payload["packets"][0]["candidate_id"], "EQ-OK")

    def test_default_queue_prefers_newer_canonical_over_stale_source_mined(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            canonical = ws / ".auditooor" / "exploit_queue.json"
            source_mined = ws / ".auditooor" / "exploit_queue.source_mined.json"
            write_json(canonical, {"queue": [complete_row()]})
            write_json(source_mined, {"queue": [{"lead_id": "EQ-STALE", "title": "stale row", "likely_severity": "High"}]})
            os.utime(source_mined, (1_700_000_000, 1_700_000_000))
            os.utime(canonical, (1_800_000_000, 1_800_000_000))

            payload = tool.build_packet(ws)
            self.assertEqual(payload["summary"]["packets_emitted"], 1)
            self.assertEqual(payload["packets"][0]["candidate_id"], "EQ-OK")
            self.assertEqual(
                payload["source_artifacts"]["exploit_queue"]["path"],
                f"{ws.name}/.auditooor/exploit_queue.json",
            )
            self.assertIn(
                "exploit_queue.source_mined.json_ignored_as_stale_or_equal_age",
                payload["source_artifacts"]["exploit_queue"]["selection_diagnostic"],
            )

    def test_missing_prefiling_truth_blocks_high_packet(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [{"lead_id": "EQ-001", "likely_severity": "High", "title": "Unknown high"}]})
            payload = tool.build_packet(ws)
            packet = payload["packets"][0]
            self.assertEqual(packet["packet_state"], "blocked_missing_truth")
            self.assertEqual(packet["verdict"], "blocked_before_poc")
            self.assertIn("verdict", packet["required_judgment_fields"])
            self.assertEqual(payload["summary"]["blocked_before_poc_count"], 1)
            self.assertFalse(payload["summary"]["strict_poc_planning_allowed"])
            self.assertEqual(payload["strict_blockers"][0]["candidate_id"], "EQ-001")

    def test_typed_admitted_queue_preserves_exact_envelope_in_packet(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            row = complete_row()
            row.update({
                "lead_id": "zdpq_typed",
                "obligation_id": "zdo_parent",
                "revision_id": "zdr_revision",
                "zero_day_proof_projection": {
                    "schema": "auditooor.zero_day_proof_queue_projection.v1",
                    "freeze_receipt_id": "a" * 64,
                    "freeze_input_fingerprint": "b" * 64,
                    "obligation_source_row_sha256": "c" * 64,
                    "parent_ids": ["zdo_parent", "zdr_revision"],
                    "selection_ordinal": 1,
                    "question_evidence": [{"question_id": "q0", "axis": "asset_invariant"}],
                },
                "zero_day_proof_admission": {
                    "freeze_receipt_id": "a" * 64,
                    "input_fingerprint": "b" * 64,
                    "obligation_source_row_sha256": "c" * 64,
                    "parent_ids": ["zdo_parent", "zdr_revision"],
                },
            })
            write_json(ws / ".auditooor" / "exploit_queue.json", {
                "schema": "auditooor.exploit_queue.v1",
                "queue_role": "proof_tasks",
                "queue": [row],
                "entries": [],
                "zero_day_proof_admission": {
                    "schema": "auditooor.zero_day_proof_admission.v1",
                    "queue_role": "proof_tasks",
                    "admission_id": "zdpa_" + "d" * 64,
                    "freeze_receipt_id": "a" * 64,
                    "freeze_input_fingerprint": "b" * 64,
                    "input_queue_sha256": "e" * 64,
                    "admitted_count": 1,
                    "admitted_parents": [{"obligation_id": "zdo_parent", "revision_id": "zdr_revision"}],
                },
            })
            queue = ws / ".auditooor" / "exploit_queue.json"
            tool._load_typed_envelope_tool().materialize(
                ws, queue, ws / ".auditooor" / "zero_day_proof_envelope.json",
            )
            payload = tool.build_packet(ws)

        self.assertEqual(1, payload["summary"]["typed_proof_envelope_packet_count"])
        envelope = payload["packets"][0]["zero_day_proof_envelope"]
        self.assertEqual("zdpq_typed", envelope["lead_id"])
        self.assertEqual(["zdo_parent", "zdr_revision"], envelope["parent_ids"])
        self.assertTrue(envelope["envelope_id"].startswith("zdpe_"))

    def test_typed_queue_rejects_stale_persisted_envelope_before_terminal_filtering(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            row = complete_row()
            row.update({
                "lead_id": "zdpq_typed_stale",
                "obligation_id": "zdo_parent",
                "revision_id": "zdr_revision",
                "zero_day_proof_projection": {
                    "schema": "auditooor.zero_day_proof_queue_projection.v1",
                    "freeze_receipt_id": "a" * 64,
                    "freeze_input_fingerprint": "b" * 64,
                    "obligation_source_row_sha256": "c" * 64,
                    "parent_ids": ["zdo_parent", "zdr_revision"],
                    "selection_ordinal": 1,
                    "question_evidence": [{"question_id": "q0", "axis": "asset_invariant"}],
                },
                "zero_day_proof_admission": {
                    "freeze_receipt_id": "a" * 64,
                    "input_fingerprint": "b" * 64,
                    "obligation_source_row_sha256": "c" * 64,
                    "parent_ids": ["zdo_parent", "zdr_revision"],
                },
            })
            queue = ws / ".auditooor" / "exploit_queue.json"
            payload = {
                "schema": "auditooor.exploit_queue.v1",
                "queue_role": "proof_tasks",
                "queue": [row],
                "entries": [],
                "zero_day_proof_admission": {
                    "schema": "auditooor.zero_day_proof_admission.v1",
                    "queue_role": "proof_tasks",
                    "admission_id": "zdpa_" + "d" * 64,
                    "freeze_receipt_id": "a" * 64,
                    "freeze_input_fingerprint": "b" * 64,
                    "input_queue_sha256": "e" * 64,
                    "admitted_count": 1,
                    "admitted_parents": [{"obligation_id": "zdo_parent", "revision_id": "zdr_revision"}],
                },
            }
            write_json(queue, payload)
            tool._load_typed_envelope_tool().materialize(
                ws, queue, ws / ".auditooor" / "zero_day_proof_envelope.json",
            )
            payload["queue"][0]["zero_day_proof_projection"]["selection_ordinal"] = 2
            write_json(queue, payload)
            with self.assertRaisesRegex(ValueError, "typed_proof_envelope_invalid"):
                tool.build_packet(ws)

    def test_source_mined_artifact_is_typed_primary_read_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            row = {
                "lead_id": "EQ-SOURCE",
                "likely_severity": "High",
                "title": "Source-mined candidate",
                "source_artifacts_complete": True,
                "source_refs": ["contracts/Vault.sol:120"],
            }
            receipts = tool._worker_receipts(row, {}, {}, ws)
            self.assertEqual(
                receipts["typed_no_lesson_pack_reasons"],
                ["NO_LESSON_PACK_REASON: source-mined artifact with current source citations is the primary read receipt"],
            )
            self.assertFalse(receipts["invalid_no_lesson_pack_reasons"])

    def test_terminal_rows_do_not_block_strict_packet(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            write_json(
                ws / ".auditooor" / "exploit_queue.json",
                {
                    "queue": [
                        {
                            "lead_id": "EQ-KILLED",
                            "likely_severity": "High",
                            "title": "Killed local candidate",
                            "proof_status": "killed",
                            "source_mined_proof_status": "killed",
                            "quality_gate_status": "closed_negative_operator_review",
                            "learning_route": "drop",
                            "negative_control": "contracts/Vault.sol:120 reverts under the clean control",
                        }
                    ]
                },
            )
            payload = tool.build_packet(ws)

            self.assertEqual(payload["summary"]["queue_rows_seen"], 0)
            self.assertEqual(payload["summary"]["blocked_before_poc_count"], 0)
            self.assertTrue(payload["summary"]["strict_poc_planning_allowed"])

    def test_unknown_severity_local_blocker_is_not_strict_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            write_json(
                ws / ".auditooor" / "exploit_queue.json",
                {
                    "queue": [
                        {
                            "lead_id": "EQ-UNKNOWN",
                            "likely_severity": "unknown",
                            "title": "Corpus fuel needs later review",
                            "dupe_risk": "not_checked",
                        }
                    ]
                },
            )
            payload = tool.build_packet(ws)

            self.assertEqual(payload["summary"]["local_blocked_packet_count"], 1)
            self.assertEqual(payload["summary"]["blocked_before_poc_count"], 0)
            self.assertEqual(payload["strict_blockers"], [])
            self.assertTrue(payload["summary"]["strict_poc_planning_allowed"])

    def test_explicit_non_proof_high_rows_do_not_block_strict_poc_planning(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            write_json(
                ws / ".auditooor" / "exploit_queue.json",
                {
                    "queue": [{
                        "lead_id": "EQ-COVERAGE",
                        "likely_severity": "High",
                        "title": "Coverage fuel, not a proof candidate",
                        "proof_relevance": False,
                        "proof_relevance_status": "skipped_non_proof",
                    }]
                },
            )
            payload = tool.build_packet(ws)

            self.assertEqual(payload["summary"]["local_blocked_packet_count"], 1)
            self.assertEqual(payload["summary"]["blocked_before_poc_count"], 0)
            self.assertEqual(payload["summary"]["strict_excluded_non_proof_count"], 1)
            self.assertTrue(payload["summary"]["strict_poc_planning_allowed"])

    def test_strict_cli_fails_when_packet_is_blocked_before_poc(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            queue = ws / ".auditooor" / "exploit_queue.json"
            out_json = ws / ".auditooor" / "packet.json"
            write_json(queue, {"queue": [{"lead_id": "EQ-001", "likely_severity": "High", "title": "Unknown high"}]})

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--queue",
                    str(queue),
                    "--out-json",
                    str(out_json),
                    "--strict",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 1)
            self.assertIn("STRICT blocked 1 packet", proc.stderr)
            saved = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(saved["summary"]["blocked_before_poc_count"], 1)

    def test_full_typed_fields_are_ready_for_poc_planning(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [complete_row()]})
            write_json(
                ws / ".auditooor" / "prefiling_stress_test.json",
                {
                    "results": [
                        {
                            "candidate_id": "EQ-OK",
                            "verdict": "pass",
                            "evidence_plan": {"required_evidence_class": ["end_to_end_runtime"]},
                            "questions": {
                                "prior_disclosure": {"status": "clean"},
                                "economics": {"status": "pass"},
                                "privileged_or_mock_dependency": {"status": "pass", "flags": []},
                            },
                        }
                    ]
                },
            )
            payload = tool.build_packet(ws)
            packet = payload["packets"][0]
            self.assertEqual(packet["packet_state"], "ready_for_poc_planning")
            self.assertEqual(packet["verdict"], "ready_for_poc_planning")
            self.assertIn("end_to_end_runtime", packet["required_evidence_class"])
            self.assertTrue(packet["field_source_anchors"]["permissionless_trigger"])
            self.assertEqual(payload["summary"]["blocked_before_poc_count"], 0)
            self.assertTrue(payload["summary"]["strict_poc_planning_allowed"])

    def test_positive_finalization_verdict_with_current_source_and_proof_is_proof_ready(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            row = complete_row()
            row["finalization_verdict"] = "finalized"
            row["poc_path"] = "poc-tests/EQOK.t.sol"
            row["pass_evidence_lines"] = ["Suite result: ok. 1 passed; 0 failed"]
            write_source(ws / "contracts" / "Vault.sol")
            write_proof(ws / "poc-tests" / "EQOK.t.sol")
            write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [row]})

            payload = tool.build_packet(ws)
            packet = payload["packets"][0]
            self.assertEqual(packet["packet_state"], "ready_for_poc_planning")
            self.assertEqual(packet["proof_readiness"]["state"], "proof_ready")
            self.assertEqual(packet["proof_readiness"]["current_workspace_source_refs"], [f"{ws.name}/contracts/Vault.sol:120"])
            self.assertEqual(packet["proof_readiness"]["proof_artifacts"], [f"{ws.name}/poc-tests/EQOK.t.sol"])
            self.assertEqual(payload["summary"]["proof_ready_count"], 1)

    def test_positive_proof_verdict_missing_source_ref_is_not_proof_ready(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            row = complete_row()
            row.pop("source_refs")
            row["official_source_url_or_hash"] = "sha256:test"
            row["proof_verdict"] = "pass"
            row["poc_path"] = "poc-tests/EQOK.t.sol"
            row["pass_evidence_lines"] = ["--- PASS: TestExploit"]
            write_proof(ws / "poc-tests" / "EQOK.t.sol")
            write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [row]})

            payload = tool.build_packet(ws)
            packet = payload["packets"][0]
            self.assertEqual(packet["packet_state"], "blocked_weak_proof")
            self.assertEqual(packet["proof_readiness"]["state"], "not_proof_ready")
            self.assertIn("missing_current_workspace_source_ref", packet["proof_readiness"]["typed_reasons"])
            self.assertIn("proof_readiness:missing_current_workspace_source_ref", packet["promotion_blockers"])
            self.assertEqual(payload["summary"]["proof_not_ready_count"], 1)

    def test_positive_proof_verdict_stale_workspace_source_ref_is_not_proof_ready(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            row = complete_row()
            row["source_refs"] = ["contracts/MissingVault.sol:8"]
            row["proof_verdict"] = "confirmed"
            row["poc_path"] = "poc-tests/EQOK.t.sol"
            row["pass_evidence_lines"] = ["PASS TestExploit"]
            write_proof(ws / "poc-tests" / "EQOK.t.sol")
            write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [row]})

            payload = tool.build_packet(ws)
            packet = payload["packets"][0]
            self.assertEqual(packet["packet_state"], "blocked_weak_proof")
            self.assertEqual(packet["proof_readiness"]["state"], "not_proof_ready")
            self.assertIn(
                f"stale_workspace_source_ref:{ws.name}/contracts/MissingVault.sol:8",
                packet["proof_readiness"]["typed_reasons"],
            )
            self.assertNotEqual(packet["proof_readiness"]["state"], "proof_ready")

    def test_advisory_only_candidate_with_positive_proof_claim_is_not_proof_ready(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            row = complete_row()
            row["advisory_only"] = True
            row["proof_verdict"] = "pass"
            row["poc_path"] = "poc-tests/EQOK.t.sol"
            row["pass_evidence_lines"] = ["--- PASS: TestExploit"]
            write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [row]})

            payload = tool.build_packet(ws)
            packet = payload["packets"][0]
            self.assertEqual(packet["packet_state"], "ready_for_poc_planning")
            self.assertEqual(packet["proof_readiness"]["state"], "advisory_only")
            self.assertIn("advisory_only_candidate:exploit_queue.advisory_only", packet["proof_readiness"]["typed_reasons"])
            self.assertNotEqual(packet["proof_readiness"]["state"], "proof_ready")

    def test_blocked_candidate_propagates_to_proof_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            row = complete_row()
            row["proof_verdict"] = "pass"
            row["poc_path"] = "poc-tests/EQOK.t.sol"
            row["pass_evidence_lines"] = ["--- PASS: TestExploit"]
            write_source(ws / "contracts" / "Vault.sol")
            write_proof(ws / "poc-tests" / "EQOK.t.sol")
            write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [row]})
            write_json(ws / ".auditooor" / "exploit_severity_scope_oracle.json", {"candidate_id": "EQ-OK", "scope_status": "oos_risk"})

            payload = tool.build_packet(ws)
            packet = payload["packets"][0]
            self.assertEqual(packet["packet_state"], "blocked_by_scope")
            self.assertEqual(packet["proof_readiness"]["state"], "blocked")
            self.assertIn("blocked_candidate:blocked_by_scope", packet["proof_readiness"]["typed_reasons"])
            self.assertIn("scope_status_oos_risk", packet["proof_readiness"]["typed_reasons"])
            self.assertNotEqual(packet["proof_readiness"]["state"], "proof_ready")

    def test_high_packet_mcp_context_only_blocks_missing_lesson_or_source_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            row = complete_row()
            row.pop("lesson_pack_refs")
            write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [row]})
            write_json(
                ws / ".auditooor" / "prefiling_stress_test.json",
                {
                    "results": [
                        {
                            "candidate_id": "EQ-OK",
                            "verdict": "pass",
                            "evidence_plan": {"required_evidence_class": ["end_to_end_runtime"]},
                            "questions": {
                                "prior_disclosure": {"status": "clean"},
                                "economics": {"status": "pass"},
                                "privileged_or_mock_dependency": {"status": "pass", "flags": []},
                            },
                        }
                    ]
                },
            )

            payload = tool.build_packet(ws)
            packet = payload["packets"][0]
            self.assertEqual(packet["packet_state"], "blocked_missing_truth")
            self.assertIn("missing:lesson_pack_or_source_read_receipt", packet["promotion_blockers"])
            self.assertTrue(packet["worker_receipts"]["missing_worker_receipt_warning"])
            self.assertEqual(packet["worker_receipts"]["mcp_context_ids"], ["auditooor.vault_context_pack.v1:test"])
            self.assertFalse(payload["summary"]["strict_poc_planning_allowed"])

    def test_high_packet_accepts_typed_no_lesson_pack_reason(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            row = complete_row()
            row.pop("lesson_pack_refs")
            row["no_lesson_pack_reason"] = "NO_LESSON_PACK_REASON: source-free queue hygiene review only"
            write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [row]})
            write_json(
                ws / ".auditooor" / "prefiling_stress_test.json",
                {
                    "results": [
                        {
                            "candidate_id": "EQ-OK",
                            "verdict": "pass",
                            "evidence_plan": {"required_evidence_class": ["end_to_end_runtime"]},
                            "questions": {
                                "prior_disclosure": {"status": "clean"},
                                "economics": {"status": "pass"},
                                "privileged_or_mock_dependency": {"status": "pass", "flags": []},
                            },
                        }
                    ]
                },
            )

            payload = tool.build_packet(ws)
            packet = payload["packets"][0]
            self.assertEqual(packet["packet_state"], "ready_for_poc_planning")
            self.assertNotIn("missing:lesson_pack_or_source_read_receipt", packet["promotion_blockers"])
            self.assertEqual(
                packet["worker_receipts"]["typed_no_lesson_pack_reasons"],
                ["NO_LESSON_PACK_REASON: source-free queue hygiene review only"],
            )
            self.assertTrue(payload["summary"]["strict_poc_planning_allowed"])

    def test_metadata_only_chain_packet_blocks_as_weak_proof(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            row = complete_row()
            row["chain_id"] = "CHAIN-001"
            row["causal_evidence_level"] = "metadata_overlap_only_unproven"
            row["metadata_overlap_only"] = True
            write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [row]})
            write_json(
                ws / ".auditooor" / "prefiling_stress_test.json",
                {
                    "results": [
                        {
                            "candidate_id": "EQ-OK",
                            "verdict": "pass",
                            "evidence_plan": {"required_evidence_class": ["end_to_end_runtime"]},
                            "questions": {
                                "prior_disclosure": {"status": "clean"},
                                "economics": {"status": "pass"},
                                "privileged_or_mock_dependency": {"status": "pass", "flags": []},
                            },
                        }
                    ]
                },
            )

            payload = tool.build_packet(ws)
            packet = payload["packets"][0]
            self.assertEqual(packet["packet_state"], "blocked_weak_proof")
            self.assertIn(
                "chain_causal_evidence_metadata_overlap_only_unproven",
                packet["promotion_blockers"],
            )
            self.assertFalse(payload["summary"]["strict_poc_planning_allowed"])

    def test_distinct_chain_with_open_d4_gaps_blocks_as_weak_proof(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            row = complete_row()
            row["chain_id"] = "CHAIN-D4"
            row["causal_evidence_level"] = "distinct_bridge_signal_present"
            row["metadata_overlap_only"] = False
            row["source_artifacts_complete"] = False
            row["source_artifact_gaps"] = ["attacker_control", "clean_control", "harness"]
            row["attacker_control"] = "partial"
            row["proof_path"] = "manual-source"
            write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [row]})
            write_json(
                ws / ".auditooor" / "prefiling_stress_test.json",
                {
                    "results": [
                        {
                            "candidate_id": "EQ-OK",
                            "verdict": "pass",
                            "evidence_plan": {"required_evidence_class": ["end_to_end_runtime"]},
                            "questions": {
                                "prior_disclosure": {"status": "clean"},
                                "economics": {"status": "pass"},
                                "privileged_or_mock_dependency": {"status": "pass", "flags": []},
                            },
                        }
                    ]
                },
            )

            payload = tool.build_packet(ws)
            packet = payload["packets"][0]
            self.assertEqual(packet["packet_state"], "blocked_weak_proof")
            self.assertNotIn(
                "chain_causal_evidence_metadata_overlap_only_unproven",
                packet["promotion_blockers"],
            )
            self.assertIn("chain_d4_missing_negative_or_clean_control", packet["promotion_blockers"])
            self.assertIn("chain_d4_missing_harness_or_source_proof_artifact", packet["promotion_blockers"])
            self.assertFalse(payload["summary"]["strict_poc_planning_allowed"])

    def test_distinct_chain_rejects_generic_attacker_control_values(self) -> None:
        generic_values = (
            "partial",
            "partial-privilege",
            "needs_review_privileged_surface",
            "All 3 plan-level blockers must be resolved before filing",
            "Partial attacker control required - see hop preconditions",
        )

        for attacker_control in generic_values:
            with self.subTest(attacker_control=attacker_control):
                with tempfile.TemporaryDirectory() as td:
                    ws = Path(td)
                    row = complete_row()
                    row["chain_id"] = "CHAIN-D4"
                    row["causal_evidence_level"] = "distinct_bridge_signal_present"
                    row["metadata_overlap_only"] = False
                    row["source_artifacts_complete"] = True
                    row["source_artifact_gaps"] = []
                    row["attacker_control"] = attacker_control
                    row["required_control"] = "Unprivileged caller reaches all hops"
                    row["negative_control"] = "Clean run without vulnerable hop does not change victim balance"
                    row["proof_path"] = "poc-tests/chain/chain_d4.t.sol"
                    proof_path = ws / "poc-tests" / "chain" / "chain_d4.t.sol"
                    proof_path.parent.mkdir(parents=True)
                    proof_path.write_text("contract ChainD4Proof {}\n", encoding="utf-8")
                    write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [row]})
                    write_json(
                        ws / ".auditooor" / "prefiling_stress_test.json",
                        {
                            "results": [
                                {
                                    "candidate_id": "EQ-OK",
                                    "verdict": "pass",
                                    "evidence_plan": {"required_evidence_class": ["end_to_end_runtime"]},
                                    "questions": {
                                        "prior_disclosure": {"status": "clean"},
                                        "economics": {"status": "pass"},
                                        "privileged_or_mock_dependency": {"status": "pass", "flags": []},
                                    },
                                }
                            ]
                        },
                    )

                    payload = tool.build_packet(ws)
                    packet = payload["packets"][0]
                    self.assertEqual(packet["packet_state"], "blocked_weak_proof")
                    self.assertIn("chain_d4_missing_attacker_control_evidence", packet["promotion_blockers"])
                    self.assertFalse(payload["summary"]["strict_poc_planning_allowed"])

    def test_distinct_chain_requires_source_anchor_not_just_proof_precedent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            row = complete_row()
            row["chain_id"] = "CHAIN-D4"
            row["causal_evidence_level"] = "distinct_bridge_signal_present"
            row["metadata_overlap_only"] = False
            row["source_refs"] = []
            row["proof_artifact_precedent_refs"] = ["poc-tests/chain/chain_d4.t.sol"]
            row["attacker_control"] = "known"
            row["negative_control"] = "clean run without vulnerable hop does not change victim balance"
            row["proof_path"] = "poc-tests/chain/chain_d4.t.sol"
            write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [row]})
            write_json(
                ws / ".auditooor" / "prefiling_stress_test.json",
                {
                    "results": [
                        {
                            "candidate_id": "EQ-OK",
                            "verdict": "pass",
                            "evidence_plan": {"required_evidence_class": ["end_to_end_runtime"]},
                            "questions": {
                                "prior_disclosure": {"status": "clean"},
                                "economics": {"status": "pass"},
                                "privileged_or_mock_dependency": {"status": "pass", "flags": []},
                            },
                        }
                    ]
                },
            )

            payload = tool.build_packet(ws)
            packet = payload["packets"][0]
            self.assertEqual(packet["packet_state"], "blocked_weak_proof")
            self.assertIn("chain_d4_missing_source_anchor", packet["promotion_blockers"])
            self.assertFalse(payload["summary"]["strict_poc_planning_allowed"])

    def test_distinct_chain_with_closed_d4_artifacts_can_plan_poc(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            row = complete_row()
            row["chain_id"] = "CHAIN-D4"
            row["causal_evidence_level"] = "distinct_bridge_signal_present"
            row["metadata_overlap_only"] = False
            row["source_artifacts_complete"] = True
            row["source_artifact_gaps"] = []
            row["attacker_control"] = "known"
            row["required_control"] = "Unprivileged caller reaches all hops"
            row["negative_control"] = "Clean run without vulnerable hop does not change victim balance"
            row["proof_path"] = "poc-tests/chain/chain_d4.t.sol"
            proof_path = ws / "poc-tests" / "chain" / "chain_d4.t.sol"
            proof_path.parent.mkdir(parents=True)
            proof_path.write_text("contract ChainD4Proof {}\n", encoding="utf-8")
            write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [row]})
            write_json(
                ws / ".auditooor" / "prefiling_stress_test.json",
                {
                    "results": [
                        {
                            "candidate_id": "EQ-OK",
                            "verdict": "pass",
                            "evidence_plan": {"required_evidence_class": ["end_to_end_runtime"]},
                            "questions": {
                                "prior_disclosure": {"status": "clean"},
                                "economics": {"status": "pass"},
                                "privileged_or_mock_dependency": {"status": "pass", "flags": []},
                            },
                        }
                    ]
                },
            )

            payload = tool.build_packet(ws)
            packet = payload["packets"][0]
            self.assertEqual(packet["packet_state"], "ready_for_poc_planning")
            self.assertNotIn(
                "chain_causal_evidence_metadata_overlap_only_unproven",
                packet["promotion_blockers"],
            )
            self.assertTrue(payload["summary"]["strict_poc_planning_allowed"])

    def test_distinct_chain_with_nonexistent_proof_path_stays_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            row = complete_row()
            row["chain_id"] = "CHAIN-D4"
            row["causal_evidence_level"] = "distinct_bridge_signal_present"
            row["metadata_overlap_only"] = False
            row["source_artifacts_complete"] = True
            row["source_artifact_gaps"] = []
            row["attacker_control"] = "known"
            row["required_control"] = "Unprivileged caller reaches all hops"
            row["negative_control"] = "Clean run without vulnerable hop does not change victim balance"
            row["proof_path"] = "poc-tests/chain/chain_d4.t.sol"
            write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [row]})
            write_json(
                ws / ".auditooor" / "prefiling_stress_test.json",
                {
                    "results": [
                        {
                            "candidate_id": "EQ-OK",
                            "verdict": "pass",
                            "evidence_plan": {"required_evidence_class": ["end_to_end_runtime"]},
                            "questions": {
                                "prior_disclosure": {"status": "clean"},
                                "economics": {"status": "pass"},
                                "privileged_or_mock_dependency": {"status": "pass", "flags": []},
                            },
                        }
                    ]
                },
            )

            payload = tool.build_packet(ws)
            packet = payload["packets"][0]
            self.assertEqual(packet["packet_state"], "blocked_weak_proof")
            self.assertIn("chain_d4_missing_harness_or_source_proof_artifact", packet["promotion_blockers"])
            self.assertFalse(payload["summary"]["strict_poc_planning_allowed"])

    def test_scope_oracle_blocks_scope_risk(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            row = complete_row()
            write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [row]})
            write_json(ws / ".auditooor" / "exploit_severity_scope_oracle.json", {"candidate_id": "EQ-OK", "scope_status": "oos_risk"})
            payload = tool.build_packet(ws)
            self.assertEqual(payload["packets"][0]["packet_state"], "blocked_by_scope")

    def test_oracle_high_dupe_risk_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [complete_row()]})
            write_json(ws / ".auditooor" / "exploit_severity_scope_oracle.json", {"candidate_id": "EQ-OK", "dupe_risk": "high"})
            payload = tool.build_packet(ws)
            self.assertEqual(payload["packets"][0]["packet_state"], "blocked_prior_disclosure")

    def test_falsification_disproved_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [complete_row()]})
            write_json(ws / ".auditooor" / "poc_falsification_runner.json", {"candidate_id": "EQ-OK", "verdict": "disproved"})
            payload = tool.build_packet(ws)
            self.assertEqual(payload["packets"][0]["packet_state"], "blocked_by_falsification")

    def test_inconclusive_falsification_with_open_blockers_blocks_weak_proof(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [complete_row()]})
            write_json(
                ws / ".auditooor" / "poc_falsification_runner.json",
                {"candidate_id": "EQ-OK", "verdict": "inconclusive", "open_blockers": ["missing negative control"]},
            )
            payload = tool.build_packet(ws)
            self.assertEqual(payload["packets"][0]["packet_state"], "blocked_weak_proof")

    def test_dupe_requires_structured_triple_not_status_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            row = complete_row()
            row.pop("dupe_triple")
            row["dupe_risk"] = "low"
            write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [row]})
            payload = tool.build_packet(ws)
            packet = payload["packets"][0]
            self.assertEqual(packet["packet_state"], "ready_for_poc_planning")
            self.assertIn("contract=Vault", packet["required_judgment_fields"]["dupe_triple"])

    def test_status_like_dupe_triple_does_not_satisfy_structured_triple(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            row = complete_row()
            row["dupe_triple"] = "not_checked"
            row.pop("contract")
            row.pop("function_name")
            write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [row]})
            payload = tool.build_packet(ws)
            self.assertIn("missing:dupe_triple", payload["packets"][0]["promotion_blockers"])

    def test_value_extraction_tags_trigger_economics_requirement(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            row = complete_row()
            row["tags"] = ["reward extraction"]
            for key in ("profit_loss", "capital_lock", "gas_slippage_time_cost"):
                row.pop(key)
            write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [row]})
            payload = tool.build_packet(ws)
            blockers = payload["packets"][0]["promotion_blockers"]
            self.assertIn("missing:economics_range", blockers)
            self.assertIn("missing:capital_lock", blockers)

    def test_high_packet_requires_execution_window_or_explicit_no_window_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            row = complete_row()
            row.pop("execution_window")
            row.pop("source_refs")
            write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [row]})
            payload = tool.build_packet(ws)
            self.assertIn("missing:execution_window", payload["packets"][0]["promotion_blockers"])

    def test_timestamp_tag_requires_execution_window_not_no_window_skip(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            row = complete_row()
            row["tags"] = ["timestamp"]
            row.pop("execution_window")
            write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [row]})
            payload = tool.build_packet(ws)
            self.assertIn("missing:execution_window", payload["packets"][0]["promotion_blockers"])

    def test_bounded_refs_and_cli_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            row = complete_row()
            row["source_refs"] = [str((ws / "contracts" / "Vault.sol").resolve()) + f":{i}" for i in range(20)]
            row["permissionless_action"] = f"Any address calls {(ws / 'contracts' / 'Vault.sol').resolve()}:120."
            queue = ws / ".auditooor" / "exploit_queue.json"
            out_json = ws / ".auditooor" / "packet.json"
            out_md = ws / ".auditooor" / "packet.md"
            write_json(queue, {"queue": [row]})

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--queue",
                    str(queue),
                    "--out-json",
                    str(out_json),
                    "--out-md",
                    str(out_md),
                    "--json",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            parsed = json.loads(proc.stdout)
            saved = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertTrue(out_json.is_file())
            self.assertTrue(out_md.is_file())
            self.assertLessEqual(len(parsed["packets"][0]["source_refs"]), 8)
            self.assertEqual(saved["workspace"], ws.name)
            self.assertEqual(saved["artifact_path"], f"{ws.name}/.auditooor/packet.json")
            self.assertEqual(saved["markdown_path"], f"{ws.name}/.auditooor/packet.md")
            self.assertEqual(saved["source_artifacts"]["exploit_queue"]["path"], f"{ws.name}/.auditooor/exploit_queue.json")
            self.assertEqual(parsed["packets"][0]["source_refs"][0], f"{ws.name}/contracts/Vault.sol:0")
            self.assertIn(f"{ws.name}/contracts/Vault.sol:120", parsed["packets"][0]["required_judgment_fields"]["permissionless_trigger"])
            assert_no_workspace_absolute(self, parsed, ws)
            assert_no_workspace_absolute(self, saved, ws)

    def test_shared_packet_sanitizes_absolute_local_paths_in_refs_and_fields(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            source = (ws / "src" / "Vault.sol").resolve()
            row = complete_row()
            row["source_refs"] = [f"{source}:44", "https://example.com/advisory"]
            row["execution_window"] = f"NO_EXECUTION_WINDOW_RELEVANCE: anchor={source}:44"
            row["required_evidence_class"] = f"runtime proof at {source}:44"
            row["lesson_pack_refs"] = [f"{source}:lesson"]
            write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [row]})

            payload = tool.build_packet(ws)
            packet = payload["packets"][0]
            self.assertEqual(packet["source_refs"][0], f"{ws.name}/src/Vault.sol:44")
            self.assertEqual(packet["source_refs"][1], "https://example.com/advisory")
            self.assertIn(f"{ws.name}/src/Vault.sol:44", packet["required_judgment_fields"]["execution_window"])
            self.assertIn(f"{ws.name}/src/Vault.sol:44", packet["required_evidence_class"])
            self.assertIn(f"{ws.name}/src/Vault.sol:lesson", packet["worker_receipts"]["lesson_pack_refs"])
            assert_no_workspace_absolute(self, payload, ws)

    def test_makefile_exposes_target(self) -> None:
        text = MAKEFILE.read_text(encoding="utf-8")
        self.assertIn("candidate-judgment-packet:", text)
        self.assertIn("candidate-judgment-packet-test:", text)
        self.assertIn("tools/candidate-judgment-packet.py", text)
        self.assertIn("$(if $(filter 1 true yes,$(STRICT)),--strict)", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
