from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "queue-proof-hard-close.py"
SCHEMA = "auditooor.queue_proof_hard_close.v1"
NOW = 1_779_235_200.0  # 2026-05-20T00:00:00Z
DAY = 86_400.0


def _import_tool():
    spec = importlib.util.spec_from_file_location("queue_proof_hard_close_test", TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_json(path: Path, payload: object) -> None:
    if isinstance(payload, dict) and str(payload.get("schema") or "").startswith("auditooor.exploit_queue"):
        payload = dict(payload)
        payload.setdefault("queue_role", "candidate_leads")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _set_mtime(path: Path, days_ago: float) -> None:
    timestamp = NOW - days_ago * DAY
    os.utime(path, (timestamp, timestamp))


def _exploit_queue_row(lead_id: str = "EQ-001") -> dict[str, object]:
    return {
        "lead_id": lead_id,
        "title": "withdraw impact candidate",
        "attack_class": "access-control",
        "likely_severity": "medium",
        "blockers": [],
    }


def _strict_proved_manifest(candidate_id: str = "EQ-001") -> dict[str, object]:
    return {
        "schema_version": "auditooor.poc_execution_manifest.v1",
        "candidate_id": candidate_id,
        "final_result": "proved",
        "impact_assertion": "exploit_impact",
        "evidence_class": "executed_with_manifest",
        "commands_attempted": [
            {
                "command": "forge test --match-test testExploitImpact",
                "status": "pass",
                "exit_code": 0,
            }
        ],
        "updated_at_unix": NOW,
    }


def _typed_admitted_queue(mod, *, terminal: bool) -> dict[str, object]:
    parent = ["zdo-close", "zdr-close"]
    row: dict[str, object] = {
        **_exploit_queue_row("zdpq-close"),
        "obligation_id": parent[0],
        "revision_id": parent[1],
        "zero_day_proof_projection": {
            "schema": "auditooor.zero_day_proof_queue_projection.v1",
            "freeze_receipt_id": "a" * 64,
            "freeze_input_fingerprint": "b" * 64,
            "obligation_source_row_sha256": "c" * 64,
            "parent_ids": parent,
            "selection_ordinal": 1,
            "question_evidence": [{"question_id": "q0", "axis": "asset_invariant"}],
        },
        "zero_day_proof_admission": {
            "freeze_receipt_id": "a" * 64,
            "input_fingerprint": "b" * 64,
            "obligation_source_row_sha256": "c" * 64,
            "parent_ids": parent,
        },
    }
    payload: dict[str, object] = {
        "schema": "auditooor.exploit_queue.v1",
        "queue_role": "proof_tasks",
        "queue": [row],
        "entries": [],
        "zero_day_proof_admission": {
            "schema": "auditooor.zero_day_proof_admission.v1",
            "queue_role": "proof_tasks",
            "admission_id": "zdpa_" + "d" * 64,
            "input_queue_sha256": "e" * 64,
            "freeze_receipt_id": "a" * 64,
            "freeze_input_fingerprint": "b" * 64,
            "admitted_count": 1,
            "admitted_parents": [{"obligation_id": parent[0], "revision_id": parent[1]}],
        },
    }
    if terminal:
        entry = mod._load_typed_envelope_tool().build_envelope(payload)["entries"][0]
        row["terminal_join"] = {
            "schema": "auditooor.zero_day_proof_terminal_verdict.v1",
            "parent_ids": entry["parent_ids"],
            "envelope_id": entry["envelope_id"],
            "evidence_ref": "src/Close.sol:42",
        }
    return payload


class QueueProofHardCloseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _import_tool()

    def test_missing_workspace_returns_fail_closed_degraded_payload(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qphc-missing-") as tmp:
            missing = Path(tmp) / "missing-workspace"
            payload = self.mod.build_payload(missing, now_unix=NOW)

        self.assertEqual(payload["schema"], SCHEMA)
        self.assertTrue(payload["degraded"])
        self.assertEqual(payload["degraded_reason"], "workspace_missing")
        self.assertEqual(payload["rows"], [])
        self.assertFalse(payload["hard_close_complete"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(payload["promotion_allowed"])

    def test_strict_proved_execution_manifest_closes_exploit_queue_row_as_proved(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qphc-proved-") as tmp:
            ws = Path(tmp)
            _write_json(
                ws / ".auditooor" / "exploit_queue.json",
                {"schema": "auditooor.exploit_queue.v1", "queue": [_exploit_queue_row("EQ-001")]},
            )
            _write_json(
                ws / "poc_execution" / "EQ-001" / "execution_manifest.json",
                _strict_proved_manifest("EQ-001"),
            )

            payload = self.mod.build_payload(ws, now_unix=NOW)

        self.assertFalse(payload["degraded"])
        self.assertEqual(payload["summary"]["total_rows"], 1)
        self.assertEqual(payload["summary"]["proved_count"], 1)
        self.assertEqual(payload["summary"]["proof_counted"], 1)
        self.assertTrue(payload["hard_close_complete"])
        row = payload["rows"][0]
        self.assertEqual(row["row_key"], "exploit_queue:EQ-001")
        self.assertEqual(row["closeout_status"], "proved")
        self.assertTrue(row["proof_counted"])
        self.assertEqual(row["proof_blockers"], [])
        self.assertEqual(row["evidence_manifest_path"], "poc_execution/EQ-001/execution_manifest.json")
        self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(row["promotion_allowed"])

    def test_typed_queue_requires_exact_terminal_record_for_closeout_credit(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qphc-typed-terminal-") as tmp:
            ws = Path(tmp)
            queue_path = ws / ".auditooor" / "exploit_queue.zero_day_admitted.json"
            _write_json(queue_path, _typed_admitted_queue(self.mod, terminal=False))
            self.mod._load_typed_envelope_tool().materialize(
                ws, queue_path, ws / ".auditooor" / "zero_day_proof_envelope.json"
            )
            _write_json(
                ws / "poc_execution" / "zdpq-close" / "execution_manifest.json",
                _strict_proved_manifest("zdpq-close"),
            )

            open_payload = self.mod.build_payload(ws, now_unix=NOW)
            _write_json(queue_path, _typed_admitted_queue(self.mod, terminal=True))
            self.mod._load_typed_envelope_tool().materialize(
                ws, queue_path, ws / ".auditooor" / "zero_day_proof_envelope.json"
            )
            closed_payload = self.mod.build_payload(ws, now_unix=NOW)

        self.assertTrue(open_payload["inputs"]["exploit_queue"]["typed_proof_queue_selected"])
        self.assertEqual(open_payload["summary"]["proved_count"], 0)
        self.assertEqual(open_payload["summary"]["missing_evidence_count"], 1)
        open_row = open_payload["rows"][0]
        self.assertIn("typed_terminal_record_missing_or_mismatched", open_row["proof_blockers"])
        self.assertIsInstance(open_row["zero_day_proof_envelope"], dict)

        self.assertTrue(closed_payload["inputs"]["exploit_queue"]["typed_proof_queue_selected"])
        self.assertEqual(closed_payload["summary"]["proved_count"], 1)
        self.assertTrue(closed_payload["rows"][0]["proof_counted"])

    def test_typed_queue_identity_mutation_after_envelope_blocks_closeout(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qphc-typed-envelope-") as tmp:
            ws = Path(tmp)
            queue_path = ws / ".auditooor" / "exploit_queue.zero_day_admitted.json"
            payload = _typed_admitted_queue(self.mod, terminal=True)
            _write_json(queue_path, payload)
            self.mod._load_typed_envelope_tool().materialize(
                ws, queue_path, ws / ".auditooor" / "zero_day_proof_envelope.json"
            )
            payload["queue"][0]["zero_day_proof_projection"]["selection_ordinal"] = 2
            _write_json(queue_path, payload)
            with self.assertRaisesRegex(ValueError, "typed_proof_envelope_invalid"):
                self.mod.build_payload(ws, now_unix=NOW)

    def test_closeout_preserves_legacy_and_rejects_cross_stage_queue(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qphc-queue-role-") as tmp:
            ws = Path(tmp)
            queue_path = ws / ".auditooor" / "exploit_queue.json"
            queue_path.parent.mkdir(parents=True)
            queue_path.write_text(json.dumps({
                "schema": "auditooor.exploit_queue.v1",
                "queue": [_exploit_queue_row()],
            }), encoding="utf-8")
            self.assertEqual(1, self.mod.build_payload(ws, now_unix=NOW)["summary"]["total_rows"])

            queue_path.write_text(json.dumps({
                "schema": "auditooor.exploit_queue.v1",
                "queue_role": "proof_tasks",
                "queue": [_exploit_queue_row()],
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "exploit_queue_role_invalid:expected-candidate_leads"):
                self.mod.build_payload(ws, now_unix=NOW)

    def test_high_proved_manifest_without_impact_contract_and_live_witness_stays_missing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qphc-high-gated-") as tmp:
            ws = Path(tmp)
            _write_json(
                ws / ".auditooor" / "exploit_queue.json",
                {
                    "schema": "auditooor.exploit_queue.v1",
                    "queue_role": "candidate_leads",
                    "queue": [{**_exploit_queue_row("EQ-HIGH"), "likely_severity": "high"}],
                },
            )
            _write_json(
                ws / "poc_execution" / "EQ-HIGH" / "execution_manifest.json",
                _strict_proved_manifest("EQ-HIGH"),
            )

            payload = self.mod.build_payload(ws, now_unix=NOW)

        self.assertEqual(payload["summary"]["total_rows"], 1)
        self.assertEqual(payload["summary"]["proved_count"], 0)
        self.assertEqual(payload["summary"]["missing_evidence_count"], 1)
        row = payload["rows"][0]
        self.assertEqual(row["closeout_status"], "missing_evidence")
        self.assertFalse(row["proof_counted"])
        self.assertIn("proof_grade_gate_blocked", row["reasons"])
        self.assertIn("missing_complete_impact_contract", row["proof_blockers"])
        self.assertIn("missing_live_state_witness", row["proof_blockers"])

    def test_high_proved_manifest_with_impact_contract_and_live_witness_closes_as_proved(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qphc-high-gated-pass-") as tmp:
            ws = Path(tmp)
            _write_json(
                ws / ".auditooor" / "exploit_queue.json",
                {
                    "schema": "auditooor.exploit_queue.v1",
                    "queue_role": "candidate_leads",
                    "queue": [{**_exploit_queue_row("EQ-HIGH"), "likely_severity": "high"}],
                },
            )
            _write_json(
                ws / ".auditooor" / "impact_contracts.json",
                {
                    "schema": "auditooor.pr560.impact_contracts.v1",
                    "contracts": [
                        {
                            "candidate_id": "EQ-HIGH",
                            "impact_contract_id": "impact-contract-EQ-HIGH",
                            "exact_impact_row": True,
                            "selected_impact": "Stealing or loss of funds",
                            "severity_tier": "High",
                            "listed_impact_proven": True,
                            "evidence_class": "fork_replay",
                            "oos_traps": ["admin-only path excluded"],
                            "stop_condition": "stop if replay no longer loses funds",
                            "protocol_defenses_enumerated": ["nonce replay guard"],
                            "opposed_trace_required": True,
                            "opposed_trace_coverage": "covered",
                            "missing_defenses": [],
                            "negative_control": (
                                "defender wins: nonce replay guard rejects the replay; "
                                "defender absent: with the guard removed the replay drains funds"
                            ),
                        }
                    ],
                },
            )
            _write_json(
                ws / ".auditooor" / "live_state_witnesses.json",
                {
                    "schema": "auditooor.live_state_witnesses.v1",
                    "witnesses": [
                        {
                            "candidate_id": "EQ-HIGH",
                            "status": "complete",
                            "pinned_block": 123,
                            "rpc_url": "http://localhost:8545",
                            "current_state_diff": {"victim_balance_before": 10, "victim_balance_after": 0},
                        }
                    ],
                },
            )
            _write_json(
                ws / "poc_execution" / "EQ-HIGH" / "execution_manifest.json",
                _strict_proved_manifest("EQ-HIGH"),
            )

            payload = self.mod.build_payload(ws, now_unix=NOW)

        self.assertEqual(payload["summary"]["total_rows"], 1)
        self.assertEqual(payload["summary"]["proved_count"], 1)
        row = payload["rows"][0]
        self.assertEqual(row["closeout_status"], "proved")
        self.assertEqual(row["impact_contract_status"], "complete")
        self.assertEqual(row["live_state_witness_status"], "complete")
        self.assertEqual(row["proof_grade_gate_blockers"], [])

    def test_source_scoped_high_manifest_does_not_require_live_witness(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qphc-source-scoped-high-") as tmp:
            ws = Path(tmp)
            (ws / "SCOPE.md").write_text(
                "In scope: https://github.com/example/protocol runtime, pallets, and smart contracts\n",
                encoding="utf-8",
            )
            _write_json(
                ws / ".auditooor" / "exploit_queue.json",
                {
                    "schema": "auditooor.exploit_queue.v1",
                    "queue_role": "candidate_leads",
                    "queue": [{**_exploit_queue_row("EQ-HIGH"), "likely_severity": "high"}],
                },
            )
            _write_json(
                ws / ".auditooor" / "impact_contracts.json",
                {
                    "schema": "auditooor.pr560.impact_contracts.v1",
                    "contracts": [
                        {
                            "candidate_id": "EQ-HIGH",
                            "impact_contract_id": "impact-contract-EQ-HIGH",
                            "exact_impact_row": True,
                            "selected_impact": "Stealing or loss of funds",
                            "severity_tier": "High",
                            "listed_impact_proven": True,
                            "evidence_class": "local_source_harness",
                            "oos_traps": ["front-run-only paths excluded"],
                            "stop_condition": "stop if source harness does not lose funds",
                            "protocol_defenses_enumerated": ["nonce replay guard"],
                            "opposed_trace_required": True,
                            "opposed_trace_coverage": "covered",
                            "missing_defenses": [],
                            "negative_control": (
                                "defender wins: nonce replay guard rejects the replay; "
                                "defender absent: with the guard removed the replay drains funds"
                            ),
                        }
                    ],
                },
            )
            _write_json(
                ws / "poc_execution" / "EQ-HIGH" / "execution_manifest.json",
                _strict_proved_manifest("EQ-HIGH"),
            )

            payload = self.mod.build_payload(ws, now_unix=NOW)

        self.assertEqual(payload["summary"]["total_rows"], 1)
        self.assertEqual(payload["summary"]["proved_count"], 1)
        row = payload["rows"][0]
        self.assertEqual(row["closeout_status"], "proved")
        self.assertEqual(row["impact_contract_status"], "complete")
        self.assertEqual(row["live_state_witness_status"], "missing")
        self.assertFalse(row["live_state_witness_required"])
        self.assertEqual(row["proof_grade_gate_blockers"], [])

    def test_generic_smart_contract_scope_still_requires_live_witness(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qphc-generic-smart-contract-") as tmp:
            ws = Path(tmp)
            (ws / "SCOPE.md").write_text(
                "IN SCOPE VULNERABILITIES: Runtime, Pallets and Smart Contracts\n",
                encoding="utf-8",
            )
            _write_json(
                ws / ".auditooor" / "exploit_queue.json",
                {
                    "schema": "auditooor.exploit_queue.v1",
                    "queue_role": "candidate_leads",
                    "queue": [{**_exploit_queue_row("EQ-HIGH"), "likely_severity": "high"}],
                },
            )
            _write_json(
                ws / ".auditooor" / "impact_contracts.json",
                {
                    "schema": "auditooor.pr560.impact_contracts.v1",
                    "contracts": [
                        {
                            "candidate_id": "EQ-HIGH",
                            "impact_contract_id": "impact-contract-EQ-HIGH",
                            "exact_impact_row": True,
                            "selected_impact": "Stealing or loss of funds",
                            "severity_tier": "High",
                            "listed_impact_proven": True,
                            "evidence_class": "local_source_harness",
                            "oos_traps": ["front-run-only paths excluded"],
                            "stop_condition": "stop if source harness does not lose funds",
                            "protocol_defenses_enumerated": ["nonce replay guard"],
                            "opposed_trace_required": True,
                            "opposed_trace_coverage": "covered",
                            "missing_defenses": [],
                            "negative_control": (
                                "defender wins: nonce replay guard rejects the replay; "
                                "defender absent: with the guard removed the replay drains funds"
                            ),
                        }
                    ],
                },
            )
            _write_json(
                ws / "poc_execution" / "EQ-HIGH" / "execution_manifest.json",
                _strict_proved_manifest("EQ-HIGH"),
            )

            payload = self.mod.build_payload(ws, now_unix=NOW)

        row = payload["rows"][0]
        self.assertEqual(row["closeout_status"], "missing_evidence")
        self.assertTrue(row["live_state_witness_required"])
        self.assertIn("missing_live_state_witness", row["proof_grade_gate_blockers"])

    def test_policy_source_scoped_override_waives_live_witness(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qphc-policy-source-scoped-") as tmp:
            ws = Path(tmp)
            (ws / "SCOPE.md").write_text("Smart contracts in scope\n", encoding="utf-8")
            _write_json(
                ws / ".auditooor" / "scope_live_proof_policy.json",
                {"source_scoped": True, "requires_live_proof": False},
            )
            _write_json(
                ws / ".auditooor" / "exploit_queue.json",
                {
                    "schema": "auditooor.exploit_queue.v1",
                    "queue_role": "candidate_leads",
                    "queue": [{**_exploit_queue_row("EQ-HIGH"), "likely_severity": "high"}],
                },
            )
            _write_json(
                ws / ".auditooor" / "impact_contracts.json",
                {
                    "schema": "auditooor.pr560.impact_contracts.v1",
                    "contracts": [
                        {
                            "candidate_id": "EQ-HIGH",
                            "impact_contract_id": "impact-contract-EQ-HIGH",
                            "exact_impact_row": True,
                            "selected_impact": "Stealing or loss of funds",
                            "severity_tier": "High",
                            "listed_impact_proven": True,
                            "evidence_class": "local_source_harness",
                            "oos_traps": ["front-run-only paths excluded"],
                            "stop_condition": "stop if source harness does not lose funds",
                            "protocol_defenses_enumerated": ["nonce replay guard"],
                            "opposed_trace_required": True,
                            "opposed_trace_coverage": "covered",
                            "missing_defenses": [],
                            "negative_control": (
                                "defender wins: nonce replay guard rejects the replay; "
                                "defender absent: with the guard removed the replay drains funds"
                            ),
                        }
                    ],
                },
            )
            _write_json(
                ws / "poc_execution" / "EQ-HIGH" / "execution_manifest.json",
                _strict_proved_manifest("EQ-HIGH"),
            )

            payload = self.mod.build_payload(ws, now_unix=NOW)

        row = payload["rows"][0]
        self.assertEqual(row["closeout_status"], "proved")
        self.assertFalse(row["live_state_witness_required"])
        self.assertEqual(row["proof_grade_gate_blockers"], [])

    def test_advisory_oos_and_dupe_questions_are_not_proof_rows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qphc-advisory-skip-") as tmp:
            ws = Path(tmp)
            _write_json(
                ws / ".auditooor" / "exploit_queue.json",
                {
                    "schema": "auditooor.exploit_queue.v1",
                    "queue_role": "candidate_leads",
                    "queue": [
                        {
                            "lead_id": "EQ-OOS",
                            "title": "10. **Q-OOS-scope-md-1**: Advisory OOS check",
                            "proof_status": "needs_source",
                            "quality_gate_status": "needs_source",
                        },
                        {
                            "lead_id": "EQ-DUPE",
                            "title": "Q-DUPE: Does this candidate pass duplicate review?",
                            "proof_status": "needs_source",
                            "quality_gate_status": "needs_source",
                        },
                    ],
                },
            )

            payload = self.mod.build_payload(ws, now_unix=NOW)

        self.assertEqual(payload["summary"]["total_rows"], 0)
        self.assertEqual(payload["summary"]["missing_evidence_count"], 0)
        self.assertEqual(payload["summary"]["advisory_rows_skipped"], 2)
        self.assertTrue(payload["hard_close_complete"])

    def test_blocked_bridge_row_is_terminal_blocked_without_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qphc-blocked-") as tmp:
            ws = Path(tmp)
            _write_json(
                ws / ".auditooor" / "high_impact_execution_bridge.json",
                {
                    "schema_version": "auditooor.high_impact_execution_bridge.v1",
                    "rows": [
                        {
                            "row_id": "BASE-SC-I01",
                            "severity": "Critical",
                            "invariant_family": "proof-domain",
                            "bridge_status": "blocked_missing_impact_contract",
                            "runnable_harness": False,
                            "poc_execution_record_status": "blocked",
                            "poc_execution_record_path": "",
                            "poc_execution_record_blocked_reason": "missing_exact_impact_contract",
                        }
                    ],
                },
            )

            payload = self.mod.build_payload(ws, now_unix=NOW)

        self.assertEqual(payload["summary"]["total_rows"], 1)
        self.assertEqual(payload["summary"]["blocked_count"], 1)
        self.assertTrue(payload["hard_close_complete"])
        row = payload["rows"][0]
        self.assertEqual(row["row_key"], "high_impact_execution_bridge:BASE-SC-I01")
        self.assertEqual(row["closeout_status"], "blocked")
        self.assertFalse(row["proof_counted"])
        self.assertEqual(row["evidence_manifest_path"], "")
        self.assertIn("missing_exact_impact_contract", row["reasons"])

    def test_killed_source_proof_closes_exploit_queue_row_as_killed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qphc-source-kill-") as tmp:
            ws = Path(tmp)
            _write_json(
                ws / ".auditooor" / "exploit_queue.json",
                {"schema": "auditooor.exploit_queue.v1", "queue": [_exploit_queue_row("EQ-003")]},
            )
            _write_json(
                ws / "source_proofs" / "EQ-003" / "source_proof.json",
                {
                    "schema_version": "auditooor.source_proof.v1",
                    "candidate_id": "EQ-003",
                    "final_verdict": "killed",
                    "evidence_class": "generated_hypothesis",
                    "valid_source_citation_count": 2,
                    "source_citation_count": 2,
                    "blockers": [],
                    "updated_at_unix": NOW,
                },
            )

            payload = self.mod.build_payload(ws, now_unix=NOW)

        self.assertEqual(payload["summary"]["total_rows"], 1)
        self.assertEqual(payload["summary"]["killed_count"], 1)
        self.assertEqual(payload["summary"]["missing_evidence_count"], 0)
        self.assertEqual(payload["summary"]["source_proofs_seen"], 1)
        self.assertTrue(payload["hard_close_complete"])
        row = payload["rows"][0]
        self.assertEqual(row["row_key"], "exploit_queue:EQ-003")
        self.assertEqual(row["closeout_status"], "killed")
        self.assertEqual(row["evidence_manifest_path"], "source_proofs/EQ-003/source_proof.json")
        self.assertEqual(row["final_result"], "killed")
        self.assertIn("source_proof_killed", row["reasons"])

    def test_matched_source_kill_takes_precedence_over_loose_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qphc-matched-source-over-manifest-") as tmp:
            ws = Path(tmp)
            _write_json(
                ws / ".auditooor" / "exploit_queue.json",
                {"schema": "auditooor.exploit_queue.v1", "queue": [_exploit_queue_row("GET-FEE")]},
            )
            _write_json(
                ws / "poc_execution" / "GET-FEE" / "execution_manifest.json",
                {
                    "schema_version": "auditooor.poc_execution_manifest.v1",
                    "candidate_id": "GET-FEE",
                    "final_result": "needs_human",
                    "impact_assertion": "setup_or_branch_only",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": [
                        {
                            "command": "forge test --match-test testBranchOnly",
                            "status": "pass",
                            "exit_code": 0,
                        }
                    ],
                    "updated_at_unix": NOW,
                },
            )
            _write_json(
                ws / "source_proofs" / "GET-FEE" / "source_proof.json",
                {
                    "schema_version": "auditooor.source_proof.v1",
                    "candidate_id": "GET-FEE",
                    "final_verdict": "killed",
                    "evidence_class": "generated_hypothesis",
                    "valid_source_citation_count": 3,
                    "source_citation_count": 3,
                    "blockers": [],
                    "updated_at_unix": NOW,
                },
            )

            payload = self.mod.build_payload(ws, now_unix=NOW)

        self.assertEqual(payload["summary"]["total_rows"], 1)
        self.assertEqual(payload["summary"]["killed_count"], 1)
        self.assertEqual(payload["summary"]["missing_evidence_count"], 0)
        row = payload["rows"][0]
        self.assertEqual(row["row_key"], "exploit_queue:GET-FEE")
        self.assertEqual(row["closeout_status"], "killed")
        self.assertEqual(row["evidence_manifest_path"], "source_proofs/GET-FEE/source_proof.json")
        self.assertIn("source_proof_killed", row["reasons"])

    def test_source_mined_queue_is_selected_when_present(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qphc-source-mined-") as tmp:
            ws = Path(tmp)
            _write_json(
                ws / ".auditooor" / "exploit_queue.json",
                {"schema": "auditooor.exploit_queue.v1", "queue": [_exploit_queue_row("EQ-OLD")]},
            )
            _write_json(
                ws / ".auditooor" / "exploit_queue.source_mined.json",
                {"schema": "auditooor.exploit_queue.v1", "queue": [_exploit_queue_row("EQ-MINED")]},
            )
            _write_json(
                ws / "source_proofs" / "EQ-MINED" / "source_proof.json",
                {
                    "schema_version": "auditooor.source_proof.v1",
                    "candidate_id": "EQ-MINED",
                    "final_verdict": "killed",
                    "evidence_class": "generated_hypothesis",
                    "valid_source_citation_count": 1,
                    "source_citation_count": 1,
                    "blockers": [],
                    "updated_at_unix": NOW,
                },
            )

            payload = self.mod.build_payload(ws, now_unix=NOW)

        self.assertTrue(payload["inputs"]["exploit_queue"]["source_mined_selected"])
        self.assertEqual(payload["inputs"]["exploit_queue"]["path"], ".auditooor/exploit_queue.source_mined.json")
        self.assertEqual(payload["inputs"]["canonical_exploit_queue"]["row_count"], 1)
        self.assertEqual(payload["inputs"]["source_mined_exploit_queue"]["row_count"], 1)
        self.assertEqual(payload["summary"]["total_rows"], 1)
        self.assertEqual(payload["rows"][0]["row_key"], "exploit_queue:EQ-MINED")
        self.assertEqual(payload["rows"][0]["closeout_status"], "killed")

    def test_unmatched_local_execution_manifest_is_reported_as_first_class_row(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qphc-local-manifest-") as tmp:
            ws = Path(tmp)
            _write_json(
                ws / ".auditooor" / "exploit_queue.json",
                {"schema": "auditooor.exploit_queue.v1", "queue": [_exploit_queue_row("EQ-OLD")]},
            )
            _write_json(
                ws / "poc_execution" / "GET-REAL" / "execution_manifest.json",
                {
                    "schema_version": "auditooor.poc_execution_manifest.v1",
                    "candidate_id": "GET-REAL",
                    "final_result": "needs_human",
                    "impact_assertion": "setup_or_branch_only",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": [
                        {
                            "command": "forge test --match-test testRealCandidate",
                            "status": "pass",
                            "exit_code": 0,
                        }
                    ],
                    "updated_at_unix": NOW,
                },
            )

            payload = self.mod.build_payload(ws, now_unix=NOW)

        self.assertEqual(payload["summary"]["total_rows"], 2)
        local_rows = [row for row in payload["rows"] if row["row_kind"] == "local_poc_execution"]
        self.assertEqual(len(local_rows), 1)
        row = local_rows[0]
        self.assertEqual(row["row_key"], "local_poc_execution:GET-REAL")
        self.assertEqual(row["closeout_status"], "missing_evidence")
        self.assertEqual(row["poc_execution_record_status"], "present_unmatched_to_queue")
        self.assertIn("unmatched_local_poc_execution", row["reasons"])
        self.assertIn("execution_manifest_not_terminal", row["reasons"])

    def test_unmatched_local_source_proof_is_reported_as_first_class_row(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qphc-local-source-proof-") as tmp:
            ws = Path(tmp)
            _write_json(
                ws / ".auditooor" / "exploit_queue.json",
                {"schema": "auditooor.exploit_queue.v1", "queue": [_exploit_queue_row("EQ-OLD")]},
            )
            _write_json(
                ws / "source_proofs" / "SOURCE-ONLY-AUTH" / "source_proof.json",
                {
                    "schema_version": "auditooor.source_proof.v1",
                    "candidate_id": "SOURCE-ONLY-AUTH",
                    "final_verdict": "killed",
                    "evidence_class": "generated_hypothesis",
                    "valid_source_citation_count": 4,
                    "source_citation_count": 4,
                    "blockers": [],
                    "updated_at_unix": NOW,
                },
            )

            payload = self.mod.build_payload(ws, now_unix=NOW)

        local_rows = [row for row in payload["rows"] if row["row_kind"] == "local_source_proof"]
        self.assertEqual(len(local_rows), 1)
        row = local_rows[0]
        self.assertEqual(row["row_key"], "local_source_proof:SOURCE-ONLY-AUTH")
        self.assertEqual(row["closeout_status"], "killed")
        self.assertIn("unmatched_local_source_proof", row["reasons"])
        self.assertIn("source_proof_killed", row["reasons"])

    def test_unmatched_source_kill_takes_precedence_over_loose_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qphc-local-source-over-manifest-") as tmp:
            ws = Path(tmp)
            _write_json(
                ws / ".auditooor" / "exploit_queue.json",
                {"schema": "auditooor.exploit_queue.v1", "queue": [_exploit_queue_row("EQ-OLD")]},
            )
            _write_json(
                ws / "poc_execution" / "RELAYER-U256-TRUNCATION" / "execution_manifest.json",
                {
                    "schema_version": "auditooor.poc_execution_manifest.v1",
                    "candidate_id": "RELAYER-U256-TRUNCATION",
                    "final_result": "needs_human",
                    "impact_assertion": "not_demonstrated",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": [
                        {
                            "command": "python3 proof_model.py",
                            "status": "pass",
                            "exit_code": 0,
                        }
                    ],
                    "updated_at_unix": NOW,
                },
            )
            _write_json(
                ws / "source_proofs" / "RELAYER-U256-TRUNCATION" / "source_proof.json",
                {
                    "schema_version": "auditooor.source_proof.v1",
                    "candidate_id": "RELAYER-U256-TRUNCATION",
                    "final_verdict": "killed",
                    "evidence_class": "generated_hypothesis",
                    "valid_source_citation_count": 5,
                    "source_citation_count": 5,
                    "blockers": [],
                    "updated_at_unix": NOW,
                },
            )

            payload = self.mod.build_payload(ws, now_unix=NOW)

        relayer_rows = [row for row in payload["rows"] if row["row_id"] == "RELAYER-U256-TRUNCATION"]
        self.assertEqual(len(relayer_rows), 1)
        row = relayer_rows[0]
        self.assertEqual(row["row_kind"], "local_source_proof")
        self.assertEqual(row["closeout_status"], "killed")
        self.assertEqual(row["evidence_manifest_path"], "source_proofs/RELAYER-U256-TRUNCATION/source_proof.json")

    def test_stale_expected_missing_bridge_evidence_stays_missing_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qphc-stale-") as tmp:
            ws = Path(tmp)
            bridge_path = ws / ".auditooor" / "high_impact_execution_bridge.json"
            _write_json(
                bridge_path,
                {
                    "schema_version": "auditooor.high_impact_execution_bridge.v1",
                    "rows": [
                        {
                            "row_id": "BASE-DLT-I01",
                            "severity": "High",
                            "invariant_family": "withdrawals-root",
                            "bridge_status": "scaffolded_ready_for_execution_record",
                            "runnable_harness": True,
                            "poc_execution_record_status": "expected_missing",
                            "poc_execution_record_path": str(
                                ws / "poc_execution" / "base-dlt-i01" / "execution_manifest.json"
                            ),
                            "poc_execution_record_blocked_reason": "",
                        }
                    ],
                },
            )
            _set_mtime(bridge_path, days_ago=10)

            payload = self.mod.build_payload(ws, now_unix=NOW, stale_days=7)

        self.assertEqual(payload["summary"]["missing_evidence_count"], 1)
        self.assertEqual(payload["summary"]["stale_evidence_count"], 1)
        self.assertFalse(payload["hard_close_complete"])
        row = payload["rows"][0]
        self.assertEqual(row["closeout_status"], "missing_evidence")
        self.assertTrue(row["stale_evidence"])
        self.assertIn("missing_poc_execution_manifest", row["proof_blockers"])
        self.assertIn("stale_missing_execution_evidence", row["reasons"])

    def test_claimed_proved_without_strict_evidence_is_missing_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qphc-weak-proof-") as tmp:
            ws = Path(tmp)
            _write_json(
                ws / ".auditooor" / "exploit_queue.json",
                {"schema": "auditooor.exploit_queue.v1", "queue": [_exploit_queue_row("EQ-002")]},
            )
            weak = _strict_proved_manifest("EQ-002")
            weak["evidence_class"] = "scaffolded_unverified"
            weak["commands_attempted"] = [
                {
                    "command": "forge test --match-test testExploitImpact",
                    "status": "recorded_without_execution",
                    "exit_code": None,
                }
            ]
            _write_json(ws / "poc_execution" / "EQ-002" / "execution_manifest.json", weak)

            payload = self.mod.build_payload(ws, now_unix=NOW)

        row = payload["rows"][0]
        self.assertEqual(row["closeout_status"], "missing_evidence")
        self.assertFalse(row["proof_counted"])
        self.assertIn("claimed_proved_but_strict_evidence_missing", row["reasons"])
        self.assertIn("evidence_class_executed_with_manifest", row["proof_blockers"])
        self.assertIn("commands_attempted_pass_exit_0", row["proof_blockers"])

    def test_changed_bound_source_loses_strict_proof_credit(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qphc-bound-source-") as tmp:
            ws = Path(tmp)
            source = ws / "src" / "agent.oscript"
            source.parent.mkdir(parents=True)
            source.write_text("v1", encoding="utf-8")
            manifest = _strict_proved_manifest("EQ-BOUND-SOURCE")
            manifest["bound_sources"] = [
                {
                    "path": "src/agent.oscript",
                    "sha256": hashlib.sha256(b"v1").hexdigest(),
                    "size": 2,
                }
            ]
            manifest_path = ws / "poc_execution" / "EQ-BOUND-SOURCE" / "execution_manifest.json"
            _write_json(manifest_path, manifest)
            source.write_text("v2", encoding="utf-8")

            row = self.mod._manifest_status(manifest, manifest_path, ws, NOW, 7)

        self.assertEqual(row["closeout_status"], "missing_evidence")
        self.assertFalse(row["proof_counted"])
        self.assertIn("bound_source_hash_mismatch", row["bound_source_blockers"])
        self.assertIn("bound_source_binding_blocked", row["reasons"])


    # ------------------------------------------------------------------
    # HACKERMAN_V3 opposed-trace proof gate (POINT 2)
    # ------------------------------------------------------------------
    def _opposed_contract(self, **over) -> dict:
        contract = {
            "candidate_id": "EQ-HIGH",
            "impact_contract_id": "impact-contract-EQ-HIGH",
            "exact_impact_row": True,
            "selected_impact": "Direct loss of user funds",
            "severity_tier": "High",
            "listed_impact_proven": True,
            "evidence_class": "fork_replay",
            "oos_traps": ["admin-only path excluded"],
            "stop_condition": "stop if replay no longer loses funds",
            "protocol_defenses_enumerated": ["lower-timelock connector refund", "watchtower path"],
            "opposed_trace_required": True,
            "opposed_trace_coverage": "covered",
            "missing_defenses": [],
            "negative_control": (
                "defender wins: lower-timelock refund recovers the funds; "
                "defender absent: with the refund path removed the attacker drains funds"
            ),
        }
        contract.update(over)
        return contract

    def _write_high_workspace(self, ws: Path, contract: dict) -> None:
        _write_json(
            ws / ".auditooor" / "scope_live_proof_policy.json",
            {"source_scoped": True, "requires_live_proof": False},
        )
        _write_json(
            ws / ".auditooor" / "exploit_queue.json",
            {
                "schema": "auditooor.exploit_queue.v1",
                "queue_role": "candidate_leads",
                "queue": [{**_exploit_queue_row("EQ-HIGH"), "likely_severity": "high"}],
            },
        )
        _write_json(
            ws / ".auditooor" / "impact_contracts.json",
            {"schema": "auditooor.pr560.impact_contracts.v1", "contracts": [contract]},
        )
        _write_json(
            ws / "poc_execution" / "EQ-HIGH" / "execution_manifest.json",
            _strict_proved_manifest("EQ-HIGH"),
        )

    def test_opposed_trace_empty_defenses_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qphc-opp-empty-") as tmp:
            ws = Path(tmp)
            self._write_high_workspace(
                ws,
                self._opposed_contract(
                    protocol_defenses_enumerated=[],
                    opposed_trace_coverage="missing",
                ),
            )
            payload = self.mod.build_payload(ws, now_unix=NOW)
        row = payload["rows"][0]
        self.assertEqual(row["closeout_status"], "missing_evidence")
        self.assertFalse(row["proof_counted"])
        self.assertIn("unopposed_trace_high_plus", row["proof_grade_gate_blockers"])

    def test_opposed_trace_required_but_not_covered_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qphc-opp-uncovered-") as tmp:
            ws = Path(tmp)
            self._write_high_workspace(
                ws,
                self._opposed_contract(
                    opposed_trace_coverage="missing",
                    missing_defenses=["watchtower path"],
                ),
            )
            payload = self.mod.build_payload(ws, now_unix=NOW)
        row = payload["rows"][0]
        self.assertEqual(row["closeout_status"], "missing_evidence")
        self.assertIn("unopposed_trace_high_plus", row["proof_grade_gate_blockers"])

    def test_opposed_trace_missing_defender_control_variants_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qphc-opp-controls-") as tmp:
            ws = Path(tmp)
            self._write_high_workspace(
                ws,
                self._opposed_contract(
                    negative_control="consumed exit txid is rejected",
                ),
            )
            payload = self.mod.build_payload(ws, now_unix=NOW)
        row = payload["rows"][0]
        self.assertEqual(row["closeout_status"], "missing_evidence")
        self.assertIn(
            "opposed_trace_missing_defender_wins_control", row["proof_grade_gate_blockers"]
        )
        self.assertIn(
            "opposed_trace_missing_defender_absent_control", row["proof_grade_gate_blockers"]
        )

    def test_opposed_trace_fully_covered_closes_as_proved(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qphc-opp-covered-") as tmp:
            ws = Path(tmp)
            self._write_high_workspace(ws, self._opposed_contract())
            payload = self.mod.build_payload(ws, now_unix=NOW)
        row = payload["rows"][0]
        self.assertEqual(row["closeout_status"], "proved")
        self.assertTrue(row["proof_counted"])
        self.assertEqual(row["proof_grade_gate_blockers"], [])

    def test_opposed_trace_not_applied_to_non_high_plus_row(self) -> None:
        # A medium-severity row with a non-fund-loss impact is not subject to
        # the opposed-trace gate even with an empty-defenses contract.
        with tempfile.TemporaryDirectory(prefix="qphc-opp-nonhigh-") as tmp:
            ws = Path(tmp)
            _write_json(
                ws / ".auditooor" / "exploit_queue.json",
                {
                    "schema": "auditooor.exploit_queue.v1",
                    "queue_role": "candidate_leads",
                    "queue": [{**_exploit_queue_row("EQ-MED"), "likely_severity": "medium"}],
                },
            )
            _write_json(
                ws / ".auditooor" / "impact_contracts.json",
                {
                    "schema": "auditooor.pr560.impact_contracts.v1",
                    "contracts": [
                        {
                            "candidate_id": "EQ-MED",
                            "impact_contract_id": "impact-contract-EQ-MED",
                            "exact_impact_row": True,
                            "selected_impact": "Event emitted in wrong order",
                            "severity_tier": "Medium",
                            "listed_impact_proven": True,
                            "evidence_class": "local_source_harness",
                            "oos_traps": ["cosmetic-only excluded"],
                            "stop_condition": "stop if event order is unchanged",
                        }
                    ],
                },
            )
            _write_json(
                ws / "poc_execution" / "EQ-MED" / "execution_manifest.json",
                _strict_proved_manifest("EQ-MED"),
            )
            payload = self.mod.build_payload(ws, now_unix=NOW)
        row = payload["rows"][0]
        self.assertNotIn("unopposed_trace_high_plus", row["proof_grade_gate_blockers"])
        self.assertEqual(row["closeout_status"], "proved")

    def test_opposed_trace_advisory_on_non_high_plus_freeze_row(self) -> None:
        # Tiered model: a non-HIGH+ (Medium) freeze-class row with an
        # unopposed-trace contract gets an advisory_unopposed_trace ADVISORY
        # (non-blocking) - the row still hard-closes as proved, but the
        # advisory stays visible to the operator.
        with tempfile.TemporaryDirectory(prefix="qphc-opp-med-adv-") as tmp:
            ws = Path(tmp)
            _write_json(
                ws / ".auditooor" / "exploit_queue.json",
                {
                    "schema": "auditooor.exploit_queue.v1",
                    "queue_role": "candidate_leads",
                    "queue": [{**_exploit_queue_row("EQ-MED"), "likely_severity": "medium"}],
                },
            )
            _write_json(
                ws / ".auditooor" / "impact_contracts.json",
                {
                    "schema": "auditooor.pr560.impact_contracts.v1",
                    "contracts": [
                        {
                            "candidate_id": "EQ-MED",
                            "impact_contract_id": "impact-contract-EQ-MED",
                            "exact_impact_row": True,
                            "selected_impact": "Temporary freezing of user funds",
                            "severity_tier": "Medium",
                            "listed_impact_proven": True,
                            "evidence_class": "local_source_harness",
                            "oos_traps": ["cosmetic-only excluded"],
                            "stop_condition": "stop if funds unfreeze",
                            "protocol_defenses_enumerated": [],
                            "opposed_trace_coverage": "missing",
                            "contract_advisories": ["opposed_trace_defenses_unenumerated"],
                        }
                    ],
                },
            )
            _write_json(
                ws / "poc_execution" / "EQ-MED" / "execution_manifest.json",
                _strict_proved_manifest("EQ-MED"),
            )
            payload = self.mod.build_payload(ws, now_unix=NOW)
        row = payload["rows"][0]
        # Advisory, not a blocker - the row still hard-closes as proved.
        self.assertNotIn("unopposed_trace_high_plus", row["proof_grade_gate_blockers"])
        self.assertEqual(row["proof_grade_gate_blockers"], [])
        self.assertIn("advisory_unopposed_trace", row["proof_grade_gate_advisories"])
        self.assertEqual(row["closeout_status"], "proved")
        self.assertTrue(row["proof_counted"])


if __name__ == "__main__":
    unittest.main()
