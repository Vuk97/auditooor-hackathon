"""Tests for tools/prove-top-leads.py."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "prove-top-leads.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("prove_top_leads", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = _load_module()


def _link_fixed_bypass_awareness(workspace: Path, queue: Path) -> None:
    """Attach the only awareness disposition that can enter proof conversion."""
    source_types = sorted(M.E._awareness_validator().SOURCE_TYPES)
    pin_hash = "b" * 64
    sources = [{
        "source_id": f"source-{index}",
        "source_type": source_type,
        "status": "reviewed",
        "team_awareness": "fixed_bypass",
        "repository": "example/repository",
        "source_commit": "c" * 40,
        "audit_pin_sha256": pin_hash,
        "stable_ref": f"stable-{index}",
        "snapshot_sha256": f"{index + 1:x}" * 64,
        "review_receipt": {"receipt_id": f"review-{index}", "reviewer": "test"},
    } for index, source_type in enumerate(source_types)]
    receipt = {
        "schema": "auditooor.awareness_admission_receipt.v1",
        "receipt_id": "test-awareness-receipt",
        "audit_pin": {"commit": "a" * 40, "pin_sha256": pin_hash},
        "source_inventory": {
            "status": "complete", "coverage_status": "complete",
            "expected_source_types": source_types, "sources": sources,
        },
        "semantic_decisions": [{
            "decision_id": "fixed-bypass-1",
            "classification": "fixed_bypass",
            "source_ids": [source["source_id"] for source in sources],
            "rationale": "current-pin semantic review",
            "root_cause": "the historical remediation is bypassable at the audit pin",
            "affected_execution_path": "the cited production execution path",
            "required_remediation": "the missing remediation primitive",
            "evidence": {
                "fix_verification": "bypass_at_current_pin",
                "exact_source_ref": "src/Ok.sol:1",
                "exact_exploit_ref": "poc/FixedBypass.t.sol:1",
            },
        }],
    }
    receipt_path = workspace / ".auditooor" / "awareness-receipt.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    payload = json.loads(queue.read_text(encoding="utf-8"))
    for row in payload["queue"]:
        row["awareness_receipt_path"] = ".auditooor/awareness-receipt.json"
        row["awareness_decision_id"] = "fixed-bypass-1"
    queue.write_text(json.dumps(payload), encoding="utf-8")


def _typed_queue(*, terminal: bool) -> dict:
    parent = ["zdo-proof", "zdr-proof"]
    row = {
        "lead_id": "zdpq-proof",
        "proof_status": "killed",
        "quality_gate_status": "closed_negative_source_proof",
        "source_proof_path": "source_proofs/zdpq-proof/source_proof.json",
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
    queue = {
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
        entry = M._load_typed_envelope_tool().build_envelope(queue)["entries"][0]
        row["terminal_join"] = {
            "schema": "auditooor.zero_day_proof_terminal_verdict.v1",
            "parent_ids": entry["parent_ids"],
            "envelope_id": entry["envelope_id"],
            "evidence_ref": "src/Proof.sol:42",
        }
    return queue


class TestProveTopLeads(unittest.TestCase):
    def test_queue_semantics_reject_bad_rows_and_keep_valid_rows_advisory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="prove-top-leads-") as td:
            ws = Path(td) / "ws"
            aud = ws / ".auditooor"
            (ws / "src").mkdir(parents=True)
            (ws / "test").mkdir()
            aud.mkdir()
            (ws / "src" / "Ok.sol").write_text("contract Ok {}\n", encoding="utf-8")
            (ws / "test" / "Ready.t.sol").write_text("contract ReadyTest {}\n", encoding="utf-8")
            queue = aud / "exploit_queue.source_mined.json"
            queue.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.exploit_queue.v1",
                        "queue": [
                            {
                                "lead_id": "VALID",
                                "title": "current source but no harness yet",
                                "likely_severity": "high",
                                "source_refs": ["src/Ok.sol:1"],
                            },
                            {
                                "lead_id": "ADVISORY",
                                "title": "advisory row",
                                "advisory_only": True,
                                "source_refs": ["src/Ok.sol:1"],
                            },
                            {
                                "lead_id": "MISSING",
                                "title": "missing source refs",
                            },
                            {
                                "lead_id": "STALE",
                                "title": "stale source ref",
                                "source_refs": ["src/Missing.sol:1"],
                            },
                            {
                                "lead_id": "BLOCKED",
                                "title": "blocked candidate",
                                "proof_status": "needs_harness",
                                "source_refs": ["src/Ok.sol:1"],
                            },
                            {
                                "lead_id": "CLAIMED",
                                "title": "claimed proof without harness",
                                "proof_verdict": "proof-backed",
                                "source_refs": ["src/Ok.sol:1"],
                            },
                            {
                                "lead_id": "READY",
                                "title": "proof row with runnable harness",
                                "proof_verdict": "proof-backed",
                                "proof_path": "test/Ready.t.sol",
                                "source_refs": ["src/Ok.sol:1"],
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            harness_queue = aud / "harness_execution_queue_from_exploit_queue.json"
            harness_queue.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.harness_execution_queue.v0",
                        "ready_commands": [
                            {
                                "row_id": "READY",
                                "command_status": "ready_now",
                                "command": "forge test --match-path test/Ready.t.sol -vv",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            _link_fixed_bypass_awareness(ws, queue)

            payload = M.assess_queue(
                workspace=ws,
                queue_path=queue,
                harness_queue_path=harness_queue,
                top_n=10,
            )

            rows = {row["row_id"]: row for row in payload["rows"]}
            self.assertEqual(rows["VALID"]["decision"], "advisory_only")
            self.assertEqual(rows["ADVISORY"]["decision"], "rejected")
            self.assertIn("advisory_only_row", rows["ADVISORY"]["rejection_reasons"])
            self.assertEqual(rows["MISSING"]["decision"], "rejected")
            self.assertIn("missing_source_refs", rows["MISSING"]["rejection_reasons"])
            self.assertEqual(rows["STALE"]["decision"], "rejected")
            self.assertIn("stale_workspace_source_refs", rows["STALE"]["rejection_reasons"])
            self.assertEqual(rows["BLOCKED"]["decision"], "rejected")
            self.assertIn("blocked_candidate", rows["BLOCKED"]["rejection_reasons"])
            self.assertEqual(rows["CLAIMED"]["decision"], "rejected")
            self.assertIn(
                "proof_without_runnable_harness_evidence",
                rows["CLAIMED"]["rejection_reasons"],
            )
            self.assertEqual(rows["READY"]["decision"], "proof_ready")
            self.assertTrue(rows["READY"]["has_runnable_harness_evidence"])
            self.assertEqual(payload["rejected_count"], 5)
            self.assertEqual(payload["advisory_count"], 1)
            self.assertEqual(payload["proof_ready_count"], 1)

    def test_terminal_negative_rows_are_not_relabelled_advisory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="prove-top-leads-terminal-") as td:
            ws = Path(td) / "ws"
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            (ws / "src").mkdir()
            (ws / "src" / "Live.sol").write_text("contract Live {}\n", encoding="utf-8")
            queue = aud / "exploit_queue.source_mined.json"
            queue.write_text(
                json.dumps({
                    "queue": [
                        {
                            "lead_id": "KILLED",
                            "proof_status": "killed",
                            "quality_gate_status": "closed_negative_source_proof",
                            "source_proof_path": "source_proofs/KILLED/source_proof.json",
                        },
                        {"lead_id": "OPEN", "source_refs": ["src/Live.sol:1"]},
                    ]
                }),
                encoding="utf-8",
            )
            _link_fixed_bypass_awareness(ws, queue)
            payload = M.assess_queue(workspace=ws, queue_path=queue, top_n=10)
            self.assertEqual(payload["terminal_rows_skipped"], 1)
            self.assertEqual([row["row_id"] for row in payload["rows"]], ["OPEN"])
            self.assertEqual(payload["advisory_count"], 1)

    def test_typed_queue_requires_exact_terminal_record_before_skipping_row(self) -> None:
        with tempfile.TemporaryDirectory(prefix="prove-top-leads-typed-terminal-") as td:
            ws = Path(td) / "ws"
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            queue = aud / "exploit_queue.zero_day_admitted.json"

            queue.write_text(json.dumps(_typed_queue(terminal=False)), encoding="utf-8")
            envelope = M._load_typed_envelope_tool()
            envelope.materialize(
                ws, queue, aud / "zero_day_proof_envelope.json",
            )
            open_payload = M.assess_queue(workspace=ws, queue_path=queue, top_n=10)
            self.assertTrue(open_payload["typed_proof_queue"])
            self.assertEqual(open_payload["terminal_rows_skipped"], 0)
            self.assertEqual(open_payload["row_count"], 1)

            queue.write_text(json.dumps(_typed_queue(terminal=True)), encoding="utf-8")
            closed_payload = M.assess_queue(workspace=ws, queue_path=queue, top_n=10)
            self.assertTrue(closed_payload["typed_proof_queue"])
            self.assertEqual(closed_payload["terminal_rows_skipped"], 1)
            self.assertEqual(closed_payload["row_count"], 0)
            self.assertEqual(closed_payload["proof_conversion_posture"], "no_live_rows_all_terminal")

    def test_typed_queue_rejects_stale_persisted_envelope(self) -> None:
        with tempfile.TemporaryDirectory(prefix="prove-top-leads-typed-stale-") as td:
            ws = Path(td) / "ws"
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            queue = aud / "exploit_queue.zero_day_admitted.json"
            payload = _typed_queue(terminal=False)
            queue.write_text(json.dumps(payload), encoding="utf-8")
            M._load_typed_envelope_tool().materialize(
                ws, queue, aud / "zero_day_proof_envelope.json",
            )
            payload["queue"][0]["zero_day_proof_projection"]["selection_ordinal"] = 2
            queue.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "typed_proof_envelope_invalid"):
                M.assess_queue(workspace=ws, queue_path=queue, top_n=10)

    def test_typed_queue_rejects_legacy_entries_before_terminal_filtering(self) -> None:
        with tempfile.TemporaryDirectory(prefix="prove-top-leads-typed-mixed-") as td:
            ws = Path(td) / "ws"
            queue = ws / "typed.json"
            ws.mkdir()
            payload = _typed_queue(terminal=False)
            payload["entries"] = [{"lead_id": "legacy"}]
            queue.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "typed_proof_envelope_legacy_entries_present"):
                M.assess_queue(workspace=ws, queue_path=queue, top_n=10)

    def test_strict_main_rejects_remaining_advisory_rows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="prove-top-leads-advisory-") as td:
            ws = Path(td) / "ws"
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            (ws / "src").mkdir()
            (ws / "src" / "Live.sol").write_text("contract Live {}\n", encoding="utf-8")
            queue = aud / "exploit_queue.source_mined.json"
            queue.write_text(
                json.dumps({"queue": [{"lead_id": "OPEN", "source_refs": ["src/Live.sol:1"]}]}),
                encoding="utf-8",
            )
            rc = M.main(["--workspace", str(ws), "--queue", str(queue), "--strict"])
            self.assertEqual(rc, 1)

    def test_generated_unanchorable_chain_join_is_terminal_oos(self) -> None:
        with tempfile.TemporaryDirectory(prefix="prove-top-leads-chain-oos-") as td:
            ws = Path(td) / "ws"
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            queue = aud / "exploit_queue.source_mined.json"
            queue.write_text(
                json.dumps({
                    "queue": [{
                        "lead_id": "CHAIN-OOS",
                        "proof_status": "closed_negative",
                        "quality_gate_status": "closed_negative",
                        "terminal_join": {
                            "evidence_ref": "unanchorable-no-target",
                            "reason": "anchorless corpus-hunt fuel row: no function and no contract (malformed cross-language template) - auto-terminalized OOS",
                        },
                    }]
                }),
                encoding="utf-8",
            )
            payload = M.assess_queue(workspace=ws, queue_path=queue, top_n=10)
            self.assertEqual(payload["terminal_rows_skipped"], 1)
            self.assertEqual(payload["row_count"], 0)
            self.assertEqual(payload["advisory_count"], 0)
            self.assertEqual(payload["proof_conversion_posture"], "no_live_rows_all_terminal")

    def test_strict_main_returns_nonzero_when_rows_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="prove-top-leads-strict-") as td:
            ws = Path(td) / "ws"
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            queue = aud / "exploit_queue.source_mined.json"
            queue.write_text(
                json.dumps({"schema": "auditooor.exploit_queue.v1", "queue": [{"lead_id": "BAD"}]}),
                encoding="utf-8",
            )
            out = aud / "out.json"

            rc = M.main([
                "--workspace",
                str(ws),
                "--queue",
                str(queue),
                "--out",
                str(out),
                "--strict",
            ])

            self.assertEqual(rc, 1)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["rejected_count"], 1)
            self.assertEqual(payload["rows"][0]["decision"], "rejected")


    def test_top_n_zero_means_all_leads_unbounded(self) -> None:
        # An audit must not silently drop leads beyond an arbitrary top-N.
        # top_n<=0 => assess EVERY queued lead; a positive top_n caps to the first N.
        with tempfile.TemporaryDirectory(prefix="prove-top-leads-all-") as td:
            ws = Path(td) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            queue = ws / ".auditooor" / "exploit_queue.source_mined.json"
            rows = [{"lead_id": f"L{i}", "title": f"lead {i}"} for i in range(5)]
            queue.write_text(
                json.dumps({"schema": "auditooor.exploit_queue.v1", "queue": rows}),
                encoding="utf-8",
            )
            all_payload = M.assess_queue(workspace=ws, queue_path=queue, top_n=0)
            self.assertEqual(len(all_payload["rows"]), 5,
                             "top_n=0 must assess ALL 5 queued leads (unbounded)")
            capped = M.assess_queue(workspace=ws, queue_path=queue, top_n=2)
            self.assertEqual(len(capped["rows"]), 2,
                             "a positive top_n must cap to the first N")


if __name__ == "__main__":
    unittest.main()
