#!/usr/bin/env python3
"""Focused coverage for immutable typed zero-day proof envelopes."""
from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "zero-day-proof-envelope-verify.py"
SPEC = importlib.util.spec_from_file_location("zero_day_proof_envelope_verify_test", TOOL)
assert SPEC and SPEC.loader
ENVELOPE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ENVELOPE
SPEC.loader.exec_module(ENVELOPE)


class ZeroDayProofEnvelopeVerifyTest(unittest.TestCase):
    def _queue(self) -> dict:
        parent = ["zdo_parent", "zdr_revision"]
        row = {
            "lead_id": "zdpq_lead",
            "obligation_id": parent[0],
            "revision_id": parent[1],
            "title": "Frozen obligation",
            "zero_day_proof_projection": {
                "schema": ENVELOPE.PROJECTION_SCHEMA,
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
        return {
            "schema": ENVELOPE.QUEUE_SCHEMA,
            "queue_role": ENVELOPE.PROOF_TASK_QUEUE_ROLE,
            "queue": [row],
            "zero_day_proof_admission": {
                "schema": ENVELOPE.ADMISSION_SCHEMA,
                "queue_role": ENVELOPE.PROOF_TASK_QUEUE_ROLE,
                "admission_id": "zdpa_" + "d" * 64,
                "input_queue_sha256": "e" * 64,
                "freeze_receipt_id": "a" * 64,
                "freeze_input_fingerprint": "b" * 64,
                "admitted_count": 1,
                "admitted_parents": [{"obligation_id": parent[0], "revision_id": parent[1]}],
            },
        }

    def test_materializes_and_verifies_exact_typed_identity(self) -> None:
        queue = self._queue()
        envelope = ENVELOPE.build_envelope(queue)
        self.assertEqual(ENVELOPE.ENVELOPE_SCHEMA, envelope["schema"])
        self.assertEqual(ENVELOPE.PROOF_TASK_QUEUE_ROLE, envelope["queue_role"])
        self.assertEqual(1, envelope["entry_count"])
        candidate = copy.deepcopy(queue)
        candidate["queue"][0]["local_proof"] = {"command": "forge test", "result": "pending"}
        report = ENVELOPE.verify_envelope(envelope, candidate)
        self.assertEqual("pass-zero-day-proof-envelope", report["verdict"])

    def test_rejects_identity_mutation_unknown_rows_and_missing_rows(self) -> None:
        queue = self._queue()
        envelope = ENVELOPE.build_envelope(queue)
        mutated = copy.deepcopy(queue)
        mutated["queue"][0]["zero_day_proof_projection"]["selection_ordinal"] = 2
        with self.assertRaisesRegex(ENVELOPE.EnvelopeError, "proof_envelope_identity_mutated:zdpq_lead"):
            ENVELOPE.verify_envelope(envelope, mutated)
        with self.assertRaisesRegex(ENVELOPE.EnvelopeError, "proof_envelope_admission_count_mismatch"):
            ENVELOPE.verify_envelope(envelope, {**queue, "queue": []})
        unknown = copy.deepcopy(queue)
        unknown["queue"][0]["lead_id"] = "unknown"
        with self.assertRaisesRegex(ENVELOPE.EnvelopeError, "proof_envelope_row_set_mismatch"):
            ENVELOPE.verify_envelope(envelope, unknown)
        top_level = copy.deepcopy(queue)
        top_level["zero_day_proof_admission"]["freeze_receipt_id"] = "f" * 64
        with self.assertRaisesRegex(ENVELOPE.EnvelopeError, "proof_envelope_admission_top_level_mismatch:row-1"):
            ENVELOPE.verify_envelope(envelope, top_level)

    def test_rejects_malformed_typed_rows(self) -> None:
        queue = self._queue()
        del queue["queue"][0]["zero_day_proof_admission"]
        with self.assertRaisesRegex(ENVELOPE.EnvelopeError, "proof_envelope_admission_missing:row-1"):
            ENVELOPE.build_envelope(queue)

    def test_rejects_missing_or_wrong_proof_task_role(self) -> None:
        queue = self._queue()
        for field, value, code in (
            ("queue_role", None, "proof_envelope_queue_role_invalid"),
            ("queue_role", "candidate_leads", "proof_envelope_queue_role_invalid"),
        ):
            with self.subTest(field=field, value=value):
                malformed = copy.deepcopy(queue)
                malformed[field] = value
                with self.assertRaisesRegex(ENVELOPE.EnvelopeError, code):
                    ENVELOPE.build_envelope(malformed)
        malformed_admission = copy.deepcopy(queue)
        malformed_admission["zero_day_proof_admission"]["queue_role"] = "candidate_leads"
        with self.assertRaisesRegex(ENVELOPE.EnvelopeError, "proof_envelope_admission_queue_role_invalid"):
            ENVELOPE.build_envelope(malformed_admission)

    def test_terminal_record_requires_exact_parent_envelope_and_source_cite(self) -> None:
        queue = self._queue()
        entry = ENVELOPE.build_envelope(queue)["entries"][0]
        row = queue["queue"][0]
        row["terminal_join"] = {
            "schema": ENVELOPE.TERMINAL_VERDICT_SCHEMA,
            "parent_ids": entry["parent_ids"],
            "envelope_id": entry["envelope_id"],
            "evidence_ref": "src/Vault.sol:L42",
        }
        self.assertTrue(ENVELOPE.terminal_record_matches(entry, row))
        row["terminal_join"]["envelope_id"] = "zdpe-wrong"
        self.assertFalse(ENVELOPE.terminal_record_matches(entry, row))

    def test_materialize_and_verify_are_workspace_bound_and_clear_stale_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "ws"
            queue_path = workspace / ".auditooor" / "admitted.json"
            output_path = workspace / ".auditooor" / "envelope.json"
            queue_path.parent.mkdir(parents=True)
            queue_path.write_text(json.dumps(self._queue()), encoding="utf-8")
            output_path.write_text("stale", encoding="utf-8")
            envelope = ENVELOPE.materialize(workspace, queue_path, output_path)
            self.assertEqual(1, envelope["entry_count"])
            self.assertEqual(envelope, json.loads(output_path.read_text(encoding="utf-8")))
            report = ENVELOPE.verify(workspace, output_path, queue_path)
            self.assertEqual("pass-zero-day-proof-envelope", report["verdict"])
            default_path = workspace / ENVELOPE.DEFAULT_ENVELOPE_REL
            ENVELOPE.materialize(workspace, queue_path, default_path)
            persisted = ENVELOPE.verify_persisted(workspace, queue_path)
            self.assertEqual("pass-zero-day-proof-envelope", persisted["verdict"])
            outside = Path(temporary) / "outside.json"
            outside.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ENVELOPE.EnvelopeError, "proof_envelope_candidate_outside_workspace"):
                ENVELOPE.verify(workspace, output_path, outside)


if __name__ == "__main__":
    unittest.main()
