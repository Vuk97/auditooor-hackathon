#!/usr/bin/env python3
"""Focused coverage for typed zero-day proof-conversion admission."""
from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "zero-day-proof-admission.py"
SPEC = importlib.util.spec_from_file_location("zero_day_proof_admission_test", TOOL)
assert SPEC and SPEC.loader
ADMISSION = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ADMISSION
SPEC.loader.exec_module(ADMISSION)


class ZeroDayProofAdmissionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.parent = ("zdo_parent", "zdr_revision")
        self.bus = {
            "receipt": {
                "receipt_id": "a" * 64,
                "input_fingerprint": "b" * 64,
            },
            "obligation_by_parent": {
                self.parent: {"source_row_sha256": "c" * 64},
            },
        }

    def test_admits_only_exact_current_parent_and_preserves_input(self) -> None:
        payload = {
            "schema": ADMISSION.QUEUE_SCHEMA,
            "queue_role": ADMISSION.PROOF_TASK_QUEUE_ROLE,
            "queue": [{"lead_id": "lead-1", "obligation_id": self.parent[0], "revision_id": self.parent[1]}],
        }
        original = copy.deepcopy(payload)
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "ws"
            workspace.mkdir()
            queue_path = workspace / ".auditooor" / "exploit_queue.json"
            queue_path.parent.mkdir()
            queue_path.write_text(json.dumps(payload), encoding="utf-8")
            admitted = ADMISSION.admit_queue(payload, "d" * 64, queue_path, workspace, self.bus)
        self.assertEqual(payload, original)
        self.assertEqual(ADMISSION.QUEUE_SCHEMA, admitted["schema"])
        self.assertEqual(ADMISSION.PROOF_TASK_QUEUE_ROLE, admitted["queue_role"])
        self.assertEqual(self.parent, tuple(admitted["queue"][0]["zero_day_proof_admission"]["parent_ids"]))
        metadata = admitted["zero_day_proof_admission"]
        self.assertEqual(ADMISSION.ADMISSION_SCHEMA, metadata["schema"])
        self.assertEqual(ADMISSION.PROOF_TASK_QUEUE_ROLE, metadata["queue_role"])
        self.assertEqual(1, metadata["admitted_count"])
        self.assertEqual([{"obligation_id": self.parent[0], "revision_id": self.parent[1]}], metadata["admitted_parents"])

    def test_rejects_missing_or_stale_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "ws"
            workspace.mkdir()
            queue_path = workspace / "queue.json"
            for row, code in (
                ({"lead_id": "missing"}, "proof_admission_obligation_id_missing:row-1"),
                ({"lead_id": "stale", "obligation_id": self.parent[0], "revision_id": "zdr_stale"},
                 "proof_admission_parent_not_current:row-1"),
            ):
                with self.subTest(row=row):
                    with self.assertRaisesRegex(ADMISSION.AdmissionError, code):
                        ADMISSION.admit_queue({"schema": ADMISSION.QUEUE_SCHEMA, "queue": [row]},
                                              "d" * 64, queue_path, workspace, self.bus)

    def test_run_reuses_current_bus_validator_and_writes_separate_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "ws"
            queue_path = workspace / ".auditooor" / "exploit_queue.json"
            output_path = workspace / ".auditooor" / "exploit_queue.admitted.json"
            queue_path.parent.mkdir(parents=True)
            payload = {
                "schema": ADMISSION.QUEUE_SCHEMA,
                "queue_role": ADMISSION.PROOF_TASK_QUEUE_ROLE,
                "queue": [{"lead_id": "lead-1", "obligation_id": self.parent[0], "revision_id": self.parent[1]}],
            }
            queue_path.write_text(json.dumps(payload), encoding="utf-8")
            with mock.patch.object(ADMISSION, "load_frozen_bus", return_value=self.bus) as validator:
                receipt = ADMISSION.run(workspace, queue_path, output_path)
            validator.assert_called_once_with(workspace.resolve())
            self.assertEqual("a" * 64, receipt["freeze_receipt_id"])
            self.assertEqual(payload, json.loads(queue_path.read_text(encoding="utf-8")))
            written = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual("lead-1", written["queue"][0]["lead_id"])
            self.assertEqual("a" * 64, written["zero_day_proof_admission"]["freeze_receipt_id"])

    def test_rejects_queue_or_output_outside_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "ws"
            workspace.mkdir()
            outside = root / "outside.json"
            outside.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ADMISSION.AdmissionError, "proof_admission_queue_outside_workspace"):
                ADMISSION.run(workspace, outside, workspace / "out.json")

    def test_failed_admission_removes_prior_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "ws"
            queue_path = workspace / ".auditooor" / "exploit_queue.json"
            output_path = workspace / ".auditooor" / "exploit_queue.admitted.json"
            queue_path.parent.mkdir(parents=True)
            queue_path.write_text(json.dumps({"schema": ADMISSION.QUEUE_SCHEMA,
                                               "queue_role": ADMISSION.PROOF_TASK_QUEUE_ROLE,
                                               "queue": [{"lead_id": "bad"}]}),
                                  encoding="utf-8")
            output_path.write_text("stale", encoding="utf-8")
            with mock.patch.object(ADMISSION, "load_frozen_bus", return_value=self.bus):
                with self.assertRaisesRegex(ADMISSION.AdmissionError, "proof_admission_obligation_id_missing:row-1"):
                    ADMISSION.run(workspace, queue_path, output_path)
            self.assertFalse(output_path.exists())

    def test_rejects_missing_or_wrong_queue_role_before_admission(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "ws"
            queue_path = workspace / ".auditooor" / "exploit_queue.json"
            queue_path.parent.mkdir(parents=True)
            for role in (None, "candidate_leads"):
                payload = {"schema": ADMISSION.QUEUE_SCHEMA, "queue": []}
                if role is not None:
                    payload["queue_role"] = role
                queue_path.write_text(json.dumps(payload), encoding="utf-8")
                with self.subTest(role=role):
                    with self.assertRaisesRegex(ADMISSION.AdmissionError, "proof_admission_queue_role_invalid"):
                        ADMISSION._load_queue(queue_path)


if __name__ == "__main__":
    unittest.main()
