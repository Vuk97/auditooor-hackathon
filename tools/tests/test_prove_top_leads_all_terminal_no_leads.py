#!/usr/bin/env python3
"""test_prove_top_leads_all_terminal_no_leads.py

Generic gate-gap fix (2026-07-03, surfaced on NUVA): the prove-top-leads no-leads
manifest required an EMPTY exploit queue (current==0) to declare "no provable leads".
But a genuine honest-0 can have a LARGE processed corpus-driven-hunt queue where every
eligible TOP lead is already terminal/adjudicated and nothing is submit-ready - neither
the submittable-packets path nor the empty-queue path fit, so audit-complete could never
green. The no-leads manifest now also accepts a non-empty queue when it declares
all_top_leads_terminal AND the UN-FAKEABLE prefiling-stress producer independently
reports top_n==0 (0 non-terminal top rows, terminal rows skipped>0). A hand-forged claim
is contradicted by the prefiling producer, which recomputes top_n from the live queue.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "audit-completeness-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("audit_completeness_check", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["audit_completeness_check"] = m
    try:
        spec.loader.exec_module(m)
    except Exception:
        pass
    return m


def _load_envelope_tool():
    spec = importlib.util.spec_from_file_location(
        "all_terminal_no_leads_envelope", _TOOL.with_name("zero-day-proof-envelope-verify.py"),
    )
    m = importlib.util.module_from_spec(spec)
    sys.modules["all_terminal_no_leads_envelope"] = m
    spec.loader.exec_module(m)
    return m


def _typed_queue(envelope_tool, terminal):
    parent = ["zdo-validator", "zdr-validator"]
    row = {
        "lead_id": "zdpq-validator",
        "obligation_id": parent[0],
        "revision_id": parent[1],
        "proof_status": "disproved",
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
    payload = {
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
        entry = envelope_tool.build_envelope(payload)["entries"][0]
        row["terminal_join"] = {
            "schema": "auditooor.zero_day_proof_terminal_verdict.v1",
            "parent_ids": entry["parent_ids"],
            "envelope_id": entry["envelope_id"],
            "evidence_ref": "src/Validator.sol:42",
        }
    return payload


def _ws(queue_rows, manifest, prefiling=None, typed_queue=None):
    d = Path(tempfile.mkdtemp())
    a = d / ".auditooor"
    a.mkdir()
    q = {"queue": [{"i": i} for i in range(queue_rows)]}
    (a / "exploit_queue.json").write_text(json.dumps(q))
    (a / "exploit_queue.source_mined.json").write_text(json.dumps(q))
    if typed_queue is not None:
        (a / "exploit_queue.zero_day_admitted.json").write_text(json.dumps(typed_queue))
    if manifest is not None:
        (a / "prove_top_leads_no_leads.json").write_text(json.dumps(manifest))
    if prefiling is not None:
        (a / "prove_top_leads_prefiling_stress_test.json").write_text(json.dumps(prefiling))
    return d


_SCHEMA = "auditooor.prove_top_leads_no_leads.v1"
_ALL_TERMINAL_PREFILING = {"top_n": 10, "rows_assessed": 0, "terminal_rows_skipped": 134}


class TestAllTerminalNoLeads(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _valid(self, ws):
        return self.m._valid_prove_top_leads_no_leads_manifest(
            ws, ws / ".auditooor" / "prove_top_leads_no_leads.json")

    def test_empty_queue_still_valid(self):
        ws = _ws(0, {"schema": _SCHEMA, "no_leads": True, "lead_count": 0,
                     "current_queue_rows": {".auditooor/exploit_queue.json": 0,
                                            ".auditooor/exploit_queue.source_mined.json": 0}})
        self.assertTrue(self._valid(ws))

    def test_nonempty_all_terminal_valid_with_prefiling(self):
        ws = _ws(7814, {"schema": _SCHEMA, "no_leads": True, "lead_count": 0,
                        "all_top_leads_terminal": True,
                        "current_queue_rows": {".auditooor/exploit_queue.json": 7814,
                                               ".auditooor/exploit_queue.source_mined.json": 7814}},
                 prefiling=_ALL_TERMINAL_PREFILING)
        self.assertTrue(self._valid(ws))

    def test_nonempty_rejected_without_prefiling_corroboration(self):
        # claim all-terminal but prefiling shows non-terminal rows -> cannot game
        ws = _ws(7814, {"schema": _SCHEMA, "no_leads": True, "lead_count": 0,
                        "all_top_leads_terminal": True,
                        "current_queue_rows": {".auditooor/exploit_queue.json": 7814,
                                               ".auditooor/exploit_queue.source_mined.json": 7814}},
                 prefiling={"top_n": 5, "rows_assessed": 5, "terminal_rows_skipped": 10})
        self.assertFalse(self._valid(ws))

    def test_nonempty_rejected_without_flag(self):
        ws = _ws(7814, {"schema": _SCHEMA, "no_leads": True, "lead_count": 0,
                        "current_queue_rows": {".auditooor/exploit_queue.json": 7814,
                                               ".auditooor/exploit_queue.source_mined.json": 7814}},
                 prefiling=_ALL_TERMINAL_PREFILING)
        self.assertFalse(self._valid(ws))

    def test_stale_declared_counts_rejected(self):
        # manifest declares old counts that don't match the live queue
        ws = _ws(7814, {"schema": _SCHEMA, "no_leads": True, "lead_count": 0,
                        "all_top_leads_terminal": True,
                        "current_queue_rows": {".auditooor/exploit_queue.json": 100,
                                               ".auditooor/exploit_queue.source_mined.json": 100}},
                 prefiling=_ALL_TERMINAL_PREFILING)
        self.assertFalse(self._valid(ws))

    def test_prefiling_confirms_helper(self):
        ws = _ws(7814, None, prefiling=_ALL_TERMINAL_PREFILING)
        self.assertTrue(self.m._prefiling_confirms_all_terminal(ws))
        ws2 = _ws(7814, None, prefiling={"top_n": 0, "rows_assessed": 0, "terminal_rows_skipped": 0})
        self.assertFalse(self.m._prefiling_confirms_all_terminal(ws2))  # empty/unrun, not all-terminal

    def test_typed_bare_status_cannot_close_no_leads_manifest(self):
        ws = _ws(1, {"schema": _SCHEMA, "no_leads": True, "lead_count": 0,
                     "all_top_leads_terminal": True,
                     "current_queue_rows": {
                         ".auditooor/exploit_queue.json": 1,
                         ".auditooor/exploit_queue.source_mined.json": 1,
                         ".auditooor/exploit_queue.zero_day_admitted.json": 1,
                     }}, prefiling=_ALL_TERMINAL_PREFILING,
                 typed_queue=_typed_queue(_load_envelope_tool(), terminal=False))
        self.assertFalse(self._valid(ws))

    def test_typed_exact_terminal_record_can_close_no_leads_manifest(self):
        ws = _ws(1, {"schema": _SCHEMA, "no_leads": True, "lead_count": 0,
                     "all_top_leads_terminal": True,
                     "current_queue_rows": {
                         ".auditooor/exploit_queue.json": 1,
                         ".auditooor/exploit_queue.source_mined.json": 1,
                         ".auditooor/exploit_queue.zero_day_admitted.json": 1,
                     }}, prefiling=_ALL_TERMINAL_PREFILING,
                 typed_queue=_typed_queue(_load_envelope_tool(), terminal=True))
        self.assertTrue(self._valid(ws))

    def test_typed_queue_must_be_declared_even_when_legacy_manifest_is_otherwise_current(self):
        ws = _ws(1, {"schema": _SCHEMA, "no_leads": True, "lead_count": 0,
                     "all_top_leads_terminal": True,
                     "current_queue_rows": {
                         ".auditooor/exploit_queue.json": 1,
                         ".auditooor/exploit_queue.source_mined.json": 1,
                     }}, prefiling=_ALL_TERMINAL_PREFILING,
                 typed_queue=_typed_queue(_load_envelope_tool(), terminal=True))
        self.assertFalse(self._valid(ws))


if __name__ == "__main__":
    unittest.main()
