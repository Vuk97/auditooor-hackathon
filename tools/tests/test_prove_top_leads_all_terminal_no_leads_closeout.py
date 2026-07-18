#!/usr/bin/env python3
"""test_prove_top_leads_all_terminal_no_leads_closeout.py

Parity regression (2026-07-04, surfaced on NUVA): the CLOSEOUT no-leads manifest
validator (tools/audit-closeout-check.py:_valid_prove_top_leads_no_leads_manifest)
had diverged from the COMPLETENESS validator
(tools/audit-completeness-check.py:_valid_prove_top_leads_no_leads_manifest). Two
divergences:

  1. It read a DIFFERENT queue rel set (exploit_queue.json +
     proof_obligation_queue.json) instead of the producer's real rel set
     (exploit_queue.json + exploit_queue.source_mined.json), so the manifest's
     declared_counts never matched the live queue counts.
  2. It only accepted an EMPTY queue (current==0) to declare "no provable leads",
     rejecting the non-empty-all-terminal honest-0 shape the completeness validator
     already accepts.

Result: the real emitted manifest passed audit-complete but FAILED audit-closeout
(verified on NUVA: completeness=True, closeout=False). This test mirrors
tools/tests/test_prove_top_leads_all_terminal_no_leads.py against the CLOSEOUT
validator and pins the three cases: accept non-empty-all-terminal WITH prefiling
corroboration; reject WITHOUT; still accept empty. It also pins the un-fakeable
prefiling helper and the stale-declared-counts rejection.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "audit-closeout-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("audit_closeout_check", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["audit_closeout_check"] = m
    try:
        spec.loader.exec_module(m)
    except Exception:
        pass
    return m


def _ws(queue_rows, manifest, prefiling=None, typed_payload=None):
    d = Path(tempfile.mkdtemp())
    a = d / ".auditooor"
    a.mkdir()
    q = {"queue": [{"i": i} for i in range(queue_rows)]}
    (a / "exploit_queue.json").write_text(json.dumps(q))
    (a / "exploit_queue.source_mined.json").write_text(json.dumps(q))
    if typed_payload is not None:
        (a / "exploit_queue.zero_day_admitted.json").write_text(json.dumps(typed_payload))
    if manifest is not None:
        (a / "prove_top_leads_no_leads.json").write_text(json.dumps(manifest))
    if prefiling is not None:
        (a / "prove_top_leads_prefiling_stress_test.json").write_text(json.dumps(prefiling))
    return d


_SCHEMA = "auditooor.prove_top_leads_no_leads.v1"
_ALL_TERMINAL_PREFILING = {"top_n": 10, "rows_assessed": 0, "terminal_rows_skipped": 134}


class TestCloseoutAllTerminalNoLeads(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _valid(self, ws):
        return self.m._valid_prove_top_leads_no_leads_manifest(
            ws, ws / ".auditooor" / "prove_top_leads_no_leads.json")

    def test_closeout_reads_source_mined_rel_not_proof_obligation(self):
        # Parity guard: the closeout rel set must match the producer + the
        # completeness validator, including the canonical admitted typed queue.
        self.assertEqual(
            self.m._PROVE_TOP_LEADS_QUEUE_RELS,
            (
                ".auditooor/exploit_queue.json",
                ".auditooor/exploit_queue.source_mined.json",
                ".auditooor/exploit_queue.zero_day_admitted.json",
            ),
        )

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

    def test_closeout_rejects_malformed_typed_queue_that_old_empty_rule_accepted(self):
        ws = _ws(0, {"schema": _SCHEMA, "no_leads": True, "lead_count": 0,
                     "current_queue_rows": {
                         ".auditooor/exploit_queue.json": 0,
                         ".auditooor/exploit_queue.source_mined.json": 0,
                         ".auditooor/exploit_queue.zero_day_admitted.json": 0,
                     }}, typed_payload={"queue": []})
        self.assertFalse(self._valid(ws))


if __name__ == "__main__":
    unittest.main()
