#!/usr/bin/env python3
"""Regression: L37 ``_has_medium_plus_evm_candidate`` must NOT count a
terminal-NEGATIVE (refuted) exploit-queue lead as an OPEN Medium+ EVM 0-day
obligation.

Bug (axelar-sc 2026-07-12): the exploit_queue had 10 ``likely_severity: high``
rows ALL at ``proof_status: closed_negative`` (every Medium+ lead already
driven to a NEGATIVE terminal). ``_has_medium_plus_evm_candidate`` counted them
regardless of terminal state, so under ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1 the
``evm-0day-proof`` signal demanded an EVM 0-day proof-conversion artifact for
leads that were already REFUTED - a FALSE-RED (the same class as the NUVA
corpus-fuel false-red the function already guards against).

The fix excludes terminal-negative rows via ``_row_is_terminal_negative``. This
opens NO hole: the QUALITY of each refutation stays accountable under the
separate disqualification signal (``_is_disqualification_kill`` / signal u),
which independently requires a SUBSTANTIVE ``negative_control`` for every
``closed_negative`` kill - so a lazy "couldn't auto-prove -> closed_negative"
dodge is still caught there.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_TOOL = _REPO / "tools" / "audit-completeness-check.py"


def _load_acc_module():
    spec = importlib.util.spec_from_file_location("_acc_evm0day_termneg_test_mod", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_acc_evm0day_termneg_test_mod"] = mod
    spec.loader.exec_module(mod)
    return mod


_ACC = _load_acc_module()


def _write_queue(ws: Path, rows):
    a = ws / ".auditooor"
    a.mkdir(parents=True, exist_ok=True)
    (a / "exploit_queue.json").write_text(
        json.dumps({"queue": rows}), encoding="utf-8"
    )


class TerminalNegativeExclusionTest(unittest.TestCase):
    def test_all_closed_negative_high_leads_are_not_open_candidates(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write_queue(ws, [
                {"lead_id": f"EQ-{i:03d}", "likely_severity": "high",
                 "proof_status": "closed_negative",
                 "title": "role-grant-divergence"}
                for i in range(1, 11)
            ])
            self.assertFalse(
                _ACC._has_medium_plus_evm_candidate(ws),
                "closed_negative (refuted) Medium+ leads must NOT count as OPEN "
                "EVM 0-day obligations",
            )

    def test_open_high_lead_still_counts(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write_queue(ws, [
                {"lead_id": "EQ-001", "likely_severity": "high",
                 "proof_status": "unproved", "title": "genuine open lead"},
            ])
            self.assertTrue(
                _ACC._has_medium_plus_evm_candidate(ws),
                "an OPEN (unproved) Medium+ lead must still demand a 0-day proof",
            )

    def test_mixed_queue_one_open_lead_dominates(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write_queue(ws, [
                {"lead_id": "EQ-001", "likely_severity": "high",
                 "proof_status": "closed_negative", "title": "refuted"},
                {"lead_id": "EQ-002", "likely_severity": "medium",
                 "proof_status": "needs_harness", "title": "still open"},
            ])
            self.assertTrue(
                _ACC._has_medium_plus_evm_candidate(ws),
                "one OPEN Medium+ lead among refuted ones keeps the obligation",
            )

    def test_terminal_negative_via_quality_gate_status(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write_queue(ws, [
                {"lead_id": "EQ-001", "likely_severity": "critical",
                 "quality_gate_status": "disqualified", "title": "gate-refuted"},
            ])
            self.assertFalse(
                _ACC._has_medium_plus_evm_candidate(ws),
                "a lead disqualified via quality_gate_status is not an OPEN "
                "obligation",
            )

    def test_helper_predicate_direct(self):
        self.assertTrue(_ACC._row_is_terminal_negative(
            {"proof_status": "closed_negative"}))
        self.assertTrue(_ACC._row_is_terminal_negative(
            {"quality_gate_status": "closed_negative_source_proof"}))
        self.assertFalse(_ACC._row_is_terminal_negative(
            {"proof_status": "unproved"}))
        self.assertFalse(_ACC._row_is_terminal_negative({}))


if __name__ == "__main__":
    unittest.main()
