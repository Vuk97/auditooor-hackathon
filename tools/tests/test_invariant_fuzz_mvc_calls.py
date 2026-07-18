#!/usr/bin/env python3
"""Regression: invariant-fuzz-completeness credits a machine-readable call count
recorded in an mvc_sidecar's `medusa_campaign.calls_executed` (serving-join).

Strata 2026-07-07: a step-4b lane recorded its real 1.2M medusa campaign under
mvc_sidecar medusa_campaign.calls_executed (with corpus_dir + FNDA), but
_campaign_call_metrics only read the receipt + *.log, so the >=1M floor read
UNVERIFIABLE (corpus-only-no-counter) - a false-red on a genuine campaign.
Never-false: a count is credited ONLY when the sidecar maps to the harness AND
carries execution evidence."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_H = Path(__file__).resolve().parent
_s = importlib.util.spec_from_file_location(
    "ifc", _H.parent / "invariant-fuzz-completeness.py")
m = importlib.util.module_from_spec(_s)
_s.loader.exec_module(m)


class T(unittest.TestCase):
    def _ws_with_sidecar(self, campaign):
        ws = Path(tempfile.mkdtemp())
        hd = ws / "chimera_harnesses" / "FooConservation"
        hd.mkdir(parents=True)
        (hd / "FooConservation.sol").write_text("contract FooConservation {}\n")
        sc = ws / ".auditooor" / "mvc_sidecar"
        sc.mkdir(parents=True)
        rec = {"schema": "x", "harness_path": "chimera_harnesses/FooConservation/FooConservation.sol"}
        if campaign is not None:
            rec["medusa_campaign"] = campaign
        (sc / "mvc-foo.json").write_text(json.dumps(rec))
        return ws, hd

    def test_credits_recorded_count_with_execution_evidence(self):
        ws, hd = self._ws_with_sidecar({
            "calls_executed": 1_203_846, "call_sequence_length": 50,
            "corpus_dir": "chimera_harnesses/FooConservation/medusa_corpus",
            "properties_passed": 4})
        self.assertEqual(m._mvc_sidecar_calls(ws, hd), 1_203_846)

    def test_no_execution_evidence_not_credited(self):
        # a bare count with NO corpus/fnda/properties is not trusted (never-false).
        ws, hd = self._ws_with_sidecar({"calls_executed": 9_999_999})
        self.assertEqual(m._mvc_sidecar_calls(ws, hd), 0)

    def test_unmapped_sidecar_not_credited(self):
        ws, hd = self._ws_with_sidecar({
            "calls_executed": 1_203_846, "corpus_dir": "x", "properties_passed": 4})
        other = ws / "chimera_harnesses" / "BarConservation"
        other.mkdir(parents=True)
        (other / "BarConservation.sol").write_text("contract BarConservation {}\n")
        # the sidecar maps to Foo, not Bar
        self.assertEqual(m._mvc_sidecar_calls(ws, other), 0)

    def test_no_sidecar_dir(self):
        ws = Path(tempfile.mkdtemp())
        hd = ws / "chimera_harnesses" / "FooConservation"
        hd.mkdir(parents=True)
        self.assertEqual(m._mvc_sidecar_calls(ws, hd), 0)

    def test_metrics_folds_in_sidecar_count(self):
        ws, hd = self._ws_with_sidecar({
            "calls_executed": 1_500_000, "corpus_dir": "x", "properties_passed": 3})
        calls, _dry = m._campaign_call_metrics(ws, hd)
        self.assertGreaterEqual(calls, 1_500_000)


if __name__ == "__main__":
    unittest.main()
