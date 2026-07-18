#!/usr/bin/env python3
"""Regression: invariant-fuzz-completeness credits a harness's >=1M call floor from the
structured fuzz_campaign_receipt.json (the artifact its own FAIL message names), not just
from a greppable 'calls: N' log line. A receipt-backed >=1.2M medusa campaign whose log
lacks a parseable counter must NOT read as exec_calls=0 (serving-join false-red)."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_MOD = _HERE.parent / "invariant-fuzz-completeness.py"
_spec = importlib.util.spec_from_file_location("ifc_receipt_credit", _MOD)
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)


class TestReceiptCallCredit(unittest.TestCase):
    def _ws(self, receipt: dict) -> Path:
        ws = Path(tempfile.mkdtemp())
        aud = ws / ".auditooor"
        aud.mkdir(parents=True, exist_ok=True)
        (aud / "fuzz_campaign_receipt.json").write_text(json.dumps(receipt))
        (ws / "chimera_harnesses" / "AprPairFeedBounds").mkdir(parents=True, exist_ok=True)
        return ws

    def test_credits_by_harness_path(self):
        ws = self._ws({"campaigns": [{
            "name": "AprPairFeedBounds",
            "harness": "chimera_harnesses/AprPairFeedBounds/AprPairFeedBounds.sol",
            "result": {"calls": 1211236}}]})
        hd = ws / "chimera_harnesses" / "AprPairFeedBounds"
        self.assertEqual(_m._receipt_calls_for_harness(ws, hd), 1211236)
        # and the public metric surfaces it (no log line present anywhere)
        calls, _dry = _m._campaign_call_metrics(ws, hd)
        self.assertGreaterEqual(calls, _m.MIN_CALLS)

    def test_credits_by_name_match(self):
        ws = self._ws({"campaigns": [{
            "name": "AprPairFeedBounds", "result": {"calls": 1205980}}]})
        hd = ws / "chimera_harnesses" / "AprPairFeedBounds"
        self.assertEqual(_m._receipt_calls_for_harness(ws, hd), 1205980)

    def test_no_receipt_entry_returns_zero(self):
        ws = self._ws({"campaigns": [{
            "name": "SomethingElse", "result": {"calls": 2000000}}]})
        hd = ws / "chimera_harnesses" / "AprPairFeedBounds"
        self.assertEqual(_m._receipt_calls_for_harness(ws, hd), 0)

    def test_testlimit_fallback_when_calls_absent(self):
        ws = self._ws({"campaigns": [{
            "name": "AprPairFeedBounds", "config": {"testLimit": 1500000}}]})
        hd = ws / "chimera_harnesses" / "AprPairFeedBounds"
        self.assertEqual(_m._receipt_calls_for_harness(ws, hd), 1500000)

    def test_missing_receipt_returns_zero(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "chimera_harnesses" / "X").mkdir(parents=True, exist_ok=True)
        self.assertEqual(_m._receipt_calls_for_harness(ws, ws / "chimera_harnesses" / "X"), 0)


if __name__ == "__main__":
    unittest.main()
