#!/usr/bin/env python3
"""Guard: _receipt_calls_for_harness must join a per-harness
`<harness_dir>/campaign_result.json` (auditooor.medusa_campaign_result.v1), not only
the aggregate `.auditooor/fuzz_campaign_receipt.json`.

Root cause (nuva 2026-07-13): a coverage lane sandboxed to chimera_harnesses/** wrote
the real >=1.2M medusa counts to per-harness campaign_result.json; the reader
early-returned 0 when the aggregate receipt was absent, so a genuine campaign read as
0 calls (false-red). A failed/counterexample campaign must NOT credit.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location(
        "ifc_join", str(_TOOLS / "invariant-fuzz-completeness.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["ifc_join"] = m
    spec.loader.exec_module(m)
    return m


class TestPerHarnessCampaignReceiptJoin(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _mk(self, body):
        t = tempfile.mkdtemp()
        ws = Path(t)
        hd = ws / "chimera_harnesses" / "CrossChainVault"
        hd.mkdir(parents=True)
        (hd / "campaign_result.json").write_text(json.dumps(body), encoding="utf-8")
        return ws, hd

    def test_clean_pass_campaign_credits(self):
        ws, hd = self._mk({"campaign_calls": 1202994, "seq_len": 50,
                           "campaign_status": "pass", "counterexample": None})
        self.assertEqual(self.m._receipt_calls_for_harness(ws, hd), 1202994)

    def test_no_aggregate_receipt_still_joins(self):
        # the aggregate .auditooor/fuzz_campaign_receipt.json is absent - must NOT early-return 0
        ws, hd = self._mk({"campaign_calls": 1500000, "campaign_status": "pass"})
        self.assertEqual(self.m._receipt_calls_for_harness(ws, hd), 1500000)

    def test_failed_campaign_does_not_credit(self):
        ws, hd = self._mk({"campaign_calls": 1202994, "campaign_status": "failed",
                           "counterexample": {"seq": [1, 2]}})
        self.assertEqual(self.m._receipt_calls_for_harness(ws, hd), 0)

    def test_counterexample_does_not_credit(self):
        ws, hd = self._mk({"campaign_calls": 1202994, "campaign_status": "pass",
                           "counterexample": {"seq": [1]}})
        self.assertEqual(self.m._receipt_calls_for_harness(ws, hd), 0)


if __name__ == "__main__":
    unittest.main()
