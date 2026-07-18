#!/usr/bin/env python3
"""Guard: _sidecar_cleared_call_floor must read the `call_count` field (a real
medusa/echidna sidecar sometimes records the executed count under `call_count`, not
`campaign_calls`). Root cause (nuva mvc-src-crosschainvaulthandler: engine=medusa,
call_count=1,225,621 was invisible -> serving-join false-red). The floor+engine gate
must still reject a SHALLOW call_count (128k forge never clears the medusa floor).
"""
import importlib.util
import sys
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location(
        "ifc_cc", str(_TOOLS / "invariant-fuzz-completeness.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["ifc_cc"] = m
    spec.loader.exec_module(m)
    return m


class TestSidecarCallCountField(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def test_real_medusa_call_count_credits(self):
        d = {"engine": "medusa", "call_count": 1225621, "mutation_verified": True}
        self.assertTrue(self.m._sidecar_cleared_call_floor(Path("/tmp/nows"), d))

    def test_top_level_and_nested_call_count(self):
        d = {"medusa_campaign": {"engine": "medusa", "call_count": 1300000}}
        self.assertTrue(self.m._sidecar_cleared_call_floor(Path("/tmp/nows"), d))

    def test_shallow_call_count_does_not_credit(self):
        # a 128k forge-shaped count under call_count must NOT clear the >=1M medusa floor
        d = {"engine": "medusa", "call_count": 128000, "mutation_verified": True}
        self.assertFalse(self.m._sidecar_cleared_call_floor(Path("/tmp/nows"), d))

    def test_no_campaign_evidence_does_not_credit(self):
        d = {"engine": "forge", "mutation_verified": True}
        self.assertFalse(self.m._sidecar_cleared_call_floor(Path("/tmp/nows"), d))


if __name__ == "__main__":
    unittest.main()
