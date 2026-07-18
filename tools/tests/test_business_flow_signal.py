"""The business-flow-coverage L37 signal fails CLOSED under strict on an
undriven cross-module flow (not advisory)."""
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "audit-completeness-check.py"
_spec = importlib.util.spec_from_file_location("audit_completeness_check", _TOOL)
ACC = importlib.util.module_from_spec(_spec)
import sys as _sys
_sys.modules["audit_completeness_check"] = ACC
_spec.loader.exec_module(ACC)


def _ws(units, sidecars=None):
    ws = Path(tempfile.mkdtemp())
    a = ws / ".auditooor"
    a.mkdir()
    (a / "inscope_units.jsonl").write_text(
        "".join(json.dumps(u) + "\n" for u in units), encoding="utf-8")
    if sidecars:
        sd = a / "hunt_findings_sidecars"
        sd.mkdir()
        for i, fn in enumerate(sidecars):
            (sd / f"h{i}.json").write_text(json.dumps(
                {"function_anchor": {"file": "x.sol", "fn": fn}, "result": {"verdict": "kill"}}))
    return ws


class TestBusinessFlowSignal(unittest.TestCase):
    def setUp(self):
        self._saved = os.environ.get("AUDITOOOR_L37_STRICT")
        os.environ["AUDITOOOR_L37_STRICT"] = "1"

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("AUDITOOOR_L37_STRICT", None)
        else:
            os.environ["AUDITOOOR_L37_STRICT"] = self._saved

    def test_undriven_flow_fails_closed_under_strict(self):
        ws = _ws([{"file": "src/Vault.sol", "function": "deposit"},
                  {"file": "src/Router.sol", "function": "deposit"}], sidecars=[])
        r = ACC.check_business_flow_coverage(ws)
        self.assertFalse(r.ok, r.reason)
        self.assertIn("BF-asset-lifecycle-deposit", r.detail["undriven"])

    def test_driven_flow_passes(self):
        ws = _ws([{"file": "src/Vault.sol", "function": "deposit"},
                  {"file": "src/Router.sol", "function": "deposit"}], sidecars=["deposit"])
        self.assertTrue(ACC.check_business_flow_coverage(ws).ok)

    def test_no_flows_passes(self):
        ws = _ws([{"file": "a.sol", "function": "getConfig"}])
        self.assertTrue(ACC.check_business_flow_coverage(ws).ok)


if __name__ == "__main__":
    unittest.main()
