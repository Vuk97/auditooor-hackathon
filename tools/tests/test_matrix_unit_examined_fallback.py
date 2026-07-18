#!/usr/bin/env python3
"""Regression: _hunt_examined_keys derives the examined fn from a sidecar's `unit`
field (Contract.fn [+ ...]) when neither function_anchor nor the hunt__<Contract>.sol__<fn>
filename encoding is present - the 753-sidecar `unit`/`file_line` schema was otherwise
invisible, so a genuinely-examined fn with a real R76 verdict fell to NOT-ENUMERATED."""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_MOD = _HERE.parent / "completeness-matrix-build.py"
_spec = importlib.util.spec_from_file_location("cmb_unit", _MOD)
_m = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _m
_spec.loader.exec_module(_m)


class TestUnitExaminedFallback(unittest.TestCase):
    def _ws(self, files: dict) -> Path:
        ws = Path(tempfile.mkdtemp())
        d = ws / ".auditooor" / "hunt_findings_sidecars"
        d.mkdir(parents=True)
        for name, rec in files.items():
            (d / name).write_text(json.dumps(rec))
        return ws

    def test_unit_field_credits_fn(self):
        ws = self._ws({
            "STRATA-resid5-StrataCDO-accrueFee.json": {
                "unit": "StrataCDO.accrueFee", "file_line": "src/x.sol:10", "verdict": "NEGATIVE"},
        })
        self.assertIn("accrueFee", _m._hunt_examined_keys(ws))

    def test_unit_with_plus_takes_first_arm(self):
        ws = self._ws({
            "s.json": {"unit": "AccessControlManager.isAllowedToCall + AccessControlled._checkAccessAllowed",
                       "verdict": "NEGATIVE"},
        })
        self.assertIn("isAllowedToCall", _m._hunt_examined_keys(ws))

    def test_function_anchor_still_preferred(self):
        ws = self._ws({
            "s.json": {"unit": "Wrong.wrongFn", "function_anchor": {"fn": "rightFn"}, "verdict": "NEGATIVE"},
        })
        keys = _m._hunt_examined_keys(ws)
        self.assertIn("rightFn", keys)

    def test_no_unit_no_anchor_contributes_nothing(self):
        ws = self._ws({"s.json": {"verdict": "NEGATIVE"}})
        self.assertEqual(_m._hunt_examined_keys(ws), set())


if __name__ == "__main__":
    unittest.main()
