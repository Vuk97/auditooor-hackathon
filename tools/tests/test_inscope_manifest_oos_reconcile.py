#!/usr/bin/env python3
"""Test inscope-manifest-oos-reconcile: drop ONLY units whose file has a cited
OOS adjudication; never a value-mover without one; back up + log on apply."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_MOD = _HERE.parent / "inscope-manifest-oos-reconcile.py"
_spec = importlib.util.spec_from_file_location("inscope_reconcile", _MOD)
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)


class TestReconcile(unittest.TestCase):
    def _ws(self, units, adjs):
        ws = Path(tempfile.mkdtemp())
        d = ws / ".auditooor"
        d.mkdir(parents=True)
        (d / "inscope_units.jsonl").write_text("\n".join(json.dumps(u) for u in units) + "\n")
        (d / "commit_adjudications.jsonl").write_text("\n".join(json.dumps(a) for a in adjs) + "\n")
        return ws

    def test_drops_only_cited_oos_file(self):
        units = [
            {"file": "src/contracts/lens/CDOLens.sol", "function": "initialize"},
            {"file": "src/contracts/lens/CDOLens.sol", "function": "netApr"},
            {"file": "src/contracts/tranches/Accounting.sol", "function": "calculateNAVSplit"},
        ]
        adjs = [{"verdict": "oos", "source_ref": "contracts/lens/CDOLens.sol",
                 "reason": "lens/ not among the in-scope targets; read-only view helper"}]
        ws = self._ws(units, adjs)
        res = _m.reconcile(ws, apply=True)
        self.assertEqual(res["verdict"], "reconciled")
        self.assertEqual(res["dropped_count"], 2)          # both CDOLens units
        self.assertEqual(res["kept_count"], 1)             # Accounting value-mover kept
        remaining = (ws / ".auditooor" / "inscope_units.jsonl").read_text()
        self.assertIn("Accounting.sol", remaining)
        self.assertNotIn("CDOLens", remaining)
        self.assertTrue((ws / ".auditooor" / "inscope_units.jsonl.pre_oos_reconcile").exists())
        self.assertTrue((ws / ".auditooor" / "inscope_oos_reconcile_log.json").exists())

    def test_never_drops_without_cited_reason(self):
        units = [{"file": "src/contracts/lens/CDOLens.sol", "function": "x"}]
        # verdict oos but NO reason -> must NOT drop (guard against silent value-mover removal)
        adjs = [{"verdict": "oos", "source_ref": "contracts/lens/CDOLens.sol", "reason": ""}]
        ws = self._ws(units, adjs)
        res = _m.reconcile(ws, apply=True)
        self.assertEqual(res["dropped_count"], 0)

    def test_no_adjudication_is_noop(self):
        units = [{"file": "src/contracts/tranches/Accounting.sol", "function": "x"}]
        ws = self._ws(units, [])
        res = _m.reconcile(ws, apply=True)
        self.assertEqual(res["verdict"], "pass-no-oos-units-in-manifest")
        self.assertEqual(res["dropped_count"], 0)


if __name__ == "__main__":
    unittest.main()
