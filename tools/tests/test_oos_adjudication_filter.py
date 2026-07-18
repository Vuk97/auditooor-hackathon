#!/usr/bin/env python3
"""Regression: write_inscope_manifest's _oos_adjudication_filter drops rows whose
file has a cited verdict:oos adjudication, but never a value-mover without one, and
never empties the manifest. Wired at the write chokepoint so it survives regens."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_MOD = _HERE.parent / "workspace-coverage-heatmap.py"
_spec = importlib.util.spec_from_file_location("wch", _MOD)
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)


class TestOosAdjudicationFilter(unittest.TestCase):
    def _ws(self, adjs):
        ws = Path(tempfile.mkdtemp())
        d = ws / ".auditooor"
        d.mkdir(parents=True)
        (d / "commit_adjudications.jsonl").write_text(
            "\n".join(json.dumps(a) for a in adjs) + "\n")
        return ws

    def test_drops_cited_oos_keeps_value_mover(self):
        ws = self._ws([
            {"verdict": "oos", "source_ref": "contracts/lens/CDOLens.sol",
             "reason": "lens/ not among in-scope targets; read-only view helper"}])
        rows = [
            {"file": "src/contracts/contracts/lens/CDOLens.sol", "function": "getAPRs"},
            {"file": "src/contracts/contracts/tranches/Accounting.sol", "function": "calculateNAVSplit"},
        ]
        kept = _m._oos_adjudication_filter(ws, rows)
        files = {r["file"] for r in kept}
        self.assertNotIn("src/contracts/contracts/lens/CDOLens.sol", files)
        self.assertIn("src/contracts/contracts/tranches/Accounting.sol", files)

    def test_no_reason_is_noop(self):
        ws = self._ws([
            {"verdict": "oos", "source_ref": "contracts/lens/CDOLens.sol", "reason": ""}])
        rows = [{"file": "contracts/lens/CDOLens.sol", "function": "x"}]
        self.assertEqual(len(_m._oos_adjudication_filter(ws, rows)), 1)

    def test_never_empties_manifest(self):
        ws = self._ws([
            {"verdict": "oos", "source_ref": "contracts/lens/CDOLens.sol", "reason": "lens oos"}])
        rows = [{"file": "contracts/lens/CDOLens.sol", "function": "x"}]  # the ONLY row is OOS
        # fail-safe: never return empty
        self.assertEqual(len(_m._oos_adjudication_filter(ws, rows)), 1)

    def test_no_adjudications_is_noop(self):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir(parents=True)
        rows = [{"file": "a/B.sol", "function": "x"}]
        self.assertEqual(_m._oos_adjudication_filter(ws, rows), rows)


if __name__ == "__main__":
    unittest.main()
