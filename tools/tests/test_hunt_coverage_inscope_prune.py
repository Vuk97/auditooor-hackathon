#!/usr/bin/env python3
# <!-- r36-rebuttal: lane HUNT-COVERAGE-INSCOPE-PRUNE registered in commit message -->
"""hunt-coverage-gate: prune dir-granularity over-enumeration to the in-scope manifest.

Strata 2026-06-30: SCOPE.md enumerates SPECIFIC provider files (AprPairProvider.sol,
ChainlinkAprProviderLib.sol) under tranches/oracles/providers/, but heatmap.enumerate_units
resolves scope at DIR granularity and admitted the dir's OOS siblings (Aave*Provider.sol),
inflating the hunt-coverage denominator 135 -> 372 and false-failing queued-not-scanned.
The authoritative .auditooor/inscope_units.jsonl (allowlist-honoring) is the in-scope set;
the gate now intersects by file-basename. Pin the helper + the never-false-pass property.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "hunt-coverage-gate.py"
_spec = importlib.util.spec_from_file_location("hcg", _T)
hcg = importlib.util.module_from_spec(_spec)
sys.modules["hcg"] = hcg
_spec.loader.exec_module(hcg)


class InscopePruneTest(unittest.TestCase):
    def _ws(self, files):
        ws = Path(tempfile.mkdtemp(prefix="hcg_"))
        (ws / ".auditooor").mkdir()
        mf = ws / ".auditooor" / "inscope_units.jsonl"
        mf.write_text("\n".join(json.dumps({"file": f, "function": "x"}) for f in files),
                      encoding="utf-8")
        return ws

    def test_manifest_basenames(self):
        ws = self._ws([
            "src/contracts/contracts/tranches/oracles/providers/AprPairProvider.sol",
            "src/contracts/contracts/tranches/Accounting.sol",
        ])
        names = hcg._inscope_manifest_basenames(ws)
        self.assertEqual(names, {"AprPairProvider.sol", "Accounting.sol"})

    def test_prune_drops_oos_keeps_inscope(self):
        ws = self._ws([
            "src/contracts/contracts/tranches/oracles/providers/AprPairProvider.sol",
            "src/contracts/contracts/tranches/Accounting.sol",
        ])
        inscope = hcg._inscope_manifest_basenames(ws)
        units = {
            "AprPairProvider.sol::getAprPair",          # in-scope -> keep
            "Accounting.sol::nav",                       # in-scope -> keep
            "AaveAprPairProvider.sol::getAPRbase",       # OOS sibling -> drop
            "AaveOracleAprPairProvider.sol::constructor",  # OOS sibling -> drop
        }
        kept = {u for u in units if hcg._unit_basename(u) in inscope}
        self.assertEqual(kept, {"AprPairProvider.sol::getAprPair", "Accounting.sol::nav"})
        # never-false-pass: an in-scope unit is NEVER dropped by the prune
        self.assertIn("Accounting.sol::nav", kept)

    def test_no_manifest_is_noop(self):
        ws = Path(tempfile.mkdtemp(prefix="hcg_"))
        (ws / ".auditooor").mkdir()
        self.assertEqual(hcg._inscope_manifest_basenames(ws), set())


if __name__ == "__main__":
    unittest.main(verbosity=2)
