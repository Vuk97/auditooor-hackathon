#!/usr/bin/env python3
"""Regression: completeness-matrix credits a value-moving file's invariant CATEGORIES
transitively when a mutation-verified harness imports it AND `new`-deploys its contract -
so an impl covered only via its strategy's conservation harness is not read as 0/10.

Strata 2026-07-07: the 3 cooldown impls (Midas/sNUSD/Saturn CooldownRequestImpl) were
`new`-deployed + driven by their StrategyConservation harness (and named in its no-overclaim
invariant) yet the per-asset enumeration keyed only on a DIRECT mvc sidecar -> 4 never-
enumerated assets. After the transitive credit only sNUSDSwapAdapter (deployed by NO harness)
remains a genuine gap."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_H = Path(__file__).resolve().parent
_s = importlib.util.spec_from_file_location("cm", _H.parent / "completeness-matrix-build.py")
m = importlib.util.module_from_spec(_s)
_s.loader.exec_module(m)


class T(unittest.TestCase):
    def _ws(self, deploys_impl=True, mv=True):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor" / "mvc_sidecar").mkdir(parents=True)
        (ws / "src").mkdir()
        (ws / "src" / "CooldownImpl.sol").write_text("contract CooldownImpl { function f() external {} }")
        hd = ws / "chimera_harnesses" / "StratConservation"
        hd.mkdir(parents=True)
        deploy = "impl = new CooldownImpl(a);" if deploys_impl else "// no deploy"
        (hd / "StratConservation.sol").write_text(
            'import { CooldownImpl } from "strata/x/CooldownImpl.sol";\n'
            "contract StratConservation {\n"
            f"  function setup() external {{ {deploy} }}\n"
            "  function echidna_no_overclaim() public view returns (bool) { return true; }\n"
            "  function echidna_proxy_solvency() public view returns (bool) { return true; }\n}")
        (ws / ".auditooor" / "mvc_sidecar" / "mvc-StratConservation.json").write_text(json.dumps(
            {"harness_path": "chimera_harnesses/StratConservation/StratConservation.sol",
             "verdict": "non-vacuous" if mv else "vacuous", "mutation_verified": mv}))
        return ws

    def test_new_deployed_impl_inherits_categories(self):
        ws = self._ws(deploys_impl=True)
        tac = m._transitive_asset_categories(ws, m._perfile_asset_of)
        key = next((k for k in tac if k.endswith("CooldownImpl.sol")), None)
        self.assertIsNotNone(key, "impl should be credited")
        self.assertIn("custody", tac[key])          # from echidna_proxy_solvency
        self.assertIn("ordering", tac[key])          # from echidna_no_overclaim

    def test_imported_but_not_deployed_not_credited(self):
        ws = self._ws(deploys_impl=False)
        tac = m._transitive_asset_categories(ws, m._perfile_asset_of)
        self.assertFalse(any(k.endswith("CooldownImpl.sol") for k in tac))

    def test_unverified_harness_credits_nothing(self):
        ws = self._ws(deploys_impl=True, mv=False)
        self.assertEqual(m._transitive_asset_categories(ws, m._perfile_asset_of), {})


if __name__ == "__main__":
    unittest.main()
