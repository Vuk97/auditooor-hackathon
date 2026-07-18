#!/usr/bin/env python3
"""Regression: invariant-fuzz-completeness credits a value-moving in-scope file
TRANSITIVELY when a mutation-verified, floor-cleared harness imports it AND directly
DEPLOYS its contract via `new <C>(` - the serving-join that made Strata's cooldown impls
(Midas/sNUSD/Saturn CooldownRequestImpl) read as gaps though a StrategyConservation harness
`new`-deploys + drives them and names them in its no-overclaim invariant.

NEVER-FALSE: `new <Contract>(` is the anchor (a mock is `new Mock<X>(`, a different stem);
a file merely imported for a type (no `new`) is NOT credited."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_H = Path(__file__).resolve().parent
_s = importlib.util.spec_from_file_location("ifc", _H.parent / "invariant-fuzz-completeness.py")
ifc = importlib.util.module_from_spec(_s)
_s.loader.exec_module(ifc)


class T(unittest.TestCase):
    def _ws(self, harness_src, mvc):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor" / "mvc_sidecar").mkdir(parents=True)
        hdir = ws / "chimera_harnesses" / "StratConservation"
        hdir.mkdir(parents=True)
        (hdir / "StratConservation.sol").write_text(harness_src)
        (ws / ".auditooor" / "mvc_sidecar" / "mvc-strat.json").write_text(json.dumps(mvc))
        return ws

    def _mvc(self, calls=1_500_000, verdict="non-vacuous", mv=True):
        return {"harness_path": "chimera_harnesses/StratConservation/StratConservation.sol",
                "verdict": verdict, "mutation_verified": mv, "behavior_changing_kill_count": 1,
                "medusa_campaign": {"calls_executed": calls}}

    def test_new_deploy_gets_transitive_credit(self):
        src = ('import { CooldownImpl } from "strata/x/CooldownImpl.sol";\n'
               'contract StratConservation { CooldownImpl t;\n'
               '  function setup() external { t = new CooldownImpl(addr); } }')
        ws = self._ws(src, self._mvc())
        cov = ifc._transitively_covered_files(ws, {"src/x/CooldownImpl.sol"})
        self.assertIn("src/x/CooldownImpl.sol", cov)

    def test_import_only_not_credited(self):
        # imported for a type but never `new`-deployed -> NOT covered (never-false)
        src = ('import { CooldownImpl } from "strata/x/CooldownImpl.sol";\n'
               'contract StratConservation { function f(CooldownImpl c) external {} }')
        ws = self._ws(src, self._mvc())
        cov = ifc._transitively_covered_files(ws, {"src/x/CooldownImpl.sol"})
        self.assertNotIn("src/x/CooldownImpl.sol", cov)

    def test_mock_deploy_not_credited(self):
        # `new MockCooldownImpl(` is a different stem -> the real file is NOT credited
        src = ('import { CooldownImpl } from "strata/x/CooldownImpl.sol";\n'
               'contract StratConservation { function s() external { new MockCooldownImpl(); } }')
        ws = self._ws(src, self._mvc())
        cov = ifc._transitively_covered_files(ws, {"src/x/CooldownImpl.sol"})
        self.assertNotIn("src/x/CooldownImpl.sol", cov)

    def test_below_floor_not_credited(self):
        src = ('import { CooldownImpl } from "strata/x/CooldownImpl.sol";\n'
               'contract StratConservation { function s() external { new CooldownImpl(a); } }')
        ws = self._ws(src, self._mvc(calls=100_000))  # below MIN_CALLS
        cov = ifc._transitively_covered_files(ws, {"src/x/CooldownImpl.sol"})
        self.assertNotIn("src/x/CooldownImpl.sol", cov)

    def test_not_mutation_verified_not_credited(self):
        src = ('import { CooldownImpl } from "strata/x/CooldownImpl.sol";\n'
               'contract StratConservation { function s() external { new CooldownImpl(a); } }')
        ws = self._ws(src, self._mvc(verdict="vacuous", mv=False))
        cov = ifc._transitively_covered_files(ws, {"src/x/CooldownImpl.sol"})
        self.assertNotIn("src/x/CooldownImpl.sol", cov)


if __name__ == "__main__":
    unittest.main()
