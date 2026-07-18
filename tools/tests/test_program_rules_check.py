#!/usr/bin/env python3
"""Regression (Strata 2026-07-07): program-rules-check enforces a bounty program's own
PoC/scope rules on a paste-ready finding. The DiscreteAccounting finding seeded both
tranches compliantly (100e18) yet its impact PROVABLY required Junior NAV -> 0 (< ONE_ASSET,
a program-excluded condition) - undetectable by regex. So the load-bearing check is a
COMPLIANCE ATTESTATION: a High+ finding must affirmatively address each program rule; one
that never does is flagged. Plus hard catches for a literal excluded-phrase / sub-floor seed."""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "prc", _HERE.parent / "program-rules-check.py")
_m = importlib.util.module_from_spec(_spec)
sys.modules["prc"] = _m
_spec.loader.exec_module(_m)

_RULES = {
    "program": "Strata",
    "poc_seeding": {"min_assets_per_entity": 10, "floor_constant": "ONE_ASSET",
                    "floor_value_wei": "1000000000000000000",
                    "entities": ["Junior", "Senior"]},
    "invalid_impact_conditions": ["base nav at or near one_asset"],
    "ineligible_if_disclosed": {"enforced": True, "note": "x", "audits": ["a"]},
}


class TestProgramRulesCheck(unittest.TestCase):
    def _ws(self, draft_md, poc_sol=None):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir(parents=True)
        (ws / ".auditooor" / "program_rules.json").write_text(json.dumps(_RULES))
        fd = ws / "submissions" / "paste_ready" / "f"
        fd.mkdir(parents=True)
        md = fd / "f.md"
        md.write_text(draft_md)
        if poc_sol is not None:
            (fd / "Poc.t.sol").write_text(poc_sol)
        return ws, md

    def test_no_rules_file_is_na(self):
        ws = Path(tempfile.mkdtemp())
        md = ws / "f.md"; md.write_text("# x")
        self.assertEqual(_m.check(ws, md)["verdict"], "n/a")

    def test_missing_attestation_warns(self):
        ws, md = self._ws("# Finding\n## Summary\nSenior over-withdraws.\n")
        r = _m.check(ws, md)
        self.assertEqual(r["verdict"], "warn")
        att = [c for c in r["checks"] if c["check"] == "poc-requirements-attested"][0]
        self.assertEqual(att["status"], "warn")

    def test_full_attestation_passes(self):
        ws, md = self._ws(
            "# Finding\n## PoC Requirements compliance\n"
            "The PoC seeds both tranches with >= 10 assets each (deployable state); the impact "
            "does not depend on ONE_ASSET - it holds with Junior NAV well above the floor.\n")
        r = _m.check(ws, md)
        att = [c for c in r["checks"] if c["check"] == "poc-requirements-attested"][0]
        self.assertEqual(att["status"], "pass")

    def test_excluded_phrase_fails(self):
        ws, md = self._ws("# Finding\n## Impact\nThe base NAV at or near ONE_ASSET is required.\n")
        r = _m.check(ws, md)
        self.assertEqual(r["verdict"], "fail")

    def test_sub_floor_seed_warns(self):
        ws, md = self._ws(
            "# Finding\n## Summary\nseeds both tranches with >= 10 assets, does not depend on ONE_ASSET\n",
            poc_sol="contract P { function t() public { vault.deposit(1e18); } }\n")
        r = _m.check(ws, md)
        seed = [c for c in r["checks"] if c["check"] == "poc-seeding-floor"][0]
        self.assertEqual(seed["status"], "warn")

    def test_rebuttal_marker_clears(self):
        ws, md = self._ws(
            "# Finding\nprogram-rules-rebuttal: operator approved\n## Impact\n"
            "base NAV at or near ONE_ASSET is required.\n")
        r = _m.check(ws, md)
        # the excluded-phrase check is rebutted -> no hard fail
        self.assertNotEqual(r["verdict"], "fail")


if __name__ == "__main__":
    unittest.main()
