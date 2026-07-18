#!/usr/bin/env python3
"""Guard: invariant-fuzz-credit-audit must report distinct UNCOVERED assets, not raw
shallow-sidecar count. Four fixes (nuva 2026-07-13, flagger said 50 vs gate 5):
  1. _norm_asset collapses absolute + relative asset paths (no double-count).
  2. a suspect is SUPPRESSED if the SAME asset has a floor-clearing sidecar (superseded).
  3. CALL_KEYS reads `call_count` (a real medusa sidecar sometimes records under it).
  4. a nested coverage-guided `medusa_campaign` block upgrades a forge/manual top-level
     engine so its real >=1M campaign clears the floor (mirrors the gate).
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
        "fca", str(_TOOLS / "invariant-fuzz-credit-audit.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["fca"] = m
    spec.loader.exec_module(m)
    return m


class TestFlaggerAssetDedupAndCredit(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _ws(self, sidecars):
        t = tempfile.mkdtemp()
        ws = Path(t)
        sd = ws / ".auditooor" / "mvc_sidecar"
        sd.mkdir(parents=True)
        for name, body in sidecars.items():
            (sd / name).write_text(json.dumps(body), encoding="utf-8")
        return ws

    def test_norm_collapses_abs_and_rel(self):
        ws = Path("/Users/wolf/audits/nuva")
        self.assertEqual(
            self.m._norm_asset(ws, "/Users/wolf/audits/nuva/src/X.sol"),
            self.m._norm_asset(ws, "src/X.sol"))

    def test_shallow_suppressed_when_asset_covered_elsewhere(self):
        ws = self._ws({
            "shallow.json": {"mutation_verified": True, "engine": "forge-invariant",
                             "mode": "source-mutation-verify", "source_file": "src/X.sol",
                             "call_count": 128000},
            "deep.json": {"mutation_verified": True, "engine": "medusa",
                          "source_file": "src/X.sol", "campaign_calls": 1200000},
        })
        r = self.m.audit_workspace(ws)
        self.assertEqual(r["suspect_asset_count"], 0, "asset covered by the deep sidecar")

    def test_call_count_field_clears_floor(self):
        ws = self._ws({
            "cc.json": {"mutation_verified": True, "engine": "medusa",
                        "source_file": "src/Y.sol", "call_count": 1225621},
        })
        r = self.m.audit_workspace(ws)
        self.assertEqual(r["suspect_asset_count"], 0)

    def test_nested_medusa_campaign_upgrades_forge_toplevel(self):
        ws = self._ws({
            "fac.json": {"mutation_verified": True, "engine": "forge-invariant",
                         "mode": "source-mutation-verify", "source_file": "src/Fac.sol",
                         "medusa_campaign": {"engine": "medusa", "campaign_calls": 1234659}},
        })
        r = self.m.audit_workspace(ws)
        self.assertEqual(r["suspect_asset_count"], 0, "nested medusa 1.2M clears the floor")

    def test_campaign_plus_mutant_mode_is_coverage_guided(self):
        # a real medusa campaign that ALSO ran a mutant (mode contains 'mutant-harness')
        # must NOT be misclassified as non-coverage-guided (nuva CrossChainVault false-flag)
        self.assertEqual(
            self.m._engine_class("medusa", "medusa-campaign-plus-mutant-harness"), "medusa")
        # a HAND-registered manual record stays non-coverage-guided even with a medusa engine
        self.assertEqual(
            self.m._engine_class("medusa", "manual-mutant-harness"), "non-coverage-guided")

    def test_genuine_shallow_only_asset_stays_suspect(self):
        ws = self._ws({
            "only.json": {"mutation_verified": True, "engine": "forge-invariant",
                          "mode": "source-mutation-verify", "source_file": "src/Z.sol",
                          "call_count": 128000},
        })
        r = self.m.audit_workspace(ws)
        self.assertEqual(r["suspect_asset_count"], 1, "no deep campaign -> real debt")


if __name__ == "__main__":
    unittest.main()
