#!/usr/bin/env python3
"""test_invariant_fuzz_credit_audit.py - hermetic unit tests for the
invariant-fuzz DEPTH-false-credit retroactive scanner.

Fixtures (all in-memory tempdirs; no real workspace touched):
  (a) medusa 1.2M mutation-verified            -> NOT suspect (cleared floor)
  (b) manual-mutant-harness, no campaign_calls,
      mutation-verified                         -> SUSPECT (non-coverage-guided)
  (c) forge invariant runs:256 / 128000 calls,
      mutation-verified                         -> SUSPECT (forge, not coverage-guided)
  (d) echidna 600k mutation-verified            -> NOT suspect (>= echidna floor)
  (e) non-mutation-verified sidecar             -> not evaluated
"""

from __future__ import annotations

import json
import tempfile
import unittest
import importlib.util as _ilu
from pathlib import Path

_TOOLS_DIR = Path(__file__).parent.parent
_TOOL_PATH = _TOOLS_DIR / "invariant-fuzz-credit-audit.py"
_spec = _ilu.spec_from_file_location("invariant_fuzz_credit_audit", _TOOL_PATH)
_mod = _ilu.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]

audit_workspace = _mod.audit_workspace
evaluate_sidecar = _mod.evaluate_sidecar


def _make_ws(tmp: str, sidecars: dict[str, dict]) -> Path:
    ws = Path(tmp)
    sd = ws / ".auditooor" / "mvc_sidecar"
    sd.mkdir(parents=True, exist_ok=True)
    for name, payload in sidecars.items():
        (sd / name).write_text(json.dumps(payload), encoding="utf-8")
    return ws


class TestCreditAudit(unittest.TestCase):

    def _eval_one(self, payload: dict):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(tmp, {"s.json": payload})
            sd = ws / ".auditooor" / "mvc_sidecar" / "s.json"
            return evaluate_sidecar(sd)

    def test_a_medusa_1p2m_not_suspect(self):
        ev = self._eval_one({
            "engine": "medusa", "mutation_verified": True, "non_vacuous": True,
            "campaign_calls": 1_200_424, "cut": "src/Foo.sol",
        })
        self.assertIsNotNone(ev)
        self.assertTrue(ev["cleared_call_floor"])
        self.assertFalse(ev["suspect"])
        self.assertEqual(ev["engine_class"], "medusa")

    def test_b_manual_mutant_harness_suspect(self):
        ev = self._eval_one({
            "mode": "manual-mutant-harness", "mutation_verified": True,
            "manual_registration": True, "cut": "src/Bar.sol",
        })
        self.assertIsNotNone(ev)
        self.assertFalse(ev["cleared_call_floor"])
        self.assertTrue(ev["suspect"])
        self.assertEqual(ev["engine_class"], "non-coverage-guided")

    def test_c_forge_runs256_suspect(self):
        ev = self._eval_one({
            "engine": "forge-invariant", "mutation_verified": True,
            "non_vacuous": True, "runs": 256, "calls": 128_000,
            "cut": "src/Baz.sol",
        })
        self.assertIsNotNone(ev)
        self.assertFalse(ev["cleared_call_floor"])
        self.assertTrue(ev["suspect"])

    def test_d_echidna_600k_not_suspect(self):
        ev = self._eval_one({
            "engine": "echidna", "mutation_verified": True, "non_vacuous": True,
            "total_calls_baseline": 600_000, "cut": "src/Qux.sol",
        })
        self.assertIsNotNone(ev)
        self.assertTrue(ev["cleared_call_floor"])
        self.assertFalse(ev["suspect"])
        self.assertEqual(ev["engine_class"], "echidna")

    def test_e_non_mutation_verified_not_evaluated(self):
        ev = self._eval_one({
            "engine": "medusa", "mutation_verified": False,
            "campaign_calls": 1_200_000, "cut": "src/Skip.sol",
        })
        self.assertIsNone(ev)

    def test_echidna_below_floor_suspect(self):
        # echidna 400k < 500k floor -> suspect (sub-floor).
        ev = self._eval_one({
            "engine": "echidna", "mutation_verified": True, "non_vacuous": True,
            "total_calls_baseline": 400_000, "cut": "src/Low.sol",
        })
        self.assertTrue(ev["suspect"])

    def test_workspace_rollup_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(tmp, {
                "good.json": {"engine": "medusa", "mutation_verified": True,
                              "campaign_calls": 1_200_000, "cut": "a.sol"},
                "bad1.json": {"mode": "manual-mutant-harness",
                              "mutation_verified": True, "cut": "b.sol"},
                "bad2.json": {"engine": "forge-invariant",
                              "mutation_verified": True, "runs": 256,
                              "calls": 128_000, "cut": "c.sol"},
                "skip.json": {"engine": "medusa", "mutation_verified": False,
                              "campaign_calls": 2_000_000, "cut": "d.sol"},
            })
            res = audit_workspace(ws)
            self.assertEqual(res["evaluated"], 3)  # skip.json excluded
            self.assertEqual(res["suspect_asset_count"], 2)


if __name__ == "__main__":
    unittest.main()
