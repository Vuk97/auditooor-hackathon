#!/usr/bin/env python3
"""Regression: completeness-matrix credits family-required invariant CATEGORIES from a
mutation-verified harness's declared echidna_* invariants (+ authorization from access-
control guards), instead of reading real bounds/custody/ordering/freshness coverage as a
family-recall gap.

Serving-join (Strata 2026-07-07): the family denominator required
authorization/bounds/custody/determinism/freshness/ordering; all 6 WERE tested by
mutation-verified invariants (echidna_min_shares_floor=bounds, echidna_proxy_solvency=
custody, echidna_no_early_claim=ordering+freshness, ...) but the matrix never mapped an
invariant NAME to a category, so 'all invariants held' read vacuous."""
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
    def test_classify_is_multi_category(self):
        # one invariant can cover >1 category
        self.assertEqual(m._classify_invariant_category("echidna_min_shares_floor"), {"bounds"})
        c = m._classify_invariant_category("echidna_no_early_claim")
        self.assertIn("ordering", c)
        self.assertIn("freshness", c)

    def _ws(self, invariants, mv=True, guards=0):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor" / "mvc_sidecar").mkdir(parents=True)
        hd = ws / "chimera_harnesses" / "FooConservation"
        hd.mkdir(parents=True)
        body = "contract FooConservation {\n" + "\n".join(
            f"  function {i}() public view returns (bool) {{ return true; }}" for i in invariants) + "\n}"
        (hd / "FooConservation.sol").write_text(body)
        (ws / ".auditooor" / "mvc_sidecar" / "mvc-FooConservation.json").write_text(json.dumps(
            {"harness_path": "chimera_harnesses/FooConservation/FooConservation.sol",
             "verdict": "non-vacuous" if mv else "vacuous", "mutation_verified": mv}))
        if guards:
            (ws / "src").mkdir()
            (ws / "src" / "Gated.sol").write_text(
                "contract Gated {" + " onlyRole(A) onlyRole(B) onlyRole(C) onlyRole(D)" + "}")
        return ws

    def test_mutation_verified_invariants_credit_categories(self):
        ws = self._ws(["echidna_min_shares_floor", "echidna_proxy_solvency",
                       "echidna_no_early_claim"])
        cats = m._verified_invariant_categories(ws)
        self.assertIn("bounds", cats)
        self.assertIn("custody", cats)
        self.assertIn("ordering", cats)
        self.assertIn("freshness", cats)

    def test_unverified_harness_credits_nothing(self):
        # verdict vacuous / not mutation-verified -> NO category credit (never-false)
        ws = self._ws(["echidna_min_shares_floor"], mv=False)
        self.assertEqual(m._verified_invariant_categories(ws), set())

    def test_authorization_needs_real_guards(self):
        no_guard = self._ws(["echidna_proxy_solvency"], guards=0)
        self.assertNotIn("authorization", m._verified_invariant_categories(no_guard))
        with_guard = self._ws(["echidna_proxy_solvency"], guards=4)
        self.assertIn("authorization", m._verified_invariant_categories(with_guard))


if __name__ == "__main__":
    unittest.main()
