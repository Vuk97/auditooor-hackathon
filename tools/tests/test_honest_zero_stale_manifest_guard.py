#!/usr/bin/env python3
# <!-- r36-rebuttal: lane HONEST-ZERO-STALE-MANIFEST-GUARD registered in commit message -->
"""Adversarial wiring-verify L11 (2026-06-30): a STALE genuine_coverage_manifest can pair a
build-broken all-error `counts` (checkable_count=0) with a prior-good embedded verdicts[]
(29 vacuous + 11 no-mutants). The stale checkable_count=0 silently DISARMED honest-zero-verify's
conservation gate even though the per-row detail IS the vacuous-theater it must catch. Fix:
_reconcile_gcm_counts recomputes genuine/checkable from verdicts[] and trusts the detail.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "honest-zero-verify.py"


def _load():
    spec = importlib.util.spec_from_file_location("hzv", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["hzv"] = m
    spec.loader.exec_module(m)
    return m


hzv = _load()


class ReconcileGcmCountsTest(unittest.TestCase):
    def test_stale_summary_corrected_from_verdicts(self):
        verdicts = ([{"verdict": "vacuous"}] * 29) + ([{"verdict": "no-mutants"}] * 11)
        stale = {"checkable_count": 0, "mutation_verified_genuine_count": 0,
                 "counts": {"error": 40}, "verdicts": verdicts}
        out = hzv._reconcile_gcm_counts(stale)
        # checkable = genuine(0) + vacuous(29) = 29; the stale 0 must be overridden so
        # the conservation gate (checkable>0 and genuine==0) FIRES.
        self.assertEqual(out["checkable_count"], 29)
        self.assertEqual(out["mutation_verified_genuine_count"], 0)

    def test_consistent_genuine_manifest_unchanged(self):
        verdicts = [{"verdict": "non-vacuous"}] * 40
        good = {"checkable_count": 40, "mutation_verified_genuine_count": 40,
                "verdicts": verdicts}
        out = hzv._reconcile_gcm_counts(good)
        self.assertEqual(out["mutation_verified_genuine_count"], 40)
        self.assertEqual(out["checkable_count"], 40)

    def test_no_verdicts_is_noop(self):
        m = {"checkable_count": 0, "mutation_verified_genuine_count": 0}
        self.assertIs(hzv._reconcile_gcm_counts(m), m)


if __name__ == "__main__":
    unittest.main(verbosity=2)
