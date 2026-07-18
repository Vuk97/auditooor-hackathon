#!/usr/bin/env python3
"""Regression: completeness-matrix-build credits a per-fn cell via (a) the
fcc-nonentry exemption checked BEFORE the per-frame branch (a hunted view/internal
fn no longer pins NOT-ENUMERATED) and (b) a MUTATION-VERIFIED mvc_sidecar for the
exact fn - never on a survived/vacuous sidecar. Strata 2026-07-07: 74 function
cells were false-red because the per-frame branch preceded the fcc-nonentry
exemption and never consulted mvc coverage."""
import importlib.util, json, sys, tempfile, unittest
from pathlib import Path
_H = Path(__file__).resolve().parent
_s = importlib.util.spec_from_file_location("cmb", _H.parent / "completeness-matrix-build.py")
_m = importlib.util.module_from_spec(_s); sys.modules["cmb"] = _m; _s.loader.exec_module(_m)


class T(unittest.TestCase):
    def _ws(self, sidecars):
        ws = Path(tempfile.mkdtemp())
        d = ws / ".auditooor" / "mvc_sidecar"; d.mkdir(parents=True)
        for i, sc in enumerate(sidecars):
            (d / f"m{i}.json").write_text(json.dumps(sc))
        return ws

    def test_mutation_verified_fn_credited(self):
        ws = self._ws([{"function": "accrueFee", "mutation_verified": True}])
        self.assertIn("accruefee", _m._mvc_covered_functions(ws))

    def test_nonvacuous_kill_credited(self):
        ws = self._ws([{"function": "finalize", "verdict": "non-vacuous",
                        "behavior_changing_kill_count": 2}])
        self.assertIn("finalize", _m._mvc_covered_functions(ws))

    def test_survived_sidecar_NOT_credited(self):
        # NEVER-FALSE: a sidecar that is neither mutation_verified nor a non-vacuous
        # kill credits nothing (the accrueFee sidecar with only function+harness).
        ws = self._ws([{"function": "setReserveBps",
                        "harness": "forge test ..."}])
        self.assertNotIn("setreservebps", _m._mvc_covered_functions(ws))

    def test_vacuous_verdict_NOT_credited(self):
        ws = self._ws([{"function": "updateBalanceFlow", "verdict": "non-vacuous",
                        "behavior_changing_kill_count": 0}])  # 0 kills = vacuous
        self.assertNotIn("updatebalanceflow", _m._mvc_covered_functions(ws))


if __name__ == "__main__":
    unittest.main()


class THarnessCutRemap(unittest.TestCase):
    """A mutation-verified mvc sidecar whose CUT is the HARNESS file path (not the
    in-scope source it tests) credits the in-scope source via basename embedding.
    Strata 2026-07-07: chimera harnesses register cut=chimera_harnesses/<X>/<X>.sol,
    so a >=1M mutation-verified harness left its real in-scope target reading as
    'no economic invariant' (false-red)."""
    def _ws(self, inscope, sidecar):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor" / "mvc_sidecar").mkdir(parents=True)
        (ws / ".auditooor" / "inscope_units.jsonl").write_text(
            "\n".join(json.dumps({"file": f, "function": "x"}) for f in inscope))
        (ws / ".auditooor" / "mvc_sidecar" / "m.json").write_text(json.dumps(sidecar))
        return ws

    def test_harness_cut_credits_inscope_target(self):
        ws = self._ws(["src/tranches/base/cooldown/SharesCooldown.sol"],
                      {"cut": "chimera_harnesses/SharesCooldownFeeConservation/SharesCooldownFeeConservation.sol",
                       "mutation_verified": True, "invariants": ["echidna_silo_conserved"]})
        cats = _m._mvc_asset_invariant_categories(ws, asset_key=_m._perfile_asset_of,
                                                  credit_empty_invariants=True)
        self.assertTrue(any(k.endswith("SharesCooldown.sol") for k in cats), sorted(cats))

    def test_harness_with_no_inscope_match_credits_nothing_extra(self):
        # never-false: a harness whose name embeds NO in-scope basename adds no in-scope file
        ws = self._ws(["src/SharesCooldown.sol"],
                      {"cut": "chimera_harnesses/UnrelatedThing/UnrelatedThing.sol",
                       "mutation_verified": True, "invariants": ["echidna_x"]})
        cats = _m._mvc_asset_invariant_categories(ws, asset_key=_m._perfile_asset_of,
                                                  credit_empty_invariants=True)
        self.assertFalse(any("SharesCooldown" in k for k in cats), sorted(cats))
