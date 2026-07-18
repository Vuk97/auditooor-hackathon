#!/usr/bin/env python3
"""Regression tests for tools/directional-rounding-asymmetry.py.

Proves the asymmetric rounding-direction query (mode(V) VIOLATES the protocol-
favoring owed-direction D(V)) is:
  - a DIRECTIONAL relation whose predicate DISCRIMINATES: the SAME conversion token
    (mulDiv-floor) is a SURVIVOR on a takes-in leg and CORRECT on an owes-out leg -
    the verdict flips by direction, not by token (a shape/token detector cannot);
  - NON-VACUOUS under mutation: flip a mulDiv-FLOOR to mulDiv-CEIL on an owes-out
    leg and the survivor APPEARS; flip it back and it DISAPPEARS (the asymmetry is
    load-bearing, not the trivial "any conversion");
  - a CROSS-FUNCTION relation for mirror pairs (both legs round the same direction
    -> round-trip protection broken);
  - HONEST on class-absence: a repo with no fixed-point conversion reports
    class_present False + a cited-empty (distinct from a vacuous 0-fn substrate);
  - advisory_only=needs_source when direction OR mode cannot be statically confirmed.
"""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOL = _HERE.parent / "directional-rounding-asymmetry.py"
_spec = importlib.util.spec_from_file_location("directional_rounding", _TOOL)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


# A synthetic ERC-4626-style vault.
#   previewRedeem  = owes-out (protocol pays assets out) -> MUST round DOWN.
#   previewDeposit = takes-in (protocol collects assets) -> MUST round UP.
# Here previewRedeem rounds DOWN (CORRECT, no survivor) and previewDeposit rounds
# DOWN (VIOLATION: takes-in should round up -> SURVIVOR).
_VAULT_BASE = """
contract Vault {
    function previewRedeem(uint256 shares) public view returns (uint256) {
        return shares * totalAssets / totalSupply;
    }

    function previewDeposit(uint256 assets) public view returns (uint256) {
        return assets * totalSupply / totalAssets;
    }

    function poke(uint256 u) external { stored = u; }
}
"""

# NON-VACUITY MUTATION: previewRedeem (owes-out) is flipped from a mulDiv-FLOOR to a
# mulDiv-CEIL (mulDivRoundingUp) -> owes-out now rounds UP (over-pays the user) ->
# a NEW directional survivor for previewRedeem APPEARS.
_VAULT_MUTATED = _VAULT_BASE.replace(
    "        return shares * totalAssets / totalSupply;",
    "        return shares.mulDivRoundingUp(totalAssets, totalSupply);")


# Mirror pair: convertToShares (in) and convertToAssets (out) BOTH round DOWN via
# bare scaling -> round-trip protection broken (same direction on both legs).
_VAULT_MIRROR = """
contract Vault {
    function convertToShares(uint256 assets) public view returns (uint256) {
        return assets * totalSupply / totalAssets;
    }
    function convertToAssets(uint256 shares) public view returns (uint256) {
        return shares * totalAssets / totalSupply;
    }
}
"""

# No fixed-point conversion at all -> class not present (honest cited-empty).
_NO_CONV = """
contract Bank {
    function setOwner(address o) external { owner = o; }
    function flag(bool b) external { paused = b; }
}
"""

# A conversion in a function whose owed-direction cannot be classified (generic
# name) -> advisory_only=needs_source (only emitted under --emit-advisory).
_ADVISORY = """
contract Calc {
    function scaleValue(uint256 a) public view returns (uint256) {
        return a * factor / base;
    }
}
"""


def _run(src_text, fname="Vault.sol", extra=None):
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        (ws / fname).write_text(src_text)
        emit = ws / "out.jsonl"
        argv = ["--workspace", str(ws), "--src-root", str(ws),
                "--emit", str(emit), "--json"]
        if extra:
            argv += extra
        summary = mod.run(argv)
        obs = []
        if emit.is_file():
            obs = [json.loads(l) for l in emit.read_text().splitlines() if l.strip() and "examined_record" not in l]
        return summary, obs


class DirectionalRoundingAsymmetryTest(unittest.TestCase):

    def test_takes_in_rounds_down_is_survivor(self):
        summary, obs = _run(_VAULT_BASE)
        surv = {s["fn"] for s in summary["survivors"]}
        self.assertIn("previewDeposit", surv,
                      "takes-in leg rounding DOWN under-charges -> survivor")
        self.assertTrue(summary["class_present"])
        dep = next(o for o in obs if o["function"] == "previewDeposit")
        self.assertEqual(dep["owed_direction"], "takes-in")
        self.assertEqual(dep["rounding_mode"], "down")
        self.assertEqual(dep["schema"],
                         "auditooor.directional_rounding_asymmetry.v1")
        self.assertTrue(dep["source_refs"])
        self.assertIn("Vault.sol", dep["source_refs"][0])

    def test_owes_out_rounds_down_is_correct_not_survivor(self):
        # Same mulDiv-floor TOKEN, opposite direction -> NOT a survivor. The verdict
        # is directional, not token-based (a shape detector cannot make this call).
        summary, _ = _run(_VAULT_BASE)
        surv = {s["fn"] for s in summary["survivors"]}
        self.assertNotIn("previewRedeem", surv,
                         "owes-out rounding DOWN is protocol-favoring (correct)")

    def test_mutation_flip_floor_to_ceil_on_owes_out_creates_survivor(self):
        # NON-VACUITY: previewRedeem floor->ceil (owes-out now rounds UP) -> a NEW
        # survivor appears that did not exist in the base.
        base, _ = _run(_VAULT_BASE)
        mutated, mobs = _run(_VAULT_MUTATED)
        self.assertNotIn("previewRedeem", {s["fn"] for s in base["survivors"]})
        self.assertIn("previewRedeem", {s["fn"] for s in mutated["survivors"]},
                      "floor->ceil on an owes-out leg must create the survivor")
        red = next(o for o in mobs if o["function"] == "previewRedeem")
        self.assertEqual(red["owed_direction"], "owes-out")
        self.assertEqual(red["rounding_mode"], "up")

    def test_mirror_pair_same_direction_is_survivor(self):
        summary, obs = _run(_VAULT_MIRROR)
        self.assertGreaterEqual(summary["n_mirror_survivors"], 1,
                                "both legs rounding DOWN breaks round-trip protection")
        pairs = summary["mirror_survivors"]
        self.assertTrue(any(p["in"] == "convertToShares"
                            and p["out"] == "convertToAssets" for p in pairs))
        mob = next(o for o in obs
                   if o["obligation_type"] == "directional-rounding-mirror-roundtrip")
        self.assertEqual(len(mob["source_refs"]), 2)

    def test_no_conversion_is_honest_empty(self):
        summary, obs = _run(_NO_CONV, fname="Bank.sol")
        self.assertFalse(summary["class_present"])
        self.assertTrue(summary["honest_empty_class_not_present"])
        self.assertEqual(summary["n_directional_survivors"], 0)
        self.assertEqual(obs, [])

    def test_unspecified_direction_is_advisory_needs_source(self):
        # A conversion in a generically-named fn: no directional violation claimed,
        # but under --emit-advisory it is emitted advisory_only=needs_source.
        summary, obs = _run(_ADVISORY, fname="Calc.sol",
                            extra=["--emit-advisory"])
        self.assertGreaterEqual(summary["n_advisory_nodes"], 1)
        adv = next(o for o in obs
                   if o["obligation_type"] == "directional-rounding-advisory")
        self.assertEqual(adv["advisory_only"], "needs_source")
        self.assertEqual(adv["owed_direction"], "unspecified")
        # without --emit-advisory the advisory rows are NOT emitted.
        _, obs2 = _run(_ADVISORY, fname="Calc.sol")
        self.assertEqual(obs2, [])

    def test_vacuous_substrate_flagged_not_honest_empty(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)  # no source files at all
            argv = ["--workspace", str(ws), "--src-root", str(ws),
                    "--emit", str(ws / "o.jsonl"), "--json"]
            summary = mod.run(argv)
            self.assertTrue(summary["substrate_vacuous"])
            self.assertEqual(summary["n_functions_indexed"], 0)


if __name__ == "__main__":
    unittest.main()
