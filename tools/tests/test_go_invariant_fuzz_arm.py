"""invariant-fuzz-completeness Go-arm (SEI 2026-07-05).

A Go/Cosmos L1's invariant-fuzz bar is met by go-native coverage-guided fuzz +
mutation-verified App-bound Go economic invariants, NOT .sol harnesses. The arm
credits that - but must NEVER false-green a Solidity-dominant audit.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "invariant-fuzz-completeness.py"
_spec = importlib.util.spec_from_file_location("ifc", str(_TOOL))
ifc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ifc)


def _ws(go_units, sol_units, mvc_sidecars):
    d = Path(tempfile.mkdtemp())
    ad = d / ".auditooor"
    (ad / "mvc_sidecar").mkdir(parents=True)
    man = ad / "inscope_units.jsonl"
    rows = ([json.dumps({"file": f"x/m/keeper{i}.go", "function": "F"}) for i in range(go_units)]
            + [json.dumps({"file": f"src/C{i}.sol", "function": "f"}) for i in range(sol_units)])
    man.write_text("\n".join(rows) + "\n")
    for i, sc in enumerate(mvc_sidecars):
        (ad / "mvc_sidecar" / f"go_inv_{i}.json").write_text(json.dumps(sc))
    return d


_MV = {"engine": "go-test", "lang": "go", "mutation_verified": True, "verdict": "non-vacuous"}
_FUZZ = {"engine": "go-native-coverage-guided-fuzz", "lang": "go", "campaign_calls": 30, "fuzztime": "120s"}


class GoArmTest(unittest.TestCase):
    def test_go_dominant_strong_mv_credits(self):
        ev = ifc._go_invariant_fuzz_evidence(_ws(100, 2, [_MV, _MV, _MV]))
        self.assertTrue(ev["go_dominant"])
        self.assertGreaterEqual(ev["mutation_verified"], 3)
        self.assertTrue(ev["strong"])

    def test_go_dominant_fuzz_campaign_credits(self):
        ev = ifc._go_invariant_fuzz_evidence(_ws(100, 2, [_FUZZ]))
        self.assertEqual(ev["fuzz_campaigns"], 1)
        self.assertTrue(ev["strong"])

    def test_solidity_dominant_never_credits(self):
        # 50/50 Go/Sol with genuine go evidence -> NOT go-dominant -> arm must not fire.
        ev = ifc._go_invariant_fuzz_evidence(_ws(50, 50, [_MV, _MV, _MV, _FUZZ]))
        self.assertFalse(ev["go_dominant"])
        # evaluate() must NOT return the go-arm verdict for a non-go-dominant ws.
        res = ifc.evaluate(_ws(50, 50, [_MV, _MV, _MV, _FUZZ]))
        self.assertNotEqual(res.get("verdict"), "pass-go-native-invariant-fuzz")

    def test_go_dominant_weak_evidence_does_not_credit(self):
        # go-dominant but no mutation-verified / no fuzz -> not strong -> arm off.
        ev = ifc._go_invariant_fuzz_evidence(_ws(100, 1, [{"engine": "go-test", "lang": "go"}]))
        self.assertFalse(ev["strong"])

    def test_evaluate_go_arm_pass_on_strong_go_dominant(self):
        res = ifc.evaluate(_ws(100, 2, [_MV, _MV, _MV, _FUZZ]))
        self.assertEqual(res.get("verdict"), "pass-go-native-invariant-fuzz")


if __name__ == "__main__":
    unittest.main()
