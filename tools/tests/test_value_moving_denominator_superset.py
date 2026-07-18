#!/usr/bin/env python3
"""Regression: the value-moving-file denominator (invariant-fuzz asset-coverage +
core-coverage) is a SUPERSET that catches accounting-writers / delegating
orchestrators / external-call value-movers the value_moving_functions.json producer
misses. Strata 2026-07-07: DiscreteAccounting (re-scope successor computing the NAV
split), StrataCDO, SharesCooldown and the strategies were absent from the denominator,
so their total lack of an economic-invariant harness never lowered coverage and the
gate FALSELY reported "5/6 covered, pass-invariant-fuzz-complete / fully audited"."""
import importlib.util, json, sys, tempfile, unittest
from pathlib import Path
_H = Path(__file__).resolve().parent
_s = importlib.util.spec_from_file_location("ifc", _H.parent / "invariant-fuzz-completeness.py")
_m = importlib.util.module_from_spec(_s); sys.modules["ifc"] = _m; _s.loader.exec_module(_m)


class T(unittest.TestCase):
    def _ws(self, files: dict):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir(parents=True)
        src = ws / "src"; src.mkdir()
        lines = []
        for name, body in files.items():
            (src / name).write_text(body)
            lines.append(json.dumps({"file": f"src/{name}", "function": "x"}))
        (ws / ".auditooor" / "inscope_units.jsonl").write_text("\n".join(lines))
        return ws

    def test_accounting_writer_counted(self):
        # a NAV-split writer with no transfer/no value_moving_functions.json is value-moving
        ws = self._ws({"DiscreteAccounting.sol":
                       "contract D { function updateBalanceFlow(uint a) external { srtNav = a; } }"})
        vm = _m._value_moving_inscope_files(ws)
        self.assertTrue(any("DiscreteAccounting" in f for f in vm), vm)

    def test_erc4626_value_mover_counted(self):
        ws = self._ws({"S.sol": "contract S { function withdraw(uint a) external returns(uint){ return a; } }"})
        self.assertTrue(_m._value_moving_inscope_files(ws), "withdraw fn file must be value-moving")

    def test_external_transfer_counted(self):
        ws = self._ws({"T.sol": "contract T { function pay() external { token.safeTransfer(x, 1); } }"})
        self.assertTrue(_m._value_moving_inscope_files(ws))

    def test_pure_view_config_NOT_counted(self):
        # never-false-widen: a view-only / config file matches nothing
        ws = self._ws({"Lens.sol":
                       "contract L { function getX() external view returns(uint){ return 1; } "
                       "uint public owner; }"})
        self.assertEqual(_m._value_moving_inscope_files(ws), set())

    def test_only_internal_not_counted(self):
        # an internal-only accounting helper (no external entrypoint) is not a file entrypoint
        ws = self._ws({"Int.sol": "contract I { function _calc(uint a) internal { nav = a; } }"})
        self.assertEqual(_m._value_moving_inscope_files(ws), set())


if __name__ == "__main__":
    unittest.main()


class TFuzzedCutFallback(unittest.TestCase):
    """A mutation-verified mvc_sidecar with EMPTY source_file/cut is credited to its
    filename-matched in-scope target; a non-matching name credits nothing."""
    def _ws(self, inscope_files, sidecar):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor" / "mvc_sidecar").mkdir(parents=True)
        (ws / ".auditooor" / "inscope_units.jsonl").write_text(
            "\n".join(json.dumps({"file": f, "function": "x"}) for f in inscope_files))
        (ws / ".auditooor" / "mvc_sidecar" / "s.json").write_text(json.dumps(sidecar))
        return ws

    def test_filename_fallback_credits_matched_target(self):
        ws = self._ws(["src/SharesCooldown.sol"],
                      {"source_file": "", "cut": None, "mutation_verified": True,
                       "engine": "medusa", "campaign_calls": 1_200_000})
        # rename sidecar to encode the target
        d = ws / ".auditooor" / "mvc_sidecar"
        (d / "s.json").rename(d / "mvc-src-sharescooldownfeeconservation.json")
        self.assertIn("src/SharesCooldown.sol", _m._fuzzed_cut_files(ws))

    def test_no_match_credits_nothing(self):
        ws = self._ws(["src/SharesCooldown.sol"],
                      {"source_file": "", "mutation_verified": True})
        d = ws / ".auditooor" / "mvc_sidecar"
        (d / "s.json").rename(d / "mvc-src-somethingunrelated.json")
        self.assertEqual(_m._fuzzed_cut_files(ws), set())

    def test_not_mutation_verified_no_fallback(self):
        # never-false: a non-mutation-verified sidecar gets no filename fallback
        ws = self._ws(["src/SharesCooldown.sol"],
                      {"source_file": "", "mutation_verified": False, "verdict": "survived"})
        d = ws / ".auditooor" / "mvc_sidecar"
        (d / "s.json").rename(d / "mvc-src-sharescooldownfeeconservation.json")
        self.assertEqual(_m._fuzzed_cut_files(ws), set())
