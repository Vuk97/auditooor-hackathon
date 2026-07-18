#!/usr/bin/env python3
"""Regression: _resolve_sidecar_harness_file resolves a mutation-verify sidecar whose runner
command uses --match-contract <Name> (not --match-path). mutation-verify-coverage.py accepts
either flag; the old resolver keyed ONLY on --match-path, so a genuinely mutation-verified
harness proven via --match-contract was dropped -> the engine-harness gate mislabeled it a
'fake/tautological stub' (Strata NeutrlSwapAdapterConservation 2026-07-07)."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

_H = Path(__file__).resolve().parent
_s = importlib.util.spec_from_file_location("eh", _H.parent / "engine-harness-proof-check.py")
m = importlib.util.module_from_spec(_s)
_s.loader.exec_module(m)


class T(unittest.TestCase):
    def _ws(self):
        ws = Path(tempfile.mkdtemp())
        d = ws / "chimera_harnesses" / "FooConservation"
        d.mkdir(parents=True)
        (d / "Sanity.t.sol").write_text("contract SanityFooTest { }")
        return ws, d / "Sanity.t.sol"

    def test_match_contract_resolves(self):
        ws, hpath = self._ws()
        rec = {"harness": f"cd {ws}/chimera_harnesses && forge test --match-contract SanityFooTest",
               "verdict": "non-vacuous"}
        got = m._resolve_sidecar_harness_file(rec, ws)
        self.assertEqual(got, hpath)

    def test_match_contract_quoted(self):
        ws, hpath = self._ws()
        rec = {"runner_command": "forge test --match-contract 'SanityFooTest' -vv"}
        self.assertEqual(m._resolve_sidecar_harness_file(rec, ws), hpath)

    def test_unknown_contract_returns_none(self):
        ws, _ = self._ws()
        rec = {"harness": "forge test --match-contract DoesNotExist"}
        self.assertIsNone(m._resolve_sidecar_harness_file(rec, ws))

    def test_match_path_still_works(self):
        ws, _ = self._ws()
        rec = {"harness": f"cd {ws}/chimera_harnesses && forge test --match-path 'FooConservation/Sanity.t.sol'"}
        got = m._resolve_sidecar_harness_file(rec, ws)
        self.assertIsNotNone(got)
        self.assertTrue(str(got).endswith("Sanity.t.sol"))


if __name__ == "__main__":
    unittest.main()
