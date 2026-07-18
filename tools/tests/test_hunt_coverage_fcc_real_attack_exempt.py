#!/usr/bin/env python3
"""Regression: hunt-coverage-gate credits function-coverage-completeness real-attack
units as scanned (serving-join). SSV 2026-06-26: function-coverage reported 217/217
fully-covered while hunt-coverage flagged 112 queued-not-scanned - the 112 WERE hunted
(finding-attack / mutation-killed / finding-clean-trivial evidence) but this gate's narrow
scan-artifact reader missed the SSVNetwork facade entrypoints + clean-trivial getters.
Only real-attack with non-empty evidence is credited (hollow/untouched stay flagged) so the
exemption is never-false-pass."""
import importlib.util
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "hunt-coverage-gate.py"
_s = importlib.util.spec_from_file_location("hcg_fcc_ra", _T)
hcg = importlib.util.module_from_spec(_s)
_s.loader.exec_module(hcg)


class FccRealAttackExemptTest(unittest.TestCase):
    def test_real_attack_with_evidence_credited(self):
        keys = hcg._fcc_real_attack_keys({
            "functions": [
                {"classification": "real-attack", "function": "registerOperator",
                 "file": "src/ssv-network/contracts/SSVNetwork.sol",
                 "evidence": ["mutation-killed:SSVNetwork.sol:registerOperator:112"]},
            ]
        })
        self.assertIn(("ssvnetwork.sol", "registerOperator"), keys)
        # facade unit (basename::fn) is credited
        self.assertTrue(
            hcg._unit_in_fcc_real_attack("SSVNetwork.sol::registerOperator", keys)
        )
        # path-prefixed unit also matches by basename
        self.assertTrue(
            hcg._unit_in_fcc_real_attack(
                "src/ssv-network/contracts/SSVNetwork.sol::registerOperator", keys
            )
        )

    def test_hollow_and_untouched_never_credited(self):
        keys = hcg._fcc_real_attack_keys({
            "functions": [
                {"classification": "hollow", "function": "h", "file": "A.sol",
                 "evidence": []},
                {"classification": "untouched", "function": "u", "file": "A.sol",
                 "evidence": []},
            ]
        })
        self.assertEqual(keys, set())
        self.assertFalse(hcg._unit_in_fcc_real_attack("A.sol::h", keys))
        self.assertFalse(hcg._unit_in_fcc_real_attack("A.sol::u", keys))

    def test_real_attack_with_empty_evidence_not_credited(self):
        # never-false-pass: a real-attack record must carry evidence
        keys = hcg._fcc_real_attack_keys({
            "functions": [
                {"classification": "real-attack", "function": "x", "file": "A.sol",
                 "evidence": []},
            ]
        })
        self.assertEqual(keys, set())

    def test_file_only_unit_never_matches(self):
        keys = {("a.sol", "f")}
        self.assertFalse(hcg._unit_in_fcc_real_attack("a.sol", keys))

    def test_empty_or_bad_payload_degrades_to_empty(self):
        self.assertEqual(hcg._fcc_real_attack_keys(None), set())
        self.assertEqual(hcg._fcc_real_attack_keys({}), set())
        self.assertEqual(hcg._fcc_real_attack_keys({"functions": None}), set())

    def test_distinct_basenames_disambiguate_facade_vs_module(self):
        # SSVNetwork.sol::registerOperator (facade) and SSVOperators.sol::registerOperator
        # (module) are distinct keys; crediting one must not credit the other.
        keys = hcg._fcc_real_attack_keys({
            "functions": [
                {"classification": "real-attack", "function": "registerOperator",
                 "file": "src/SSVOperators.sol", "evidence": ["finding-attack:x"]},
            ]
        })
        self.assertTrue(hcg._unit_in_fcc_real_attack("SSVOperators.sol::registerOperator", keys))
        self.assertFalse(hcg._unit_in_fcc_real_attack("SSVNetwork.sol::registerOperator", keys))


if __name__ == "__main__":
    unittest.main()
