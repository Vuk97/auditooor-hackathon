#!/usr/bin/env python3
"""Regression: the Solidity variant-arm pairer only pairs same-named functions
whose contracts share a DOMAIN base/interface (kills name-collision noise like
`balanceOf` across a lens and a cooldown), but keeps true siblings (shared
IUnstakeHandler) and fails open when a contract has no parseable base."""
import importlib.util
import sys
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_MOD = _HERE.parent / "sibling-path-guard-diff.py"
_spec = importlib.util.spec_from_file_location("spgd_shared_base_test", _MOD)
_m = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _m  # register before exec (Python 3.14 dataclass module-resolution)
_spec.loader.exec_module(_m)


def _arm(name, file, guards, bases):
    return _m.FnArm(name=name, file=file, line=1, guards=set(guards),
                    bases=frozenset(bases))


class TestSharedBaseGate(unittest.TestCase):
    def _pairs(self, arms):
        return _m._pair_variant_arms(arms)

    def test_disjoint_domain_bases_not_paired(self):
        # balanceOf across a lens (IIntegration) and a cooldown (IUnstakeCooldown):
        # unrelated contracts sharing only a name -> NOT a sibling variant.
        arms = [
            _arm("balanceOf", "lens/TermmaxIntegration.sol", ["onlyowner"], ["IIntegration", "OwnableUpgradeable"]),
            _arm("balanceOf", "cooldown/UnstakeCooldown.sol", [], ["IUnstakeCooldown", "CooldownBase"]),
        ]
        self.assertEqual(len(self._pairs(arms)), 0)

    def test_shared_domain_base_is_paired(self):
        # true siblings: both implement IUnstakeHandler -> real variant arms.
        arms = [
            _arm("finalize", "strategies/midas/MidasCooldownRequestImpl.sol", ["hasactiverequest"], ["IUnstakeHandler", "Initializable"]),
            _arm("finalize", "strategies/ethena/sUSDeCooldownRequestImpl.sol", [], ["IUnstakeHandler", "Initializable"]),
        ]
        self.assertEqual(len(self._pairs(arms)), 1)

    def test_baseless_contract_fails_open_paired(self):
        # a contract with no parseable base -> keep the pair (never drop on uncertainty).
        arms = [
            _arm("verify", "a/Foo.sol", ["onlyowner"], []),
            _arm("verify", "b/Bar.sol", [], ["ISomething"]),
        ]
        self.assertEqual(len(self._pairs(arms)), 1)

    def test_only_generic_bases_shared_not_paired(self):
        # sharing ONLY a generic base (Ownable) is not evidence of a shared role.
        arms = [
            _arm("balanceOf", "a/Foo.sol", ["onlyowner"], ["IFoo", "Ownable"]),
            _arm("balanceOf", "b/Bar.sol", [], ["IBar", "Ownable"]),
        ]
        self.assertEqual(len(self._pairs(arms)), 0)


if __name__ == "__main__":
    unittest.main()
