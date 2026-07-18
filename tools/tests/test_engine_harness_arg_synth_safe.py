#!/usr/bin/env python3
# <!-- r36-rebuttal: lane ENGINE-HARNESS-ARG-SYNTH-SAFE registered in commit message -->
"""Strata 2026-06-30: evm-engine-harness-author authored an UNCOMPILABLE test tree.

Two coupled bugs in _target_call_stmt:
  1. Non-word-boundary substitution: `arg.replace("y", "uint256(0)")` spliced the
     value INTO any identifier containing that letter, e.g.
     `IStrategyAprPairProvider(x+0)` -> `IStrateguint256(0)AprPairProvider(uint256(0)+0)`
     (NUVA had the same: `ExecutorArgs` -> `Euint256(0)ecutorArgs`). The corrupted
     source broke `forge build`, so ALL 40 harnesses went uncheckable (build-broken)
     and the deep engines recorded 0 genuine coverage.
  2. _pick_target_function selects a mutating fn by NAME hint without checking the
     param types are synthesizable, so `setProvider(IStrategyAprPairProvider)` /
     `deposit(...,TDepositParams)` got picked and emitted invalid args.

Fix: omit the mutating call when any param is a non-elementary, non-address type;
use word-boundary substitution otherwise. Pins: omit for interface/struct params;
clean valid call for all-elementary params; never corrupt an identifier.
"""
import importlib.util
import re
import sys
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "evm-engine-harness-author.py"


def _load():
    spec = importlib.util.spec_from_file_location("ehauth", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["ehauth"] = m
    spec.loader.exec_module(m)
    return m


eh = _load()


def _fn(name, params, mutability="nonpayable"):
    return eh.FuncSig(name=name, params=params, visibility="external",
                      mutability=mutability, is_payable=False, returns="")


def _surf(funcs):
    return eh.ContractSurface(name="AprPairFeed", kind="contract", bases=[], functions=funcs)


class ArgSynthSafetyTest(unittest.TestCase):
    def test_interface_param_call_omitted_not_corrupted(self):
        # setProvider(IStrategyAprPairProvider) matches the 'authorization' hint ('set').
        surf = _surf([_fn("setProvider", "IStrategyAprPairProvider provider")])
        stmt = eh._target_call_stmt(surf, "authorization", x="uint256(0)", y="uint256(0)")
        # the historical corruption MUST NOT appear
        self.assertNotIn("IStrateguint256(0)AprPairProvider", stmt)
        # the call is omitted (non-synthesizable param), harness still compiles
        self.assertIn("mutating call omitted", stmt)
        self.assertNotIn("target.setProvider(", stmt)

    def test_struct_param_call_omitted(self):
        surf = _surf([_fn("deposit", "address to, TDepositParams params")])
        stmt = eh._target_call_stmt(surf, "conservation", x="uint256(0)", y="uint256(0)")
        self.assertIn("mutating call omitted", stmt)
        self.assertNotIn("TDepositParams(uint256(0)", stmt)

    def test_elementary_params_emit_valid_call(self):
        surf = _surf([_fn("deposit", "uint256 amount, address actor")])
        stmt = eh._target_call_stmt(surf, "conservation", x="uint256(0)", y="uint256(0)",
                                    actor="address(this)")
        self.assertIn("target.deposit(", stmt)
        self.assertIn("uint256(0)", stmt)
        # no stray bare placeholder identifiers left
        self.assertNotRegex(stmt, r"\bx\b")
        self.assertNotRegex(stmt, r"\by\b")

    def test_array_param_synthesized_as_empty_array_not_scalar(self):
        # bool[]/address[]/bytes[] must become `new T[](0)`, NOT a scalar (which
        # fails to compile - the Strata addAutoWithdrawals(address,bool[]) break).
        self.assertEqual(eh._solidity_arg_for_type("bool[]", 0), "new bool[](0)")
        self.assertEqual(eh._solidity_arg_for_type("address[]", 1), "new address[](0)")
        self.assertEqual(eh._solidity_arg_for_type("bytes32[]", 2), "new bytes32[](0)")
        self.assertEqual(eh._solidity_arg_for_type("uint256[]", 3), "new uint256[](0)")
        # scalar bool still a scalar
        self.assertEqual(eh._solidity_arg_for_type("bool", 0), "(x & 1) == 1")

    def test_bool_array_call_compiles_shape(self):
        surf = _surf([_fn("addAutoWithdrawals", "address who, bool[] flags")])
        stmt = eh._target_call_stmt(surf, "conservation", x="uint256(0)", y="uint256(0)",
                                    actor="address(this)")
        # the call IS emitted (all params elementary) with an empty array, no scalar bool
        self.assertIn("new bool[](0)", stmt)
        self.assertNotIn("(uint256(0) & 1) == 1", stmt)

    def test_word_boundary_does_not_corrupt_identifier(self):
        # An elementary arg string carrying an identifier with x/y must be untouched
        # by the placeholder substitution.
        arg = "proxyType(x + 0)"  # contains 'x' inside 'proxy'
        out = re.sub(r"\bx\b", "uint256(0)", arg)
        self.assertEqual(out, "proxyType(uint256(0) + 0)")
        self.assertIn("proxyType", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
