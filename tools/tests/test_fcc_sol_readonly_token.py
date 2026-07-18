#!/usr/bin/env python3
"""Regression: the Solidity view/pure read-only exclusion must fire under the
ENUMERATOR's lang token ("sol"), not just the long name "solidity".

Before 2026-06-27 _is_read_only checked `low in ("solidity", "vyper")`, but the
enumerator passes the _LANG_BY_EXT token ".sol" -> "sol". So the documented
Solidity read-only drop was DEAD: every `view`/`pure` getter (decimals, name,
symbol, *Length, get*) was counted as an in-scope function, inflating the
coverage denominator on every .sol workspace and making the gate harder than
designed. A view/pure fn cannot mutate state or move funds (EVM reverts on a
state write), so it has no per-function attack surface and is safe to drop.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "function-coverage-completeness.py"
_s = importlib.util.spec_from_file_location("function_coverage_completeness", _T)
fcc = importlib.util.module_from_spec(_s)
sys.modules["function_coverage_completeness"] = fcc
_s.loader.exec_module(fcc)


class SolReadonlyTokenTest(unittest.TestCase):
    SOL_VIEWS = [
        ("decimals", "function decimals() public view override(ERC20, ERC4626) returns (uint8) {"),
        ("name", "function name() public view override(IERC20Metadata, ERC20) returns (string memory) {"),
        ("symbol", "function symbol() public view returns (string memory) {"),
        ("supplyQueueLength", "function supplyQueueLength() external view returns (uint256) {"),
        ("totalAssets", "function totalAssets() public view returns (uint256) {"),
    ]

    def test_sol_token_drops_view_getters(self):
        for name, sig in self.SOL_VIEWS:
            self.assertTrue(
                fcc._is_read_only(name, sig, "sol", ""),
                f"{name}: view fn must be read-only under lang token 'sol'")
            self.assertTrue(
                fcc._is_nonattack_boilerplate(name, sig, "sol", ""),
                f"{name}: view fn must be excluded as non-attack boilerplate")

    def test_long_name_still_works(self):
        self.assertTrue(fcc._is_read_only("decimals",
            "function decimals() public view returns (uint8) {", "solidity", ""))

    def test_mutator_is_NOT_dropped(self):
        # A state-mutating fn (no view/pure) must SURVIVE - never silently dropped.
        for name, sig in [
            ("deposit", "function deposit(uint256 assets, address to) external returns (uint256) {"),
            ("setFee", "function setFee(uint256 newFee) external {"),
            ("morphoSupply", "function morphoSupply(MarketParams memory mp, uint256 a) external {"),
        ]:
            self.assertFalse(fcc._is_read_only(name, sig, "sol", ""),
                             f"{name}: mutator must NOT be classed read-only")
            self.assertFalse(fcc._is_nonattack_boilerplate(name, sig, "sol", ""),
                             f"{name}: mutator must NOT be excluded")


if __name__ == "__main__":
    unittest.main()
