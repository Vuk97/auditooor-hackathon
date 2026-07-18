// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (W4 FP-fix #2): the panel's transitive FALSE POSITIVE. An INTERNAL helper
// `_fetchPrice()` makes an external VIEW call (STATICCALL); the caller writes state
// AFTER the helper. The view call cannot reenter-and-write, so the helper is NOT
// ext-bearing for the CEI marker -> NOT flagged. Pins that the transitive marker
// (W4) only propagates STATE-MUTATING external calls, not view/pure ones.
interface IPriceOracle {
    function getPrice() external view returns (uint256);
}

contract InterprocCeiViewViaHelperClean {
    IPriceOracle public oracle;
    uint256 public lastPrice;
    uint256 public balance;

    function update() external {
        _fetchPrice();      // INTERNAL helper that only does an external VIEW call
        lastPrice = 1;      // state-writes AFTER the view-only helper: CEI-SAFE
        balance = 2;
    }

    function _fetchPrice() internal view returns (uint256) {
        return oracle.getPrice();   // external VIEW call -> STATICCALL inside the helper
    }
}
