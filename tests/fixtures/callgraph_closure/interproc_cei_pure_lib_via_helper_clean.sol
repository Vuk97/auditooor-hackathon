// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (W4 FP-fix #3): the panel's second transitive FALSE POSITIVE. An INTERNAL
// helper `_accumulate()` calls an EXTERNAL `pure` library function (STATICCALL); the
// caller writes state AFTER the helper. A pure external call cannot reenter-and-write,
// so the helper is NOT ext-bearing for the CEI marker -> NOT flagged.
library MathLib {
    // external pure -> compiles to a STATICCALL at the call site
    function calc(uint256 a, uint256 b) external pure returns (uint256) {
        return a + b;
    }
}

contract InterprocCeiPureLibViaHelperClean {
    uint256 public total;
    uint256 public count;

    function bump(uint256 a, uint256 b) external {
        _accumulate(a, b);   // INTERNAL helper that only does an external PURE lib call
        total = 7;           // state-writes AFTER the pure-only helper: CEI-SAFE
        count = 1;
    }

    function _accumulate(uint256 a, uint256 b) internal view returns (uint256) {
        return MathLib.calc(a, b);   // external PURE library call -> STATICCALL
    }
}
