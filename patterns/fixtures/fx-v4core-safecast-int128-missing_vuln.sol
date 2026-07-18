// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.20;

// Fixture: SafeCast library missing int128->uint128 helper — callers use unchecked direct cast.
// Source: Uniswap/v4-core@d47ecf9 (SafeCast int128 to uint128 audit fix)
// Vulnerability: Without a dedicated toUint128(int128) function, callers must cast manually.
// A direct `uint128(int128_value)` silently wraps negative values (e.g., -1 becomes 2^128-1).
// In PoolManager, BalanceDelta stores deltas as int128; converting a negative delta to uint128
// without a sign check enables silent underflow that corrupts balance accounting.

contract Fix {
    error SafeCastOverflow();

    // EXISTS: int256 -> int128
    function toInt128(int256 x) internal pure returns (int128 y) {
        y = int128(x);
        if (x != y) revert SafeCastOverflow();
    }

    // EXISTS: uint256 -> uint128
    function toUint128(uint256 x) internal pure returns (uint128 y) {
        y = uint128(x);
        if (x != y) revert SafeCastOverflow();
    }

    // MISSING: int128 -> uint128 with sign check
    // Callers are forced to write: uint128(int128_value)  -- wraps silently on negative

    // Example caller that is unsafe without the helper
    function applyDelta(int128 delta) external pure returns (uint128) {
        // VULNERABLE: no sign check; if delta < 0 this silently wraps
        return uint128(delta);
    }
}
