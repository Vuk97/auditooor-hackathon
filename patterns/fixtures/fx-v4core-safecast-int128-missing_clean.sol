// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.20;

// Fixture: fixed SafeCast — toUint128(int128) added with explicit negative-value guard.
// Source: Uniswap/v4-core@d47ecf9 (SafeCast int128 to uint128 audit fix)

contract Fix {
    error SafeCastOverflow();

    function toInt128(int256 x) internal pure returns (int128 y) {
        y = int128(x);
        if (x != y) revert SafeCastOverflow();
    }

    function toUint128(uint256 x) internal pure returns (uint128 y) {
        y = uint128(x);
        if (x != y) revert SafeCastOverflow();
    }

    // ADDED: int128 -> uint128 with sign check — prevents silent negative wrap
    function toUint128(int128 x) internal pure returns (uint128 y) {
        if (x < 0) revert SafeCastOverflow();
        y = uint128(x);
    }

    // Caller is now safe
    function applyDelta(int128 delta) external pure returns (uint128) {
        return toUint128(delta); // reverts on negative delta
    }
}
