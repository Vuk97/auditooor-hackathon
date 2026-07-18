// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Multiply-before-divide is the CORRECT scale-then-divide ordering: scale first,
// THEN divide, so no quotient is truncated before scaling. NOT flagged.
contract MulBeforeDivClean {
    function payout(uint256 amount, uint256 rate, uint256 shares)
        external
        pure
        returns (uint256)
    {
        uint256 r = (amount * shares) / rate;
        return r;
    }
}
