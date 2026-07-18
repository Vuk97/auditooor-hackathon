// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Divide-before-multiply precision loss on value-moving operands.
// `(amount / rate) * shares` truncates the quotient BEFORE scaling -> precision
// loss vs the correct `(amount * shares) / rate`. FLAGGED.
contract DivBeforeMulSuspect {
    function payout(uint256 amount, uint256 rate, uint256 shares)
        external
        pure
        returns (uint256)
    {
        uint256 r = (amount / rate) * shares;
        return r;
    }

    // Indirect form: the quotient is bound to a named local before the multiply.
    // The IR lowers the copy as an Assignment of the division temp -> still FLAGGED.
    function payoutIndirect(uint256 balance, uint256 rate, uint256 shares)
        external
        pure
        returns (uint256)
    {
        uint256 q = balance / rate;
        uint256 r = q * shares;
        return r;
    }
}
