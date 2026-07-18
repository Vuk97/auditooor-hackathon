// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// FP regression: a variable is stamped as a division result, then REASSIGNED to a
// fresh non-division value before the multiply. The multiply consumes the fresh
// value, NOT the quotient, so this is NOT a divide-before-multiply ordering -> NOT
// FLAGGED. The forward div-result tracker must KILL the stale stamp on reassignment.
contract DivThenReassignClean {
    // x = amount / rate;  x = fresh;  return x * shares;
    // The multiply uses `fresh`, not the quotient. NOT flagged.
    function reassignThenMul(
        uint256 amount,
        uint256 rate,
        uint256 fresh,
        uint256 shares
    ) external pure returns (uint256) {
        uint256 x = amount / rate;
        x = fresh;
        return x * shares;
    }

    // Branch-reassign variant: the div result is overwritten on a conditional path
    // with a non-div value before the multiply. Conservative tracker still NOT flagged
    // because the stamp is killed on the reassignment.
    function branchReassignThenMul(
        uint256 amount,
        uint256 rate,
        uint256 fresh,
        uint256 shares,
        bool useFresh
    ) external pure returns (uint256) {
        uint256 x = amount / rate;
        if (useFresh) {
            x = fresh;
        }
        return x * shares;
    }
}
