// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.20;

// Fixture: exact-output swap guard uses == instead of >= for MAX_SWAP_FEE check.
// Source: Uniswap/v4-core@1755bfc (trail of bits i01) / 0bb382b (Spearbit M01)
// Vulnerability: Protocol allows dynamic LP fees (set by hook) up to MAX_LP_FEE + protocol fee.
// Combined swapFee (lpFee + protocolFee) can exceed MAX_SWAP_FEE without equaling it exactly.
// The guard `swapFee == MAX_SWAP_FEE` only catches one specific value; fees just above it
// bypass the check, causing exact-output swaps to loop or produce incorrect amounts.

contract Fix {
    uint24 internal constant MAX_SWAP_FEE = 1_000_000; // 100%

    error InvalidFeeForExactOut();

    // VULNERABLE: == comparison instead of >=
    // A protocol fee that pushes swapFee to 1_000_001 bypasses this guard entirely
    function swap(uint24 swapFee, bool exactInput, int256 amountSpecified) external pure returns (int256) {
        if (swapFee == MAX_SWAP_FEE) { // BUG: should be >=
            if (!exactInput) {
                revert InvalidFeeForExactOut();
            }
        }
        // ... swap math that breaks when swapFee >= MAX_SWAP_FEE and !exactInput
        return amountSpecified;
    }
}
