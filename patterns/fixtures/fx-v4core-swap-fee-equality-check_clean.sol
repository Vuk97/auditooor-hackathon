// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.20;

// Fixture: fixed swap fee boundary check — uses >= to catch all above-max values.
// Source: Uniswap/v4-core@1755bfc (trail of bits i01) / 0bb382b (Spearbit M01)

contract Fix {
    uint24 internal constant MAX_SWAP_FEE = 1_000_000; // 100%

    error InvalidFeeForExactOut();

    // FIXED: >= catches swapFee == MAX_SWAP_FEE AND any higher value
    function swap(uint24 swapFee, bool exactInput, int256 amountSpecified) external pure returns (int256) {
        if (swapFee >= MAX_SWAP_FEE) { // FIXED
            if (!exactInput) {
                revert InvalidFeeForExactOut();
            }
        }
        return amountSpecified;
    }
}
