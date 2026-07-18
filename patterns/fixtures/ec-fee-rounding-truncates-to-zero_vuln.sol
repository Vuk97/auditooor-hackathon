// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: fee = amount * bps / 10000 truncates to 0 for small amounts
// Loss ref: Sushiswap Kashi rounding / general fee-bypass pattern
// https://github.com/sushiswap/kashi-lending/issues/10
contract FeeVuln {
    uint256 public constant FEE_BPS = 30; // 0.30%
    uint256 public collectedFees;

    // VULN: fee truncates to 0 for amount < 10000/30 = 333
    function swap(uint256 amountIn) external returns (uint256 amountOut) {
        uint256 fee = amountIn * FEE_BPS / 10000; // floor division — 0 for small amounts
        collectedFees += fee;
        amountOut = amountIn - fee;
        // For amountIn = 100: fee = 100 * 30 / 10000 = 0 (fee bypass!)
    }
}
