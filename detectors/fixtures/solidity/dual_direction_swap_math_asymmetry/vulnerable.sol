// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// Vulnerable: `_swapExactInput` deducts fee from output (`x - fee`)
/// while `_swapExactOutput` adds fee on top of input (`y + fee`).
/// Effective fee rate is direction-dependent — arbitrage extractable
/// across split swaps. (Revert Cantina #102 shape.)
contract VulnerableSwap {
    struct SwapResult {
        uint256 amountIn;
        uint256 amountOut;
        uint256 totalFees;
    }

    function _swapExactInput(uint256 _amountIn) internal pure returns (SwapResult memory result) {
        uint256 rawAmountOut = _amountIn * 997 / 1000; // mock curve
        uint256 totalFees = rawAmountOut / 100;        // 1% fee
        result.amountIn = _amountIn;
        // VULN: fee subtracted from output
        result.amountOut = rawAmountOut - totalFees;
        result.totalFees = totalFees;
    }

    function _swapExactOutput(uint256 _amountOut) internal pure returns (SwapResult memory result) {
        uint256 rawAmountIn = _amountOut * 1000 / 997; // mock curve
        uint256 totalFees = rawAmountIn / 100;
        result.amountOut = _amountOut;
        // VULN: fee added on top of input → effective fee is
        // rawAmountIn / (rawAmountIn + fee), which differs from
        // rawAmountOut / (rawAmountOut - fee) computed above.
        result.amountIn = rawAmountIn + totalFees;
        result.totalFees = totalFees;
    }
}
