// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// Clean: both directions gross-up the user-leg by the symmetric
/// `(1 - f)` factor before/after curve, so effective fee rate is
/// equal in both directions.
contract CleanSwap {
    struct SwapResult {
        uint256 amountIn;
        uint256 amountOut;
        uint256 totalFees;
    }

    uint256 internal constant FEE_DENOM = 1e18;

    function _swapExactInput(uint256 _amountIn, uint256 _f) internal pure returns (SwapResult memory result) {
        // gross-up: deduct fee on the input BEFORE curve, then curve
        uint256 amountInNet = _amountIn * (FEE_DENOM - _f) / FEE_DENOM;
        uint256 rawAmountOut = amountInNet * 997 / 1000;
        result.amountIn = _amountIn;
        result.amountOut = rawAmountOut;
        result.totalFees = _amountIn - amountInNet;
    }

    function _swapExactOutput(uint256 _amountOut, uint256 _f) internal pure returns (SwapResult memory result) {
        // gross-up: add fee on the input via the SAME `(1 - f)` form
        // (NOT `(1 + f)`), so effective rate matches the input path.
        uint256 rawAmountIn = _amountOut * 1000 / 997;
        uint256 amountInGross = rawAmountIn * FEE_DENOM / (FEE_DENOM - _f);
        result.amountOut = _amountOut;
        result.amountIn = amountInGross;
        result.totalFees = amountInGross - rawAmountIn;
    }
}
