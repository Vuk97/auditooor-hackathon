// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

library Math {
    enum Rounding { Floor, Ceil }

    function mulDiv(uint256 a, uint256 b, uint256 c, Rounding r) internal pure returns (uint256) {
        if (r == Rounding.Ceil) {
            return (a * b + c - 1) / c;
        }
        return (a * b) / c;
    }
}

struct SwapContext {
    uint256 tokenInIndex;
    uint256 tokenOutIndex;
    uint256[] scaledReserves;
}

struct SwapResult {
    uint256 amountIn;
    uint256 amountOut;
}

contract CleanSwap {
    uint256[] public reserves;
    uint256[] private rates;

    function _getRate(uint256 i) internal view returns (uint256) {
        return rates[i];
    }

    /// CLEAN: required input rounds Ceil (user owes the pool -> Ceil).
    function _swapExactOutput(uint256 _amountOut, SwapContext memory _ctx)
        private
        returns (SwapResult memory result)
    {
        uint256 rawAmountIn = Math.mulDiv(
            _amountOut,
            _getRate(_ctx.tokenInIndex),
            1e18,
            Math.Rounding.Ceil
        );

        result.amountIn = rawAmountIn;
        result.amountOut = _amountOut;

        reserves[_ctx.tokenInIndex] += result.amountIn;
        reserves[_ctx.tokenOutIndex] -= result.amountOut;
    }
}
