// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

library StableSwapMath {
    function descale(uint256 scaled, uint256 rate) internal pure returns (uint256) {
        return scaled / rate; // floor
    }
}

struct SwapContext {
    uint256 tokenInIndex;
    uint256 tokenOutIndex;
    uint256[] scaledReserves;
    uint256 amp;
    uint256 invariant;
}

struct SwapResult {
    uint256 amountIn;
    uint256 amountOut;
}

contract VulnerableSwap {
    uint256[] public reserves;
    uint256[] private rates;

    function _getRate(uint256 i) internal view returns (uint256) {
        return rates[i];
    }

    /// VULN: descale rounds floor; required input may be 0 raw on
    /// low-decimal tokens.
    function _swapExactOutput(uint256 _amountOut, SwapContext memory _ctx)
        private
        returns (SwapResult memory result)
    {
        uint256 newOut = _ctx.scaledReserves[_ctx.tokenOutIndex] - _amountOut;
        uint256 newIn = _ctx.scaledReserves[_ctx.tokenInIndex] + 1; // dummy

        uint256 rawAmountIn = StableSwapMath.descale(
            newIn - _ctx.scaledReserves[_ctx.tokenInIndex],
            _getRate(_ctx.tokenInIndex)
        );

        result.amountIn = rawAmountIn;
        result.amountOut = _amountOut;

        reserves[_ctx.tokenInIndex] += result.amountIn;
        reserves[_ctx.tokenOutIndex] -= result.amountOut;

        // unused
        newOut;
    }
}
