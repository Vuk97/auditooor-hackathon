// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: Every sell-side function accepts a caller-supplied minReceived /
// minAmountOut / _minOut and forwards it to the swap, or enforces a
// post-swap `require(out >= …)`. The negative guard regex sees the
// slippage idiom and the detector does NOT fire.

interface IRouter {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory);
}

interface ICurvePool {
    function exchange(int128 i, int128 j, uint256 dx, uint256 minDy) external returns (uint256);
}

contract AsymmetricSlippageClean {
    IRouter    public immutable router;
    ICurvePool public immutable pool;
    uint256    public minOutputAmount;  // keeper-configured for internal helpers

    constructor(address _r, address _p) {
        router = IRouter(_r);
        pool   = ICurvePool(_p);
    }

    // CLEAN 1: sellToken forwards amountOutMin to the router.
    function sellToken(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path
    ) external returns (uint256 out) {
        uint256[] memory amounts = router.swapExactTokensForTokens(
            amountIn, amountOutMin, path, msg.sender, block.timestamp
        );
        out = amounts[amounts.length - 1];
        require(out >= amountOutMin, "sell: min");
    }

    // CLEAN 2: exitPosition forwards minAmountOut to Curve exchange.
    function exitPosition(uint256 amountIn, uint256 minAmountOut) external returns (uint256 got) {
        got = pool.exchange(1, 0, amountIn, minAmountOut);
        require(got >= minAmountOut, "exit: min");
    }

    // CLEAN 3: redeemForStable uses _minOut parameter name explicitly.
    function redeemForStable(
        uint256 amountIn,
        uint256 _minOut,
        address[] calldata path
    ) external returns (uint256 out) {
        uint256[] memory amounts = router.swapExactTokensForTokens(
            amountIn, _minOut, path, msg.sender, block.timestamp
        );
        out = amounts[amounts.length - 1];
    }

    // CLEAN 4: _withdrawRewards reads a keeper-configured minOutputAmount
    // from storage and forwards it; regex sees `minOutputAmount` and
    // suppresses the match.
    function _withdrawRewards() external returns (uint256 out) {
        address[] memory path = new address[](2);
        uint256[] memory amounts = router.swapExactTokensForTokens(
            1e18, minOutputAmount, path, address(this), block.timestamp
        );
        out = amounts[amounts.length - 1];
    }
}
