// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUniswapV2LikeRouter {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);
}

interface IUniswapV3LikeRouter {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }

    function exactInputSingle(ExactInputSingleParams calldata params)
        external
        payable
        returns (uint256 amountOut);
}

interface ICurveLikePool {
    function exchange(int128 i, int128 j, uint256 dx, uint256 minDy)
        external
        returns (uint256 dy);
}

contract SlippageLiteralZeroClean {
    IUniswapV2LikeRouter public immutable uniV2;
    IUniswapV3LikeRouter public immutable uniV3;
    ICurveLikePool public immutable curve;

    constructor(address v2, address v3, address c) {
        uniV2 = IUniswapV2LikeRouter(v2);
        uniV3 = IUniswapV3LikeRouter(v3);
        curve = ICurveLikePool(c);
    }

    function swapViaV2(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path
    ) external returns (uint256 amountOut) {
        require(amountOutMin > 0, "min out required");
        uint256[] memory amounts = uniV2.swapExactTokensForTokens(
            amountIn,
            amountOutMin,
            path,
            msg.sender,
            block.timestamp
        );
        amountOut = amounts[amounts.length - 1];
        require(amountOut >= amountOutMin, "slippage");
    }

    function executeV3(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 amountOutMin
    ) external returns (uint256 amountOut) {
        require(amountOutMin > 0, "min out required");
        amountOut = uniV3.exactInputSingle(
            IUniswapV3LikeRouter.ExactInputSingleParams({
                tokenIn: tokenIn,
                tokenOut: tokenOut,
                fee: 3000,
                recipient: msg.sender,
                deadline: block.timestamp,
                amountIn: amountIn,
                amountOutMinimum: amountOutMin,
                sqrtPriceLimitX96: 0
            })
        );
        require(amountOut >= amountOutMin, "slippage");
    }

    function swapCurve(uint256 amountIn, uint256 minDy)
        external
        returns (uint256 amountOut)
    {
        require(minDy > 0, "min dy required");
        amountOut = curve.exchange(0, 1, amountIn, minDy);
        require(amountOut >= minDy, "slippage");
    }
}
