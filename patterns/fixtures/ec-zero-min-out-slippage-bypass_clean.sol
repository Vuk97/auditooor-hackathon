// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUniswapRouter {
    struct ExactInputSingleParams {
        address tokenIn; address tokenOut; uint24 fee;
        address recipient; uint256 deadline;
        uint256 amountIn; uint256 amountOutMinimum; uint160 sqrtPriceLimitX96;
    }
    function exactInputSingle(ExactInputSingleParams calldata) external returns (uint256);
}
interface IERC20 { function approve(address, uint256) external returns (bool); }

// CLEAN: minOut enforced to be nonzero
contract AggregatorClean {
    IUniswapRouter public router;

    constructor(address _router) { router = IUniswapRouter(_router); }

    // CLEAN: rejects minOut=0 to ensure slippage protection
    function swapExact(
        address tokenIn, address tokenOut,
        uint256 amountIn, uint256 minOut
    ) external returns (uint256) {
        require(minOut > 0, "no slippage protection"); // enforce nonzero
        IERC20(tokenIn).approve(address(router), amountIn);
        return router.exactInputSingle(IUniswapRouter.ExactInputSingleParams({
            tokenIn: tokenIn, tokenOut: tokenOut, fee: 3000,
            recipient: msg.sender, deadline: block.timestamp + 300,
            amountIn: amountIn, amountOutMinimum: minOut,
            sqrtPriceLimitX96: 0
        }));
    }
}
