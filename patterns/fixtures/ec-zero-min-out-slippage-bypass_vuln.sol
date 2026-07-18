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

// VULN: user-supplied minAmountOut=0 accepted with no validation
// Loss ref: Li.Finance ~$600K, March 2022; Yearn yUSDT ~$11.6M, April 2023
// https://rekt.news/lifi-rekt/
// https://rekt.news/yearn-rekt/
contract AggregatorVuln {
    IUniswapRouter public router;

    constructor(address _router) { router = IUniswapRouter(_router); }

    // VULN: minOut=0 is accepted — sandwich attacker captures full slippage
    function swapExact(
        address tokenIn, address tokenOut,
        uint256 amountIn, uint256 minOut // can be 0!
    ) external returns (uint256) {
        IERC20(tokenIn).approve(address(router), amountIn);
        return router.exactInputSingle(IUniswapRouter.ExactInputSingleParams({
            tokenIn: tokenIn, tokenOut: tokenOut, fee: 3000,
            recipient: msg.sender, deadline: block.timestamp,
            amountIn: amountIn, amountOutMinimum: minOut, // 0 bypasses protection
            sqrtPriceLimitX96: 0
        }));
    }
}
