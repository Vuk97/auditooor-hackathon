// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISwapRouter {
    struct ExactInputSingleParams {
        address tokenIn; address tokenOut; uint24 fee; address recipient;
        uint256 deadline; uint256 amountIn; uint256 amountOutMinimum; uint160 sqrtPriceLimitX96;
    }
    function exactInputSingle(ExactInputSingleParams calldata p) external returns (uint256);
}

contract HardcodedSqrtClean {
    ISwapRouter public router;
    function rebalance(address a, address b, uint256 amt, uint160 sqrtLimit, uint256 minOut) external returns (uint256) {
        ISwapRouter.ExactInputSingleParams memory p = ISwapRouter.ExactInputSingleParams({
            tokenIn: a, tokenOut: b, fee: 3000, recipient: msg.sender,
            deadline: block.timestamp, amountIn: amt, amountOutMinimum: minOut, sqrtPriceLimitX96: sqrtLimit
        });
        return router.exactInputSingle(p);
    }
}
