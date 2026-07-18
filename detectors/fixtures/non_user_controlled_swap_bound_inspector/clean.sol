// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IQuoter {
    function quoteExactInputSingle(address tokenIn, address tokenOut, uint24 fee, uint256 amountIn)
        external
        returns (uint256);
}

interface IUniV3Router {
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

    function exactInputSingle(ExactInputSingleParams calldata params) external returns (uint256 amountOut);
}

contract UserControlledSwapBound {
    IQuoter public quoter;
    IUniV3Router public router;

    constructor(IQuoter quoter_, IUniV3Router router_) {
        quoter = quoter_;
        router = router_;
    }

    function rebalance(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 userMinAmountOut
    ) external returns (uint256 amountOut) {
        require(userMinAmountOut > 0, "missing user bound");
        quoter.quoteExactInputSingle(tokenIn, tokenOut, 3000, amountIn);

        amountOut = router.exactInputSingle(
            IUniV3Router.ExactInputSingleParams({
                tokenIn: tokenIn,
                tokenOut: tokenOut,
                fee: 3000,
                recipient: msg.sender,
                deadline: block.timestamp,
                amountIn: amountIn,
                amountOutMinimum: userMinAmountOut,
                sqrtPriceLimitX96: 0
            })
        );
    }
}
