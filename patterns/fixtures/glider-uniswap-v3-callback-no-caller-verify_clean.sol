// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 { function transferFrom(address, address, uint256) external returns (bool); }

contract SwapRouterClean {
    address public immutable pool;
    constructor(address p) { pool = p; }

    function uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata data) external {
        require(msg.sender == pool, "not pool");
        (address tokenIn, address payer, uint256 amount) = abi.decode(data, (address, address, uint256));
        amount0Delta; amount1Delta;
        IERC20(tokenIn).transferFrom(payer, pool, amount);
    }
}
