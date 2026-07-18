// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IOracle {
    function getPrice(address token) external view returns (uint256);
}
interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

// CLEAN: both prices captured atomically before any external call
contract SwapClean {
    IOracle public oracle;

    constructor(address _oracle) { oracle = IOracle(_oracle); }

    // CLEAN: both prices read before any external call — no manipulation window
    function swap(address tokenIn, address tokenOut, uint256 amountIn) external {
        // Read both prices atomically BEFORE any external interaction
        uint256 priceIn = oracle.getPrice(tokenIn);
        uint256 priceOut = oracle.getPrice(tokenOut);
        uint256 amountOut = amountIn * priceIn / priceOut;

        // External calls happen after pricing is fully determined
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
        IERC20(tokenOut).transfer(msg.sender, amountOut);
    }
}
