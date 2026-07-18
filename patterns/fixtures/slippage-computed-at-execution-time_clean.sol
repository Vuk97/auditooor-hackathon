// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRouter {
    function swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin,
        address[] calldata path, address to, uint256 deadline)
        external returns (uint256[] memory);
}

contract AgentTaxClean {
    IRouter public router;
    address public tokenIn;
    address public tokenOut;

    // CLEAN: minAmountOut is a caller-supplied bound, not read from live reserves.
    function dcaSell(uint256 amountIn, uint256 minAmountOut, uint256 deadline) external {
        address[] memory path = new address[](2);
        path[0] = tokenIn;
        path[1] = tokenOut;
        router.swapExactTokensForTokens(amountIn, minAmountOut, path, address(this), deadline);
    }
}
