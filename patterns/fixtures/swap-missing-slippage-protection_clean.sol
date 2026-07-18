// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRouter {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);
}

/// @notice CLEAN FIXTURE — detector MUST NOT fire.
/// Slippage enforced via explicit require(amountOut >= amountOutMin).
contract SwapNoSlippageClean {
    IRouter public immutable router;

    constructor(address r) { router = IRouter(r); }

    function swapAndDeposit(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path
    ) external returns (uint256 amountOut) {
        require(amountOutMin > 0, "slippage required");
        uint256[] memory amounts = router.swapExactTokensForTokens(
            amountIn, amountOutMin, path, msg.sender, block.timestamp
        );
        amountOut = amounts[amounts.length - 1];
        // CLEAN: explicit slippage check on the returned amountOut
        require(amountOut >= amountOutMin, "slippage");
    }

    function buyToken(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path
    ) external returns (uint256 amountOut) {
        uint256[] memory amounts = router.swapExactTokensForTokens(
            amountIn, amountOutMin, path, msg.sender, block.timestamp
        );
        amountOut = amounts[amounts.length - 1];
        require(amountOut >= amountOutMin, "slippage");
    }
}
