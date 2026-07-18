// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// swap-inner-path-no-deadline detector. DO NOT DEPLOY.
///
/// swapAndDeposit forwards into IUniswapV2Router.swapExactTokensForTokens
/// but the body contains no `deadline`, no `block.timestamp + …`, and no
/// `type(uint256).max` sentinel. The transaction can be held in the
/// mempool and executed after the pool has moved against the user.

interface IUniswapV2Router {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 /* deadline */
    ) external returns (uint256[] memory amounts);
}

contract SwapWithoutDeadlineVuln {
    IUniswapV2Router public router;

    constructor(IUniswapV2Router _router) {
        router = _router;
    }

    /// VULNERABLE: router.swapExactTokensForTokens is invoked but the
    /// function never uses a deadline / block.timestamp addition / max
    /// sentinel token. A literal 0 is forwarded, defeating the router's
    /// deadline guard; the tx is executable indefinitely.
    function swapAndDeposit(uint256 amountIn, uint256 minOut, address[] calldata path) external {
        router.swapExactTokensForTokens(amountIn, minOut, path, address(this), 0);
    }

    /// Also vulnerable — alternate entrypoint shape exercising the
    /// `_swapInner` name anchor in the pattern.
    function _swapInner(uint256 amountIn, uint256 minOut, address[] calldata path)
        external
    {
        router.swapExactTokensForTokens(amountIn, minOut, path, msg.sender, 0);
    }
}
