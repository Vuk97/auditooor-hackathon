// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire.
///
/// swapAndDeposit accepts a caller-supplied deadline and forwards it
/// into the router call. The literal `deadline` token appears in the
/// function body, satisfying the body_not_contains_regex negative guard
/// and suppressing the detector.

interface IUniswapV2Router {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);
}

contract SwapWithoutDeadlineClean {
    IUniswapV2Router public router;

    constructor(IUniswapV2Router _router) {
        router = _router;
    }

    /// CLEAN: deadline is a named parameter forwarded into the router
    /// call. The body contains the `deadline` token, which matches the
    /// negative guard regex in the pattern and prevents a match.
    function swapAndDeposit(
        uint256 amountIn,
        uint256 minOut,
        address[] calldata path,
        uint256 deadline
    ) external {
        require(deadline >= block.timestamp, "expired");
        router.swapExactTokensForTokens(amountIn, minOut, path, address(this), deadline);
    }
}
