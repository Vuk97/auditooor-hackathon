// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire.
///
/// This contract uses `block.timestamp + N` (a real future deadline) and
/// forwards a user-supplied `_deadline` parameter. Both are covered by the
/// body_not_contains_regex negative term, so the detector will not match.

interface IRouter {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory);
}

contract DeadlineEqualsBlockTimestampClean {
    IRouter public router;
    uint256 public constant MAX_DELAY = 120;

    constructor(IRouter r) {
        router = r;
    }

    // CLEAN: synthesizes a real future deadline with `block.timestamp + N`.
    function swapWithDefaultWindow(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to
    ) external returns (uint256[] memory) {
        uint256 futureDeadline = block.timestamp + MAX_DELAY;
        return router.swapExactTokensForTokens(amountIn, amountOutMin, path, to, futureDeadline);
    }

    // CLEAN: forwards a user-supplied `_deadline` parameter. The user's
    // wallet signed over this concrete value and the tx can expire.
    function swapWithUserDeadline(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 _deadline
    ) external returns (uint256[] memory) {
        return router.swapExactTokensForTokens(amountIn, amountOutMin, path, to, _deadline);
    }
}
