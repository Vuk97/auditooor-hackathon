// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// deadline-equals-block-timestamp detector. DO NOT DEPLOY.
///
/// Both swap paths pass `block.timestamp` as the router deadline, which
/// means `block.timestamp <= deadline` is always true and the deadline
/// provides no real expiry protection.

interface IRouter {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory);
}

contract DeadlineEqualsBlockTimestampVuln {
    IRouter public router;
    uint256 public deadline;

    constructor(IRouter r) {
        router = r;
    }

    // VULNERABLE: writes `deadline = block.timestamp` — matches the first
    // alternative of the body_contains_regex.
    function setDeadlineToNow() external {
        deadline = block.timestamp;
    }

    // VULNERABLE: forwards `block.timestamp` as the last positional arg
    // (the deadline slot of the router.swap call) — matches the third
    // alternative of the body_contains_regex.
    function swap(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to
    ) external returns (uint256[] memory) {
        return router.swapExactTokensForTokens(amountIn, amountOutMin, path, to, block.timestamp);
    }
}
