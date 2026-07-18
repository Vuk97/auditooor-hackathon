// SPDX-License-Identifier: MIT
// Fixture: safe-approve-non-zero-to-non-zero — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

interface IERC20 {
    function approve(address spender, uint256 value) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
}

library SafeERC20 {
    function safeApprove(IERC20 token, address spender, uint256 value) internal {
        // Simulated OZ legacy guard: reverts if changing non-zero → non-zero.
        require(
            value == 0 || token.allowance(address(this), spender) == 0,
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        token.approve(spender, value);
    }
}

contract VaultVuln {
    using SafeERC20 for IERC20;

    IERC20 public token;
    address public router;

    constructor(IERC20 _token, address _router) {
        token = _token;
        router = _router;
    }

    // VULN: calls safeApprove with a non-zero variable amount and never
    // first zeroes the allowance. If any residual allowance exists from a
    // prior partial spend, this call reverts inside the OZ guard and the
    // deposit path is permanently broken.
    function deposit(uint256 amount) external {
        token.safeApprove(router, amount);
    }

    // VULN: infinite-approval variant — `type(uint256).max` still matches
    // the non-zero branch of the regex (`type\(`).
    function approveMax() external {
        token.safeApprove(router, type(uint256).max);
    }

    // VULN: library-direct call shape `SafeERC20.safeApprove(...)`. Matches
    // the second branch of the regex alternation.
    function directCall(uint256 amount) external {
        SafeERC20.safeApprove(token, router, amount);
    }
}
