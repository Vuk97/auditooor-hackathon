// SPDX-License-Identifier: MIT
// Fixture: safe-approve-non-zero-to-non-zero — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

interface IERC20 {
    function approve(address spender, uint256 value) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
}

library SafeERC20 {
    function safeApprove(IERC20 token, address spender, uint256 value) internal {
        require(
            value == 0 || token.allowance(address(this), spender) == 0,
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        token.approve(spender, value);
    }

    function forceApprove(IERC20 token, address spender, uint256 value) internal {
        // Modern OZ 4.9+ race-safe replacement: sets the allowance directly.
        token.approve(spender, value);
    }

    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 current = token.allowance(address(this), spender);
        token.approve(spender, current + value);
    }
}

contract VaultClean {
    using SafeERC20 for IERC20;

    IERC20 public token;
    address public router;

    constructor(IERC20 _token, address _router) {
        token = _token;
        router = _router;
    }

    // CLEAN: zeroes the allowance first, then sets the new amount. The
    // `.safeApprove(spender, 0)` branch of the body_not_contains_regex
    // matches and suppresses the detector.
    function depositResetFirst(uint256 amount) external {
        token.safeApprove(router, 0);
        token.safeApprove(router, amount);
    }

    // CLEAN: uses modern `forceApprove` — matches the body_not_contains_regex
    // `forceApprove` branch.
    function depositForce(uint256 amount) external {
        token.forceApprove(router, amount);
    }

    // CLEAN: uses `safeIncreaseAllowance` for the delta — matches the
    // body_not_contains_regex `safeIncreaseAllowance` branch.
    function depositIncremental(uint256 amount) external {
        token.safeIncreaseAllowance(router, amount);
    }
}
