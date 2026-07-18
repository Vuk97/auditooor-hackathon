// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
}

/// @notice CLEAN FIXTURE — detector MUST NOT fire. No raw .transfer(...) or
/// .transferFrom(...) call sites appear anywhere in any function body, so
/// the positive body-regex matches nothing.
contract UncheckedTransferClean {
    IERC20 public immutable token;
    mapping(address => uint256) public balances;

    constructor(address t) { token = IERC20(t); }

    function deposit(uint256 amt) external {
        balances[msg.sender] += amt;
    }

    function balanceOfToken(address who) external view returns (uint256) {
        return token.balanceOf(who);
    }
}
