// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract ApprovalSweepViaDelegateClean {
    IERC20 public immutable token;
    address public immutable delegate;
    mapping(address => bool) public isDelegated;

    event PullAllowancePrepared(address indexed user, uint256 amount);

    constructor(IERC20 _token, address _delegate) {
        token = _token;
        delegate = _delegate;
    }

    function preparePullAllowance(uint256 amount) external {
        require(!isDelegated[msg.sender], "delegated account");
        require(token.approve(delegate, amount), "approve failed");
        emit PullAllowancePrepared(msg.sender, amount);
    }

    function pullFromUser(address user, address recipient, uint256 amount) external {
        require(token.transferFrom(user, recipient, amount), "pull failed");
    }
}
