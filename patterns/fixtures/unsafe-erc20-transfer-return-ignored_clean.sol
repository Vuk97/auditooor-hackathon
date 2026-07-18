// SPDX-License-Identifier: MIT
// Fixture: unsafe-erc20-transfer-return-ignored — CLEAN
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

library SafeERC20 {
    function safeTransfer(IERC20, address, uint256) internal {}
    function safeTransferFrom(IERC20, address, address, uint256) internal {}
    function forceApprove(IERC20, address, uint256) internal {}
}

contract UnsafeTransferClean {
    using SafeERC20 for IERC20;
    mapping(address => uint256) public balances;
    IERC20 public token;

    constructor(IERC20 t) { token = t; }

    // CLEAN: SafeERC20.safeTransfer reverts on false return or non-standard token.
    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;
        token.safeTransfer(msg.sender, amount);
    }

    function pull(address from, uint256 amount) external {
        token.safeTransferFrom(from, address(this), amount);
        balances[from] += amount;
    }

    function grantApproval(address spender, uint256 amount) external {
        token.forceApprove(spender, amount);
    }
}
