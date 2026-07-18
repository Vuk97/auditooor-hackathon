// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

/// @notice VULNERABLE FIXTURE — detector MUST fire. No SafeERC20, no require
/// on the return value. USDT-style tokens that don't revert on failure will
/// silently break accounting.
contract UncheckedTransferVuln {
    IERC20 public immutable token;
    mapping(address => uint256) public balances;

    constructor(address t) { token = IERC20(t); }

    function withdraw(uint256 amt) external {
        balances[msg.sender] -= amt;
        token.transfer(msg.sender, amt); // return ignored
    }

    function deposit(uint256 amt) external {
        token.transferFrom(msg.sender, address(this), amt); // return ignored
        balances[msg.sender] += amt;
    }
}
