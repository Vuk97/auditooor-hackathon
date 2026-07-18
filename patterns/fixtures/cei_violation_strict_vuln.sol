// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like { function transfer(address, uint256) external returns (bool); }

contract CEIVulnStrict {
    mapping(address => uint256) public balances;
    IERC20Like public token;

    // External call at line 10, state write at line 11 → classic reentrancy shape, no guard.
    function withdraw(uint256 amt) external {
        token.transfer(msg.sender, amt);
        balances[msg.sender] -= amt;
    }
}
