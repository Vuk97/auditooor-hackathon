// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VeTokenVuln {
    mapping(address => address) public delegates;
    mapping(address => uint256) public balance;

    // VULN: anyone can stake for user and override delegate
    function stake(address user, uint256 amount, address newDelegate) external {
        balance[user] += amount;
        delegates[user] = newDelegate;
    }
}
