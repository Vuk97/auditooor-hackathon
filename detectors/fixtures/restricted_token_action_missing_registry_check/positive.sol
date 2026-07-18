// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RestrictedTokenActionPositive {
    mapping(address => bool) public frozen;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function transfer(address to, uint256 amount) external {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external {
        allowance[msg.sender][spender] = amount;
    }
}
