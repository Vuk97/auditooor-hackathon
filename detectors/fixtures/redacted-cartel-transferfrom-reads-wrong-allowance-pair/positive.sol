// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RedactedCartelPairTokenPositive {
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public balanceOf;

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 currentAllowance = allowance[from][to];
        if (currentAllowance != type(uint256).max) {
            allowance[from][msg.sender] = currentAllowance - amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
