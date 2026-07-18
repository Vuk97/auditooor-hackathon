// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FeeTokenVuln {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public constant FEE_BPS = 100; // 1%

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 fee = (amount * FEE_BPS) / 10000;
        // VULN: balance deducted by amount+fee but allowance only by amount
        balanceOf[from] -= amount + fee;
        balanceOf[to] += amount;
        balanceOf[address(this)] += fee;
        allowance[from][msg.sender] -= amount;
        return true;
    }
}
