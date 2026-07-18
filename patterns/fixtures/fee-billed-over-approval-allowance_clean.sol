// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FeeTokenClean {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public constant FEE_BPS = 100; // 1%

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 fee = (amount * FEE_BPS) / 10000;
        uint256 totalDebit = amount + fee;
        balanceOf[from] -= totalDebit;
        balanceOf[to] += amount;
        balanceOf[address(this)] += fee;
        // CLEAN: allowance reflects the full debit
        allowance[from][msg.sender] -= totalDebit;
        return true;
    }
}
