// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract R94ReverseWithdrawTransferFailureSwallowedPositive {
    mapping(address => uint256) public balances;

    function seed(uint256 amount) external payable {
        require(msg.value == amount, "seed mismatch");
        balances[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool success, ) = msg.sender.call{value: amount}("");
        success;
        balances[msg.sender] -= amount;
    }
}
