// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract QueueClean {
    mapping(address => uint256) public pendingWithdraw;
    mapping(address => uint256) public activeRequests;
    uint256 public queueTotal;

    function enqueueWithdraw(uint256 amount) external {
        pendingWithdraw[msg.sender] += amount;
        activeRequests[msg.sender] += 1;
        queueTotal += amount;
    }

    function cancelWithdraw(uint256 amount) external {
        pendingWithdraw[msg.sender] -= amount;
        activeRequests[msg.sender] -= 1;
        queueTotal -= amount;
    }
}
