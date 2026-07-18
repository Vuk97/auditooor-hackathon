// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DefaultIterationsWithdrawalPositive {
    uint256 public _defaultIterations = 1024;
    uint256 public maxIterations = 1024;
    uint256 public lastIterationsUsed;
    mapping(address => uint256) public balances;

    constructor() {
        balances[msg.sender] = 1 ether;
    }

    function withdrawLogic(uint256 amount) external returns (uint256) {
        uint256 iterations = _defaultIterations + maxIterations;
        uint256 remaining = amount;

        for (uint256 i = 0; i < iterations; i++) {
            if (remaining == 0) {
                break;
            }
            remaining -= 1;
        }

        lastIterationsUsed = iterations;
        balances[msg.sender] -= amount - remaining;
        return remaining;
    }
}
