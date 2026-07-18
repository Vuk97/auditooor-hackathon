// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DefaultIterationsWithdrawalClean {
    uint256 public _defaultIterations = 1024;
    uint256 public maxIterations = 1024;
    uint256 public lastIterationsUsed;
    bool public interestAccrued;
    mapping(address => uint256) public balances;

    constructor() {
        balances[msg.sender] = 1 ether;
    }

    function withdrawLogic(uint256 amount) external returns (uint256) {
        _accrueInterest();

        uint256 iterations = maxIterations;
        if (iterations > 64) {
            iterations = 64;
        }

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

    function _accrueInterest() internal {
        interestAccrued = true;
    }
}
