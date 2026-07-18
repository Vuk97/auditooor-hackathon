// SPDX-License-Identifier: MIT
// Fixture: accumulator-underflow-on-decrease — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

library Math {
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}

contract StakingClean {
    uint256 public totalStaked;
    mapping(address => uint256) public stakes;

    function deposit(uint256 amount) external {
        stakes[msg.sender] += amount;
        totalStaked += amount;
    }

    // CLEAN: explicit `if (totalStaked >= amount)` saturation precondition
    // around the -= write, so the body_not_contains_regex predicate matches
    // and skips the function.
    function slash(address victim, uint256 amount) external {
        stakes[victim] -= amount;
        if (totalStaked >= amount) {
            totalStaked -= amount;
        } else {
            totalStaked = 0;
        }
    }

    // CLEAN: uses Math.min for saturating subtraction on the accumulator
    // decrement.
    function unstakeAll() external {
        uint256 amount = stakes[msg.sender];
        stakes[msg.sender] = 0;
        uint256 dec = Math.min(totalStaked, amount);
        totalStaked -= dec;
    }
}
