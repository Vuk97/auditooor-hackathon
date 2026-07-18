// SPDX-License-Identifier: MIT
// Fixture: accumulator-underflow-on-decrease — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

contract StakingVuln {
    // precondition: accumulator state var.
    uint256 public totalStaked;
    mapping(address => uint256) public stakes;

    function deposit(uint256 amount) external {
        stakes[msg.sender] += amount;
        totalStaked += amount;
    }

    // VULN: decrements totalStaked with -= and NO saturation guard —
    // no unchecked, no SafeMath, no `if (totalStaked >= amount)`, no
    // Math.min, no `? x - y : 0` ternary. After any rounding mismatch
    // (admin recalibration, migration rescaling, event reordering), the
    // running total can be less than `amount` and the tx panic-reverts.
    function slash(address victim, uint256 amount) external {
        stakes[victim] -= amount;
        totalStaked -= amount;
    }

    function unstakeAll() external {
        uint256 amount = stakes[msg.sender];
        stakes[msg.sender] = 0;
        totalStaked -= amount;
    }
}
