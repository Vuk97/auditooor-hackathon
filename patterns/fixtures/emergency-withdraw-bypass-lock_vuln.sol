// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal timelocked staking contract with an emergency-exit hatch that
// bypasses the lock without penalty or reward settlement. This is the
// C0212 bug shape: `emergencyWithdraw` lets users escape the commitment
// at zero cost while honest stakers wait out `lockEnd`.
contract EmergencyWithdrawBypassLockVuln {
    mapping(address => uint256) public stake;
    mapping(address => uint256) public lockEnd;
    uint256 public lockPeriod;
    uint256 public rewardPerTokenStored;

    constructor(uint256 _lockPeriod) {
        lockPeriod = _lockPeriod;
    }

    function deposit(uint256 amount) external {
        stake[msg.sender] += amount;
        lockEnd[msg.sender] = block.timestamp + lockPeriod;
    }

    // Honest path: lock is enforced.
    function withdraw(uint256 amount) external {
        require(block.timestamp >= lockEnd[msg.sender], "locked");
        stake[msg.sender] -= amount;
    }

    // VULN: emergencyWithdraw bypasses lockEnd, applies no penalty,
    // does not settle reward accruals.
    function emergencyWithdraw() external {
        uint256 amount = stake[msg.sender];
        stake[msg.sender] = 0;
        // NOTE: no block.timestamp check, no lockEnd reference,
        // no penalty math, no fee.
        // transfer(amount) would happen here in a real contract.
        amount;
    }

    // VULN variant: panicWithdraw — same shape.
    function panicWithdraw() external {
        stake[msg.sender] = 0;
    }

    // VULN variant: forceExit — same shape.
    function forceExit(uint256 amount) external {
        stake[msg.sender] -= amount;
    }
}
