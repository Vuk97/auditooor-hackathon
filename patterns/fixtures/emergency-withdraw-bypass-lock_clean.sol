// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Clean variant: every emergency-exit path either honors the lock, or
// charges a disclosed penalty / fee, or both. The detector's negated
// regex matches any ONE of {block.timestamp <, require(... lockEnd...),
// penalty, fee =} inside the body and the pattern does not fire.
contract EmergencyWithdrawBypassLockClean {
    mapping(address => uint256) public stake;
    mapping(address => uint256) public lockEnd;
    uint256 public lockPeriod;
    uint256 public rewardPerTokenStored;
    uint256 public constant PENALTY_BPS = 1000; // 10%

    constructor(uint256 _lockPeriod) {
        lockPeriod = _lockPeriod;
    }

    function deposit(uint256 amount) external {
        stake[msg.sender] += amount;
        lockEnd[msg.sender] = block.timestamp + lockPeriod;
    }

    function withdraw(uint256 amount) external {
        require(block.timestamp >= lockEnd[msg.sender], "locked");
        stake[msg.sender] -= amount;
    }

    // CLEAN: honors the lockEnd deadline (the require() phrase matches
    // the negated regex and suppresses the detector).
    function emergencyWithdraw() external {
        require(block.timestamp >= lockEnd[msg.sender], "still locked");
        stake[msg.sender] = 0;
    }

    // CLEAN: charges an explicit early-exit penalty.
    function panicWithdraw() external {
        uint256 amount = stake[msg.sender];
        uint256 penalty = (amount * PENALTY_BPS) / 10000;
        stake[msg.sender] = 0;
        // transfer(amount - penalty) in a real contract.
        penalty;
    }

    // CLEAN: uses a fee = ... assignment (matches negated regex).
    function forceExit(uint256 amount) external {
        uint256 fee = (amount * PENALTY_BPS) / 10000;
        stake[msg.sender] -= amount;
        fee;
    }
}
