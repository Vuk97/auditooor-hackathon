// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Simulates a stake-and-lock / lockup-setter contract. The duration and
// admin-configurable lockupTime are written without any range / non-zero
// guard, so setting them to 0 (or uint256.max) bricks or bypasses the
// whole lock mechanism.
contract LockupBypassZeroDurationVuln {
    uint256 public lockupTime;                // admin-configurable global
    mapping(address => uint256) public lockEnd; // per-user unlock deadline
    mapping(address => uint256) public stake;

    // VULN: admin setter writes lockupTime with no bounds — can be 0
    // (bypass) or uint256.max (freeze).
    function setLockupTime(uint256 newT) external {
        lockupTime = newT;
    }

    // VULN: user-supplied duration is written into lockEnd without
    // validating duration > 0 or duration <= MAX.
    function stakeAndLock(uint256 amount, uint256 duration) external {
        stake[msg.sender] += amount;
        lockEnd[msg.sender] = block.timestamp + duration;
    }

    // VULN: configureLock writes lockupTime, no guard.
    function configureLock(uint256 t) external {
        lockupTime = t;
    }

    // VULN: increaseStakeAndLock — rewrites lockEnd with a duration
    // parameter, no validation. A duration of 0 shortens an existing
    // longer lock to now.
    function increaseStakeAndLock(uint256 amount, uint256 duration) external {
        stake[msg.sender] += amount;
        lockEnd[msg.sender] = block.timestamp + duration;
    }
}
