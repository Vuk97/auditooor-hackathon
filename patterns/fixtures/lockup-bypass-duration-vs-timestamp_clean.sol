// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: each function picks one shape (duration OR timestamp) and
// applies the matching guard.
contract LockupBypassDurationVsTimestampClean {
    uint256 public constant MIN_DURATION = 7 days;
    uint256 public constant MAX_DURATION = 4 * 365 days;
    uint256 public constant MIN_DELAY    = 1 days;

    uint256 public lockupTime;
    mapping(address => uint256) public unlockTime;

    // CLEAN — DURATION shape: bounds checked, non-zero implied.
    function setLockup(uint256 duration) external {
        require(duration >= MIN_DURATION && duration <= MAX_DURATION, "bad duration");
        lockupTime = block.timestamp + duration;
    }

    // CLEAN — TIMESTAMP shape: forward-only with min-delay buffer.
    function setUnlockAt(address user, uint256 t) external {
        require(t > block.timestamp + MIN_DELAY, "deadline too soon");
        unlockTime[user] = t;
    }

    // CLEAN — extend deadline: forward-only AND must extend, never shorten.
    function extendDeadline(address user, uint256 newDeadline) external {
        require(newDeadline > block.timestamp + MIN_DELAY, "too soon");
        require(newDeadline > unlockTime[user], "must extend");
        unlockTime[user] = newDeadline;
    }
}
