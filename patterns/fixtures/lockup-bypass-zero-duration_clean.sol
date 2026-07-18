// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Clean variant: every function that writes a lock-duration storage
// field enforces `duration >= MIN && duration <= MAX` (and non-zero)
// so neither admin nor user can brick or bypass the lock mechanism.
contract LockupBypassZeroDurationClean {
    uint256 public constant MIN_LOCK = 7 days;
    uint256 public constant MAX_LOCK = 4 * 365 days;

    uint256 public lockupTime;
    mapping(address => uint256) public lockEnd;
    mapping(address => uint256) public stake;

    // CLEAN: bounds checked.
    function setLockupTime(uint256 newT) external {
        require(newT >= MIN_LOCK && newT <= MAX_LOCK, "bad lockup");
        lockupTime = newT;
    }

    function stakeAndLock(uint256 amount, uint256 duration) external {
        require(duration >= MIN_LOCK && duration <= MAX_LOCK, "bad duration");
        stake[msg.sender] += amount;
        lockEnd[msg.sender] = block.timestamp + duration;
    }

    function configureLock(uint256 t) external {
        require(t >= MIN_LOCK && t <= MAX_LOCK, "bad lockup");
        lockupTime = t;
    }

    function increaseStakeAndLock(uint256 amount, uint256 duration) external {
        require(duration >= MIN_LOCK && duration <= MAX_LOCK, "bad duration");
        stake[msg.sender] += amount;
        // only extend — never shorten
        uint256 proposed = block.timestamp + duration;
        if (proposed > lockEnd[msg.sender]) {
            lockEnd[msg.sender] = proposed;
        }
    }
}
