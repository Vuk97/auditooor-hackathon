// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: each setter writes the new policy with an `effectiveAfter`
// cutoff and every position snapshots its own lockupPeriod on deposit.
// Changes to the global field apply only to positions whose depositTs
// is >= effectiveAfter — existing positions keep their original
// schedule.
contract RetroactiveLockupChangeBreaksExistingClean {
    struct Position {
        uint256 amount;
        uint256 depositTs;
        uint256 lockupPeriodSnapshot;   // per-position snapshot
    }
    mapping(address => Position) public positions;
    uint256 public lockupPeriod;
    uint256 public lockDuration;
    uint256 public unlockTime;
    uint256 public effectiveAfter;      // cutoff for new policy
    address public owner;

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    modifier onlyAdmin() { require(msg.sender == owner, "not admin"); _; }

    constructor() {
        owner = msg.sender;
        lockupPeriod = 30 days;
        effectiveAfter = block.timestamp;
    }

    function stake(uint256 amt) external {
        positions[msg.sender] = Position(amt, block.timestamp, lockupPeriod);
    }

    // CLEAN: onlyForNewPositions — records cutoff, does not touch old positions.
    function setLockupPeriod(uint256 newPeriod) external onlyOwner {
        // onlyForNewPositions: new value applies only to deposits made
        // after effectiveAfter.
        lockupPeriod = newPeriod;
        effectiveAfter = block.timestamp;
    }

    // CLEAN: updateLockTime applies a futurePositions cutoff.
    function updateLockTime(uint256 newTime) external onlyAdmin {
        // futurePositions only
        lockDuration = newTime;
        effectiveAfter = block.timestamp;
    }

    // CLEAN: increaseLockTime uses _applyOnlyToNew semantics.
    function increaseLockTime(uint256 extra) external onlyOwner {
        // _applyOnlyToNew: extend only future positions
        lockupPeriod = lockupPeriod + extra;
        effectiveAfter = block.timestamp;
    }

    // CLEAN: residency-change path grandfathers existingPositions.
    mapping(address => bool) public restriction;
    function setRestriction(address a, bool r) external onlyOwner {
        // grandfather existingPositions — only future mints pick up the rule
        restriction[a] = r;
        effectiveAfter = block.timestamp;
    }

    function withdraw() external {
        Position memory p = positions[msg.sender];
        // reads the PER-POSITION snapshot, never the mutable global
        require(block.timestamp >= p.depositTs + p.lockupPeriodSnapshot, "locked");
        delete positions[msg.sender];
    }
}
