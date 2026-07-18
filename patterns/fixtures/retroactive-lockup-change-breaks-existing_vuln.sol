// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: admin setter mutates the global lockupPeriod in place with no
// grandfathering. Alice stakes under the old 30-day policy; governance
// then calls setLockupPeriod(365 days), and because the withdraw path
// re-reads the current lockupPeriod, Alice is trapped for an extra
// 11 months. Symmetrically, setLockupPeriod(0) lets everyone exit.
contract RetroactiveLockupChangeBreaksExistingVuln {
    struct Position { uint256 amount; uint256 depositTs; }
    mapping(address => Position) public positions;
    uint256 public lockupPeriod;   // global mutable policy
    uint256 public lockDuration;
    uint256 public unlockTime;
    address public owner;

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    modifier onlyAdmin() { require(msg.sender == owner, "not admin"); _; }

    constructor() {
        owner = msg.sender;
        lockupPeriod = 30 days;
    }

    function stake(uint256 amt) external {
        positions[msg.sender] = Position(amt, block.timestamp);
    }

    // VULN: no grandfathering — overwrites the global field in place.
    function setLockupPeriod(uint256 newPeriod) external onlyOwner {
        lockupPeriod = newPeriod;
    }

    // VULN: same failure via a different setter name observed in C0141.
    function updateLockTime(uint256 newTime) external onlyAdmin {
        lockDuration = newTime;
        unlockTime = block.timestamp + newTime;
    }

    // VULN: increaseLockTime extends every user's lock past their intent.
    function increaseLockTime(uint256 extra) external onlyOwner {
        lockupPeriod = lockupPeriod + extra;
    }

    // VULN: residency-restriction variant — flipping the restriction
    // retroactively re-locks historical issuances.
    mapping(address => bool) public restriction;
    function setRestriction(address a, bool r) external onlyOwner {
        restriction[a] = r;
    }

    function withdraw() external {
        Position memory p = positions[msg.sender];
        // re-reads the global mutable field → retroactive
        require(block.timestamp >= p.depositTs + lockupPeriod, "locked");
        delete positions[msg.sender];
    }
}
