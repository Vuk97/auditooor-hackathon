// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: showcase both lockup-bypass shapes — the additive `duration`
// shape and the absolute `unlockTime` shape — each missing the
// shape-matched guard.
contract LockupBypassDurationVsTimestampVuln {
    uint256 public lockupTime;
    mapping(address => uint256) public unlockTime;

    // VULN — DURATION shape: writes block.timestamp + duration with
    // NO guard on `duration`. Caller passes 0 → instant unlock.
    function setLockup(uint256 duration) external {
        lockupTime = block.timestamp + duration;
    }

    // VULN — TIMESTAMP shape: writes an absolute unlockTime that must
    // be compared with block.timestamp on withdraw, but the setter does
    // not require `unlockTime > block.timestamp + MIN_DELAY`. Caller
    // passes a backdated value → trivially satisfied check.
    function setUnlockAt(address user, uint256 t) external {
        unlockTime[user] = t;
    }

    // VULN — extend deadline: increases unlockTime[user] using the new
    // value without a forward-only / min-delay guard.
    function extendDeadline(address user, uint256 newDeadline) external {
        unlockTime[user] = newDeadline;
    }

    // Withdraw side just compares against the (unguarded) storage field.
    function withdraw(address user) external view returns (bool) {
        return block.timestamp >= unlockTime[user];
    }
}
