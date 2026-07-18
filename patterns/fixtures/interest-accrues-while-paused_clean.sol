// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract InterestAccruesWhilePausedClean {
    bool public paused;
    uint256 public borrowIndex = 1e18;
    uint256 public totalBorrows;
    uint256 public lastAccrued;

    modifier whenNotPaused() {
        require(!paused, "paused");
        _;
    }

    function repay(uint256 amt) external whenNotPaused {
        totalBorrows -= amt;
    }

    // CLEAN: accrual also gated by whenNotPaused — symmetric with repay
    function accrueInterest() external whenNotPaused {
        uint256 dt = block.timestamp - lastAccrued;
        borrowIndex = borrowIndex + (borrowIndex * dt) / 365 days / 100;
        lastAccrued = block.timestamp;
    }
}
