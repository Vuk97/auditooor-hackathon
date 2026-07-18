// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract InterestAccruesWhilePausedVuln {
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

    // VULN: no pause check — borrowIndex keeps compounding while repay is gated
    function accrueInterest() external {
        uint256 dt = block.timestamp - lastAccrued;
        borrowIndex = borrowIndex + (borrowIndex * dt) / 365 days / 100;
        lastAccrued = block.timestamp;
    }
}
