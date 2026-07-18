// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AuctionFailureStallsPeriodAdvanceClean {
    uint256 public currentPeriod;
    uint256 public totalRaised;
    uint256 public minRaise = 100 ether;

    event AuctionFailed(uint256 period);

    function closeAuction() external {
        if (totalRaised < minRaise) {
            emit AuctionFailed(currentPeriod);
            totalRaised = 0;
            currentPeriod++; // advance regardless of outcome
            return;
        }
        currentPeriod++;
        totalRaised = 0;
    }
}
