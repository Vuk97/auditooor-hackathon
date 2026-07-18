// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AuctionFailureStallsPeriodAdvanceVuln {
    uint256 public currentPeriod;
    uint256 public totalRaised;
    uint256 public minRaise = 100 ether;

    event AuctionFailed(uint256 period);

    function closeAuction() external {
        if (totalRaised < minRaise) {
            // VULN: period does not advance on failure.
            emit AuctionFailed(currentPeriod);
            totalRaised = 0;
            return;
        }
        currentPeriod++;
        totalRaised = 0;
    }
}
