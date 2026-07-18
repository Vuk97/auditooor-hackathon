// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RewardTerminalBranchWithoutPeriodAdvancePositive {
    uint256 public currentPeriod;
    uint256 public bidCount;
    uint256 public totalRaised;
    uint256 public minRaise = 100 ether;
    uint256 public rewardRollover;

    event AuctionFailed(uint256 indexed period);
    event RewardsAdvanced(uint256 indexed period);

    function finalizeAuction() external {
        if (bidCount == 0) {
            emit AuctionFailed(currentPeriod);
            return;
        }
        currentPeriod += 1;
        emit RewardsAdvanced(currentPeriod);
    }

    function closeRewardPeriod() external {
        if (totalRaised < minRaise) {
            rewardRollover += totalRaised;
            return;
        }
        currentPeriod++;
    }
}
