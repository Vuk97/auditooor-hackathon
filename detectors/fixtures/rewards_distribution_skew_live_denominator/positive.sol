// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RewardsDistributionSkewLiveDenominatorPositive {
    uint256 public totalStaked;
    uint256 public rewardIndex;
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public userRewardIndex;

    function stake(uint256 amount) external {
        balanceOf[msg.sender] += amount;
        totalStaked += amount;
    }

    function distributeRewards(uint256 rewardAmount) external {
        require(totalStaked > 0, "no stake");
        rewardIndex += (rewardAmount * 1e18) / totalStaked;
    }

    function claimable(address account) external view returns (uint256) {
        return (balanceOf[account] * (rewardIndex - userRewardIndex[account])) / 1e18;
    }
}
