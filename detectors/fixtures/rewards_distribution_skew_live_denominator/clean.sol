// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RewardsDistributionSkewLiveDenominatorClean {
    uint256 public totalStaked;
    uint256 public rewardIndex;
    uint256 public lastStakeBlock;
    uint256 public distributionSnapshotSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public userRewardIndex;

    function stake(uint256 amount) external {
        balanceOf[msg.sender] += amount;
        totalStaked += amount;
        lastStakeBlock = block.number;
    }

    function checkpointSupply() external {
        distributionSnapshotSupply = totalStaked;
    }

    function distributeRewards(uint256 rewardAmount) external {
        require(block.number > lastStakeBlock, "stake cooldown");
        require(distributionSnapshotSupply > 0, "no eligible supply");
        rewardIndex += (rewardAmount * 1e18) / distributionSnapshotSupply;
    }

    function claimable(address account) external view returns (uint256) {
        return (balanceOf[account] * (rewardIndex - userRewardIndex[account])) / 1e18;
    }
}
