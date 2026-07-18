// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ImmediateDistributionDilutionClean {
    uint256 public totalStaked;
    uint256 public rewardRate;
    uint256 public distributionFinishAt;
    uint256 public lastStakeUpdateBlock;
    uint256 public distributionUnlockAt;

    mapping(address => uint256) public balanceOf;

    function deposit(uint256 amount) external {
        balanceOf[msg.sender] += amount;
        totalStaked += amount;
        lastStakeUpdateBlock = block.number;
        distributionUnlockAt = block.timestamp + 1 hours;
    }

    function immediateDistribution(uint256 rewardAmount, uint256 duration) external {
        require(totalStaked > 0, "no stake");
        require(duration > 0, "duration");
        require(block.number > lastStakeUpdateBlock, "same block");
        require(block.timestamp >= distributionUnlockAt, "cooldown");

        rewardRate = rewardAmount / duration;
        distributionFinishAt = block.timestamp + duration;
    }
}
