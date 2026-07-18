// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RewardClean {
    uint256 public totalStaked;
    uint256 public rewardsPerBlock;

    function pendingReward(uint256 stake) external view returns (uint256) {
        return (stake * rewardsPerBlock) / totalStaked;
    }
}
