// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RewardEmissionAfterRemovalClean {
    mapping(address => bool) public isRewardToken;
    mapping(address => uint256) public rewardRate;
    mapping(address => uint256) public periodFinish;
    uint256 public rewardsDuration = 7 days;

    function removeRewardToken(address token) external {
        isRewardToken[token] = false;
        rewardRate[token] = 0;
    }

    function notifyRewardAmount(address token, uint256 amount) external {
        require(isRewardToken[token], "inactive reward token");
        rewardRate[token] = amount / rewardsDuration;
        periodFinish[token] = block.timestamp + rewardsDuration;
    }
}
