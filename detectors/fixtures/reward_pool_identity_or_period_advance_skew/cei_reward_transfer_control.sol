// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract CeiRewardTransferControl {
    IERC20 public rewardToken;
    mapping(address => uint256) public pendingRewards;

    constructor(IERC20 token) {
        rewardToken = token;
    }

    function claimRewards() external {
        uint256 reward = pendingRewards[msg.sender];
        rewardToken.transfer(msg.sender, reward);
        pendingRewards[msg.sender] = 0;
    }
}
