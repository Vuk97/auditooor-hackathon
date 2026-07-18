// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: rewardPerToken computed without precision multiplier — truncates to 0
// Loss ref: Unipool / Synthetix canonical precision bug, 2019-2020
// https://github.com/k06a/Unipool/issues/3
// Multiple Masterchef forks missing 1e12 multiplier, 2021-2023
contract StakingRewardVuln {
    mapping(address => uint256) public stakedBalance;
    uint256 public totalStaked;
    uint256 public rewardPerTokenStored; // NO precision multiplier
    uint256 public lastUpdateTime;
    uint256 public rewardRate = 1e18; // 1 token per second

    mapping(address => uint256) public userRewardPerTokenPaid;
    mapping(address => uint256) public rewards;

    // VULN: reward / totalStaked — truncates to 0 when totalStaked >> reward increment
    function rewardPerToken() public view returns (uint256) {
        if (totalStaked == 0) return rewardPerTokenStored;
        return rewardPerTokenStored +
            (block.timestamp - lastUpdateTime) * rewardRate / totalStaked; // truncates!
        // With totalStaked=1e24, rewardRate=1e18, dt=1: 1e18/1e24 = 0
    }

    function earned(address account) public view returns (uint256) {
        return stakedBalance[account] *
            (rewardPerToken() - userRewardPerTokenPaid[account]) + rewards[account];
        // Always 0 when rewardPerToken truncates to 0
    }
}
