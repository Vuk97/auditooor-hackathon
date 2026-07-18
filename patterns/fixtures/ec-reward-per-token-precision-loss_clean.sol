// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: 1e18 precision multiplier prevents truncation
contract StakingRewardClean {
    mapping(address => uint256) public stakedBalance;
    uint256 public totalStaked;
    uint256 public rewardPerTokenStored; // scaled by 1e18
    uint256 public lastUpdateTime;
    uint256 public rewardRate = 1e18; // 1 token per second

    mapping(address => uint256) public userRewardPerTokenPaid;
    mapping(address => uint256) public rewards;

    uint256 public constant PRECISION = 1e18; // scaling factor

    // CLEAN: multiply before divide — no truncation on small increments
    function rewardPerToken() public view returns (uint256) {
        if (totalStaked == 0) return rewardPerTokenStored;
        return rewardPerTokenStored +
            (block.timestamp - lastUpdateTime) * rewardRate * PRECISION / totalStaked;
        // With totalStaked=1e24, rewardRate=1e18, dt=1: 1e18 * 1e18 / 1e24 = 1e12 (valid)
    }

    function earned(address account) public view returns (uint256) {
        return stakedBalance[account] *
            (rewardPerToken() - userRewardPerTokenPaid[account]) / PRECISION + rewards[account];
    }
}
