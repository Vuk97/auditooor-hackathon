// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MasterChefClean {
    uint256 public accRewardPerShare;
    uint256 public totalStaked;
    uint256 public lastRewardBlock;
    uint256 public rewardPerBlock = 1e18;
    uint256 constant PRECISION = 1e12;

    function _updatePool() internal {
        if (totalStaked == 0) { lastRewardBlock = block.number; return; }
        uint256 elapsed = block.number - lastRewardBlock;
        if (elapsed == 0) return;
        uint256 rewards = elapsed * rewardPerBlock;
        accRewardPerShare += (rewards * PRECISION) / totalStaked;
        lastRewardBlock = block.number;
    }

    function stake(uint256 amount) external {
        _updatePool();
        totalStaked += amount;
    }

    function unstake(uint256 amount) external {
        _updatePool();
        totalStaked -= amount;
    }
}
