// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MasterChefVuln {
    uint256 public accRewardPerShare;
    uint256 public totalStaked;
    uint256 public lastRewardBlock;
    uint256 public rewardPerBlock = 1e18;
    uint256 constant PRECISION = 1e12;

    function _updatePool() internal {
        uint256 elapsed = block.number - lastRewardBlock;
        if (elapsed == 0) return;
        uint256 rewards = elapsed * rewardPerBlock;
        // VULN: no `if (totalStaked == 0)` short-circuit
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
