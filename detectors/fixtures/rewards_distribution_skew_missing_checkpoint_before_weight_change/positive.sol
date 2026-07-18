// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RewardsSkewMissingCheckpointBeforeWeightChangePositive {
    uint256 public accRewardPerWeight;
    uint256 public totalStaked;
    uint256 public totalWeight;
    address[] public pools;

    mapping(address => uint256) public stakedBalance;
    mapping(address => uint256) public rewardDebt;
    mapping(address => uint256) public poolWeight;
    mapping(address => bool) public isPool;

    function updateReward(address account) public {
        rewardDebt[account] = (stakedBalance[account] * accRewardPerWeight) / 1e18;
    }

    function checkpointPool(address pool) public {
        rewardDebt[pool] = (poolWeight[pool] * accRewardPerWeight) / 1e18;
    }

    function stake(uint256 amount) external {
        stakedBalance[msg.sender] += amount;
        totalStaked += amount;
        updateReward(msg.sender);
    }

    function setRewardWeight(address pool, uint256 newWeight) external {
        uint256 oldWeight = poolWeight[pool];
        poolWeight[pool] = newWeight;
        totalWeight = totalWeight - oldWeight + newWeight;
        checkpointPool(pool);
    }

    function addRewardPool(address pool, uint256 initialWeight) external {
        isPool[pool] = true;
        pools.push(pool);
        poolWeight[pool] = initialWeight;
        totalWeight += initialWeight;
        checkpointPool(pool);
    }
}
