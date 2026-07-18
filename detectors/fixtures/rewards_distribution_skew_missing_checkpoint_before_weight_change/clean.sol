// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RewardsSkewMissingCheckpointBeforeWeightChangeClean {
    uint256 public accRewardPerWeight;
    uint256 public totalStaked;
    uint256 public totalWeight;
    address[] public pools;

    mapping(address => uint256) public stakedBalance;
    mapping(address => uint256) public rewardDebt;
    mapping(address => uint256) public poolWeight;
    mapping(address => bool) public isPool;

    modifier updateReward(address account) {
        rewardDebt[account] = (stakedBalance[account] * accRewardPerWeight) / 1e18;
        _;
    }

    function checkpointPool(address pool) public {
        rewardDebt[pool] = (poolWeight[pool] * accRewardPerWeight) / 1e18;
    }

    function stake(uint256 amount) external updateReward(msg.sender) {
        stakedBalance[msg.sender] += amount;
        totalStaked += amount;
    }

    function setRewardWeight(address pool, uint256 newWeight) external {
        checkpointPool(pool);
        uint256 oldWeight = poolWeight[pool];
        poolWeight[pool] = newWeight;
        totalWeight = totalWeight - oldWeight + newWeight;
    }

    function addRewardPool(address pool, uint256 initialWeight) external {
        checkpointPool(pool);
        isPool[pool] = true;
        pools.push(pool);
        poolWeight[pool] = initialWeight;
        totalWeight += initialWeight;
    }
}
