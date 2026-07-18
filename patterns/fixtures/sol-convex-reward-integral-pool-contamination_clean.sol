// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ConvexRewardIntegralClean {
    mapping(address => uint256) public rewardsOwedToPool;
    uint256 public rewardIntegral;
    uint256 public totalSupply;
    function _calcRewardIntegral(address pool) internal {
        uint256 owed = rewardsOwedToPool[pool];
        if (totalSupply > 0) rewardIntegral += owed * 1e18 / totalSupply;
        rewardsOwedToPool[pool] = 0;
    }
    function poke(address pool) external { _calcRewardIntegral(pool); }
}
