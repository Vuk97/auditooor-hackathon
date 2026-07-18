// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RewardsDistributionSkewPostMutationCheckpointClean {
    uint256 internal constant PRECISION = 1e18;

    mapping(address => uint256) public shares;
    mapping(address => uint256) public rewardDebt;
    uint256 public accRewardPerShare;
    uint256 public totalShares;

    function deposit(uint256 amount) external {
        rewardDebt[msg.sender] = (shares[msg.sender] * accRewardPerShare) / PRECISION;
        shares[msg.sender] += amount;
        totalShares += amount;
    }

    function withdraw(uint256 amount) external {
        require(shares[msg.sender] >= amount, "shares");
        rewardDebt[msg.sender] = (shares[msg.sender] * accRewardPerShare) / PRECISION;
        shares[msg.sender] -= amount;
        totalShares -= amount;
    }
}
