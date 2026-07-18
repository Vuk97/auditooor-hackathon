// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: the distribution path refuses to credit killed gauges.
contract KilledGaugeRewardsClean {
    mapping(address => uint256) public s_claimableRewardsByGauge;
    mapping(address => bool) public s_isKilledGauge;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function killGauge(address gauge) external onlyOwner {
        s_isKilledGauge[gauge] = true;
        delete s_claimableRewardsByGauge[gauge];
    }

    function distributeRewards(address gauge, uint256 amount) external onlyOwner {
        require(!s_isKilledGauge[gauge], "killed gauge");
        s_claimableRewardsByGauge[gauge] += amount;
    }
}
