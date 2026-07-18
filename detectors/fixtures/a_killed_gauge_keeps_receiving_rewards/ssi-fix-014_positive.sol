// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: the distribution path still credits rewards to a killed gauge.
contract KilledGaugeRewardsPositive {
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

    // BUG: fresh emissions are still credited after the gauge has been killed.
    function distributeRewards(address gauge, uint256 amount) external onlyOwner {
        s_claimableRewardsByGauge[gauge] += amount;
    }
}
