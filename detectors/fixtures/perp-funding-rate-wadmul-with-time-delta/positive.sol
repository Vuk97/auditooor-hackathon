// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract PerpFundingEngine {
    uint256 public fundingRatePerSecond;
    uint256 public lastFundingTime;
    uint256 public normalizationFactor;

    constructor() {
        fundingRatePerSecond = 5e14;
        lastFundingTime = block.timestamp - 1 hours;
    }

    function setFundingRate(uint256 nextFundingRatePerSecond) external {
        fundingRatePerSecond = nextFundingRatePerSecond;
    }

    function updateFunding() external returns (uint256 totalFunding) {
        uint256 dt = block.timestamp - lastFundingTime;
        totalFunding = wadMul(fundingRatePerSecond, dt);
        normalizationFactor = normalizationFactor + totalFunding;
        lastFundingTime = block.timestamp;
    }

    function wadMul(uint256 x, uint256 y) internal pure returns (uint256) {
        return (x * y) / 1e18;
    }
}
