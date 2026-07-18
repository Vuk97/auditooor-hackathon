// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract PerpFundingRawSecondsMismatch {
    uint256 public fundingRatePerSecondWad;
    uint256 public lastAccrualTime;
    uint256 public cumulativeFunding;

    constructor() {
        fundingRatePerSecondWad = 5e14;
        lastAccrualTime = block.timestamp - 1 hours;
    }

    function accrueFunding() external returns (uint256 fundingDelta) {
        uint256 elapsed = block.timestamp - lastAccrualTime;
        fundingDelta = mulWadDown(fundingRatePerSecondWad, elapsed);
        cumulativeFunding += fundingDelta;
        lastAccrualTime = block.timestamp;
    }

    function mulWadDown(uint256 x, uint256 y) internal pure returns (uint256) {
        return (x * y) / 1e18;
    }
}
