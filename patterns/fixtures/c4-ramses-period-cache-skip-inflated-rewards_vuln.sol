// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GaugePeriodCacheVuln {
    uint256 public lastUpdatePeriod;
    mapping(uint256 => uint256) public periodCumulatives;
    uint256 public secondsPerLiquidity;

    function updatePeriod() external {
        uint256 current = block.timestamp / 1 weeks;
        periodCumulatives[current] = secondsPerLiquidity;
        lastUpdatePeriod = current;
    }
}
