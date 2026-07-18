// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GaugePeriodCacheClean {
    uint256 public lastUpdatePeriod;
    mapping(uint256 => uint256) public periodCumulatives;
    uint256 public secondsPerLiquidity;

    function _fillGap(uint256 from, uint256 to) internal {
        for (uint256 p = from; p <= to; p++) periodCumulatives[p] = secondsPerLiquidity;
    }

    function updatePeriod() external {
        uint256 current = block.timestamp / 1 weeks;
        _fillGap(lastUpdatePeriod + 1, current);
        lastUpdatePeriod = current;
    }
}
