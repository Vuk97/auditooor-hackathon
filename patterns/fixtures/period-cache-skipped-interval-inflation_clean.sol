// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GaugeClean {
    mapping(uint256 => uint256) public periodCumulative;
    uint256 public currentPeriod;

    function checkpoint(uint256 delta) external {
        periodCumulative[currentPeriod] += delta;
    }

    // CLEAN: explicit backfill using for loop
    function rewardOver(uint256 startPeriod, uint256 endPeriod) external view returns (uint256) {
        uint256 start = periodCumulative[startPeriod];
        uint256 lastSeen = start;
        for (uint256 p = startPeriod + 1; p <= endPeriod; p++) {
            uint256 slot = periodCumulative[p];
            if (slot == 0) {
                // period was skipped — preserve previous value, not inflated
                slot = lastSeen;
            }
            lastSeen = slot;
        }
        return lastSeen - start;
    }
}
