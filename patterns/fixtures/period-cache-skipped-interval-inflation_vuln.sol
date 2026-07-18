// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GaugeVuln {
    mapping(uint256 => uint256) public periodCumulative; // per-week index
    uint256 public currentPeriod;

    function checkpoint(uint256 delta) external {
        // lazy-write: only updates on interaction
        periodCumulative[currentPeriod] = periodCumulative[currentPeriod] + delta;
    }

    // VULN: raw subtraction, no backfill
    function rewardOver(uint256 startPeriod, uint256 endPeriod) external view returns (uint256) {
        return periodCumulative[endPeriod] - periodCumulative[startPeriod];
    }
}
