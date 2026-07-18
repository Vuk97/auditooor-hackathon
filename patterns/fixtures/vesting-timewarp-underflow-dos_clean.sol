// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Clean: every time-delta subtraction is floored. Admin parameter changes or
// time-warps cannot panic the release path; the schedule degrades gracefully
// to zero when block.timestamp < startTime.
contract VestingTimewarpDosClean {
    uint256 public startTime;
    uint256 public cliffEnd;
    uint256 public vestingRate;
    uint256 public unlockRate;
    uint256 public totalAllocated;
    uint256 public claimed;

    constructor(uint256 _start, uint256 _cliff, uint256 _rate, uint256 _total) {
        startTime = _start;
        cliffEnd = _cliff;
        vestingRate = _rate;
        unlockRate = _rate;
        totalAllocated = _total;
    }

    // CLEAN: ternary floor `? a - b : 0` prevents underflow when startTime is
    // moved above block.timestamp.
    function _baseVested() internal view returns (uint256) {
        uint256 elapsed = block.timestamp >= startTime ? block.timestamp - startTime : 0;
        return elapsed * vestingRate;
    }

    // CLEAN: explicit `if (block.timestamp < cliffEnd) return 0` short-circuit.
    function claimable() external view returns (uint256) {
        if (block.timestamp < cliffEnd) return 0;
        uint256 elapsed = block.timestamp - cliffEnd;
        return elapsed * unlockRate;
    }

    // CLEAN: require() fail-closed guard + saturating claimed subtraction.
    function releasable() external view returns (uint256) {
        require(block.timestamp >= startTime, "not started");
        uint256 total = _baseVested();
        return total >= claimed ? total - claimed : 0;
    }

    function setVestingRate(uint256 r) external {
        vestingRate = r;
    }

    function setStartTime(uint256 s) external {
        require(s <= block.timestamp, "start in future");
        startTime = s;
    }
}
