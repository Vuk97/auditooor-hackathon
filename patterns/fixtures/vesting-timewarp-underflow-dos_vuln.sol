// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Vulnerable: vested-amount accessors compute elapsed = block.timestamp -
// startTime with no lower-bound floor. Admin can reduce vestingRate / push
// startTime into the future, and every subsequent call to claim()/release()
// will panic-underflow, permanently DoSing the schedule.
contract VestingTimewarpDosVuln {
    uint256 public startTime;
    uint256 public cliffEnd;
    uint256 public vestingRate;     // admin-mutable
    uint256 public unlockRate;      // admin-mutable
    uint256 public totalAllocated;
    uint256 public claimed;

    constructor(uint256 _start, uint256 _cliff, uint256 _rate, uint256 _total) {
        startTime = _start;
        cliffEnd = _cliff;
        vestingRate = _rate;
        unlockRate = _rate;
        totalAllocated = _total;
    }

    // VULN: raw `block.timestamp - startTime` subtraction. If admin moves
    // startTime above block.timestamp (or reduces vestingRate which triggers
    // a re-anchor), this panics with 0x11 underflow.
    function _baseVested() internal view returns (uint256) {
        uint256 elapsed = block.timestamp - startTime;
        return elapsed * vestingRate;
    }

    // VULN: releasable calls _baseVested; same underflow path.
    function releasable() external view returns (uint256) {
        uint256 total = _baseVested();
        return total - claimed;
    }

    // VULN: second accessor with the same raw subtraction shape.
    function claimable() external view returns (uint256) {
        uint256 elapsed = block.timestamp - cliffEnd;
        return elapsed * unlockRate;
    }

    function setVestingRate(uint256 r) external {
        vestingRate = r;
    }

    function setStartTime(uint256 s) external {
        startTime = s;   // admin time-warp: s > block.timestamp → underflow
    }
}
