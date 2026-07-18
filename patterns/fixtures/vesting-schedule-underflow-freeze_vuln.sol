// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal vesting contract that computes vested amount via raw subtraction.
// After admin reduces vestingRate mid-schedule, totalVested falls below
// `claimed` and _baseVestedAmount panics-underflows on Solidity 0.8,
// permanently freezing the user's remaining tokens.
contract VestingUnderflowFreezeVuln {
    uint256 public start;
    uint256 public cliff;
    uint256 public vestingRate;   // admin-mutable
    uint256 public totalAllocated;
    uint256 public claimed;

    constructor(uint256 _start, uint256 _cliff, uint256 _rate, uint256 _total) {
        start = _start;
        cliff = _cliff;
        vestingRate = _rate;
        totalAllocated = _total;
    }

    // VULN: raw subtraction. If admin reduces vestingRate, the recomputed
    // totalVested shrinks below `claimed` and the next line panics.
    function _baseVestedAmount() public view returns (uint256) {
        uint256 elapsed = block.timestamp - start;   // raw
        uint256 totalVested = elapsed * vestingRate;
        return totalVested - claimed;                // raw, can underflow
    }

    // VULN variant: releasable uses raw subtraction against block.timestamp.
    function releasable() external view returns (uint256) {
        uint256 remaining = totalAllocated - claimed;
        uint256 elapsedSinceStart = block.timestamp - start;
        return remaining * elapsedSinceStart / 365 days;
    }

    function setVestingRate(uint256 r) external {
        vestingRate = r;
    }
}
