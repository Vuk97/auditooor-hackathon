// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Clean variant: vested-amount accessors use saturating subtraction so
// parameter changes or time warps can never revert the release path.
contract VestingUnderflowFreezeClean {
    uint256 public start;
    uint256 public cliff;
    uint256 public vestingRate;
    uint256 public totalAllocated;
    uint256 public claimed;

    constructor(uint256 _start, uint256 _cliff, uint256 _rate, uint256 _total) {
        start = _start;
        cliff = _cliff;
        vestingRate = _rate;
        totalAllocated = _total;
    }

    // CLEAN: saturating subtraction via ternary `? a - b : 0` floor.
    function _baseVestedAmount() public view returns (uint256) {
        uint256 nowTs = block.timestamp;
        uint256 elapsed = nowTs >= start ? nowTs - start : 0;
        uint256 totalVested = elapsed * vestingRate;
        return totalVested >= claimed ? totalVested - claimed : 0;
    }

    // CLEAN: uses Math.max-style floor pattern via explicit check.
    function releasable() external view returns (uint256) {
        if (totalAllocated < claimed) return 0;
        uint256 remaining = totalAllocated - claimed;
        uint256 elapsedSinceStart = block.timestamp >= start ? block.timestamp - start : 0;
        return remaining * elapsedSinceStart / 365 days;
    }

    function setVestingRate(uint256 r) external {
        vestingRate = r;
    }
}
