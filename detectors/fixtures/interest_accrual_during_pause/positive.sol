// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract InterestAccrualDuringPausePositive {
    bool internal _paused;
    uint256 public totalDebt;
    uint256 public ratePerTick = 3;

    modifier whenNotPaused() {
        require(!_paused, "paused");
        _;
    }

    function pause() external {
        _paused = true;
    }

    function paused() external view returns (bool) {
        return _paused;
    }

    function repay(uint256 amount) external whenNotPaused {
        totalDebt -= amount;
    }

    function accrueInterest() external {
        totalDebt += ratePerTick;
    }
}
