// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: accrueInterest() called before any rate computation
contract InterestRateClean {
    uint256 public totalBorrows;
    uint256 public totalCash;
    uint256 public totalReserves;
    uint256 public reserveFactorMantissa = 0.1e18;
    uint256 public accrualBlockNumber;

    function accrueInterest() public {
        if (accrualBlockNumber == block.number) return;
        // Apply interest to totalBorrows
        uint256 borrowRate = _getBorrowRate();
        uint256 blockDelta = block.number - accrualBlockNumber;
        uint256 interestAccumulated = totalBorrows * borrowRate * blockDelta / 1e18;
        totalBorrows += interestAccumulated;
        accrualBlockNumber = block.number;
    }

    function _getBorrowRate() internal view returns (uint256) {
        uint256 util = totalBorrows * 1e18 / (totalCash + totalBorrows - totalReserves + 1);
        return util * 2e17 / 1e18;
    }

    // CLEAN: accrues interest before reading rates — both from same post-accrual state
    function getSpread() external returns (uint256 borrow, uint256 supply, uint256 spread) {
        accrueInterest(); // update state first
        borrow = _getBorrowRate();
        supply = borrow * (1e18 - reserveFactorMantissa) / 1e18;
        spread = borrow - supply;
    }
}
