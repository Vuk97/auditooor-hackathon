// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: borrow and supply rates read from different snapshots (no accrueInterest)
// Loss ref: Compound V2 COMP distribution bug ~$89M, Nov 2021
// https://rekt.news/compound-rekt/
contract InterestRateVuln {
    uint256 public totalBorrows;
    uint256 public totalCash;
    uint256 public totalReserves;
    uint256 public reserveFactorMantissa = 0.1e18;

    function getBorrowRate() public view returns (uint256) {
        uint256 util = totalBorrows * 1e18 / (totalCash + totalBorrows - totalReserves);
        return util * 2e17 / 1e18; // simplified: 20% * utilization
    }

    function getSupplyRate() public view returns (uint256) {
        uint256 borrowRate = getBorrowRate(); // reads same stale state
        return borrowRate * (1e18 - reserveFactorMantissa) / 1e18;
    }

    // VULN: reads both rates without accrueInterest(); stale totalBorrows
    function getSpread() external view returns (uint256 borrow, uint256 supply, uint256 spread) {
        borrow = getBorrowRate();  // uses stale totalBorrows
        supply = getSupplyRate(); // also stale — but in a real bug these diverge
        spread = borrow - supply;
        // spread represents extractable value if rates computed from different states
    }
}
