// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Clean variant: rate/index updates call `_updateBorrowTotal` (or
// `refreshReserve` / `syncTotalBorrow`) before reading totals, so the
// utilization input is fresh. Matches the saturate regex in the DSL and
// suppresses detection.
contract InterestRateStaleClean {
    uint256 public totalBorrows;
    uint256 public totalSupply;
    uint256 public borrowIndex = 1e18;
    uint256 public liquidityIndex = 1e18;
    uint256 public utilization;
    uint256 public lastUpdate;

    // Internal refresh that folds pending index-based accrual into
    // totalBorrows before the caller reads it.
    function _updateBorrowTotal() internal {
        uint256 dt = block.timestamp - lastUpdate;
        if (dt == 0) return;
        uint256 pending = totalBorrows * dt / 365 days / 100;
        totalBorrows += pending;
    }

    // CLEAN: refresh before computing utilization. The DSL's
    // `function.body_not_contains_regex` hits on `_updateBorrowTotal`
    // and the match is skipped.
    function _updateInterestRatesAndLiquidity() external {
        _updateBorrowTotal();
        uint256 u = totalBorrows * 1e18 / (totalSupply + 1);
        utilization = u;
        uint256 rate = u / 100;
        uint256 dt = block.timestamp - lastUpdate;
        borrowIndex += rate * dt;
        liquidityIndex += rate * dt * u / 1e18;
        lastUpdate = block.timestamp;
    }

    // CLEAN variant: uses syncTotalBorrow — also suppressed by the DSL
    // saturate regex.
    function accrueInterest() external {
        syncTotalBorrow();
        uint256 dt = block.timestamp - lastUpdate;
        uint256 rate = (totalBorrows * 1e18 / (totalSupply + 1)) / 100;
        borrowIndex += rate * dt;
        lastUpdate = block.timestamp;
    }

    function syncTotalBorrow() public {
        _updateBorrowTotal();
    }

    function borrow(uint256 amt) external {
        _updateBorrowTotal();
        totalBorrows += amt;
    }

    function supply(uint256 amt) external {
        totalSupply += amt;
    }
}
