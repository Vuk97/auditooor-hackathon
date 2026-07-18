// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal lending reserve. `updateInterestRatesAndLiquidity` reads
// `totalBorrows` / `totalSupply` directly to compute utilization, but never
// refreshes them from pending borrow-index accrual, so the utilization and
// the resulting rate are stale — the C0328 class root cause.
contract InterestRateStaleVuln {
    uint256 public totalBorrows;
    uint256 public totalSupply;
    uint256 public borrowIndex = 1e18;
    uint256 public liquidityIndex = 1e18;
    uint256 public utilization;
    uint256 public lastUpdate;

    // VULN: reads totalBorrows / totalSupply without first accruing pending
    // interest into totalBorrows. The utilization below is stale for the
    // elapsed window.
    function _updateInterestRatesAndLiquidity() external {
        uint256 u = totalBorrows * 1e18 / (totalSupply + 1);
        utilization = u;
        uint256 rate = u / 100;                       // toy linear model
        uint256 dt = block.timestamp - lastUpdate;
        borrowIndex += rate * dt;
        liquidityIndex += rate * dt * u / 1e18;
        lastUpdate = block.timestamp;
    }

    // VULN variant: accrueInterest reads stale totals.
    function accrueInterest() external {
        uint256 dt = block.timestamp - lastUpdate;
        uint256 rate = (totalBorrows * 1e18 / (totalSupply + 1)) / 100;
        borrowIndex += rate * dt;
        lastUpdate = block.timestamp;
    }

    function borrow(uint256 amt) external {
        totalBorrows += amt;
    }

    function supply(uint256 amt) external {
        totalSupply += amt;
    }
}
