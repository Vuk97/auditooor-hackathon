// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Vulnerable cache-coherence example. The contract keeps cached accounting
// values that can be refreshed, but the consumer reads them directly without
// either refreshing or checking freshness.
contract CachedAccountingReadWithoutRefreshVuln {
    uint256 public cachedCreditCapacity;
    uint256 public cachedOraclePrice;
    uint256 public collateral;
    uint256 public utilization;
    uint256 public lastAccountingRefresh;

    function refreshAccounting() public {
        cachedCreditCapacity = collateral - utilization;
        cachedOraclePrice = 2e18;
        lastAccountingRefresh = block.timestamp;
    }

    function deposit(uint256 amount) external {
        collateral += amount;
    }

    function quoteBorrowable() external view returns (uint256) {
        uint256 capacity = cachedCreditCapacity;
        uint256 oraclePrice = cachedOraclePrice;
        uint256 collateralValue = collateral * oraclePrice;
        return capacity < collateralValue ? capacity : collateralValue;
    }
}
