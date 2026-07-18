// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Clean variant. The consumer refreshes the cached accounting state and
// enforces a freshness bound before using it.
contract CachedAccountingReadWithoutRefreshClean {
    uint256 public cachedCreditCapacity;
    uint256 public cachedOraclePrice;
    uint256 public collateral;
    uint256 public utilization;
    uint256 public lastAccountingRefresh;
    uint256 public constant MAX_STALE = 1 hours;

    function refreshAccounting() public {
        cachedCreditCapacity = collateral - utilization;
        cachedOraclePrice = 2e18;
        lastAccountingRefresh = block.timestamp;
    }

    function deposit(uint256 amount) external {
        collateral += amount;
    }

    function quoteBorrowable() external returns (uint256) {
        refreshAccounting();
        require(
            block.timestamp - lastAccountingRefresh <= MAX_STALE,
            "stale accounting"
        );
        uint256 capacity = cachedCreditCapacity;
        uint256 oraclePrice = cachedOraclePrice;
        uint256 collateralValue = collateral * oraclePrice;
        return capacity < collateralValue ? capacity : collateralValue;
    }
}
