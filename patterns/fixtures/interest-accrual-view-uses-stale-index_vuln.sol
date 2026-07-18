// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Lending-market-style contract. interestIndex advances only when a user
// touches the contract (deposit/borrow/repay/accrue). The view functions
// read the cached index directly without extrapolating the interest that
// has accrued since the last touch, so integrators reading totalAssets /
// convertToAssets / maxWithdraw see values BELOW the user's true entitlement.
contract InterestAccrualViewStaleVuln {
    uint256 public interestIndex = 1e27;      // RAY-scaled
    uint256 public lastUpdate;                 // last accrual timestamp
    uint256 public ratePerSecond = 1e18;       // dummy rate
    uint256 public totalBorrow;                // gross borrow (scaled in interestIndex)
    mapping(address => uint256) public shares;
    uint256 public totalSupplyShares;

    constructor() {
        lastUpdate = block.timestamp;
    }

    // Mutating accrual (the only place interestIndex advances).
    function accrue() public {
        uint256 dt = block.timestamp - lastUpdate;
        interestIndex += dt * ratePerSecond;
        lastUpdate = block.timestamp;
    }

    // VULN: view reads the cached interestIndex + totalBorrow without
    // extrapolating the interval since lastUpdate. Integrators read a stale
    // NAV below the user's actual entitlement.
    function totalAssets() external view returns (uint256) {
        return (totalBorrow * interestIndex) / 1e27;
    }

    // VULN: convertToAssets uses the stale interestIndex directly.
    function convertToAssets(uint256 shareAmount) external view returns (uint256) {
        if (totalSupplyShares == 0) return shareAmount;
        uint256 _totalAssets = (totalBorrow * interestIndex) / 1e27;
        return (shareAmount * _totalAssets) / totalSupplyShares;
    }

    // VULN: maxWithdraw reads the stale index → liquidation bots see
    // the user as smaller than they really are.
    function maxWithdraw(address user) external view returns (uint256) {
        uint256 _totalAssets = (totalBorrow * interestIndex) / 1e27;
        return (shares[user] * _totalAssets) / (totalSupplyShares == 0 ? 1 : totalSupplyShares);
    }

    // VULN: share-price view reads stale cumulativeIndex equivalent.
    function sharePrice() external view returns (uint256) {
        if (totalSupplyShares == 0) return 1e18;
        return (interestIndex * totalBorrow) / totalSupplyShares;
    }
}
