// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Simulates a Zaros-style vault-router branch. Credit capacity is
// aggregated from per-market weights + collateral. An accrual helper
// (updateCreditCapacity) exists to refresh the cached totals, but
// branch entry points fail to invoke it before returning, leaving
// dependent flows reading stale values.
contract VaultCreditCapacityStaleVuln {
    mapping(address => uint256) public collateral;   // per-user collateral
    mapping(uint256 => uint256) public marketWeight; // per-market weight
    uint256 public totalCreditCapacity;              // cached aggregate
    uint256 public utilization;

    // Accrual helper - satisfies the precondition. It recomputes the
    // cached totalCreditCapacity from current weights + utilization.
    function updateCreditCapacity(uint256 /*marketId*/) public {
        // (real impl would iterate markets; we just touch the cache)
        totalCreditCapacity = utilization + 1;
    }

    // VULN: writes to collateral / capacity-affecting state but never
    // calls updateCreditCapacity - next reader gets the stale cache.
    function deposit(uint256 amount) external {
        collateral[msg.sender] += amount;
        totalCreditCapacity += amount; // direct mutation, no refresh
    }

    // VULN: withdraw only touches collateral + utilization. The stale-cache
    // bug is still real even though the branch never writes totalCreditCapacity
    // directly.
    function withdraw(uint256 amount) external {
        collateral[msg.sender] -= amount;
        utilization -= amount;
    }

    // VULN: rebalance mutates marketWeight without refreshing capacity.
    function rebalance(uint256 marketId, uint256 newWeight) external {
        marketWeight[marketId] = newWeight;
    }

    // VULN: setWeight=0 is meant to de-list a market but capacity keeps
    // reporting the old weight because no refresh happens.
    function setWeight(uint256 marketId, uint256 w) external {
        marketWeight[marketId] = w;
    }

    // VULN: collateral-swap writes collateral + capacity storage but
    // never invokes the accrual helper.
    function _swapCollateral(address user, uint256 delta) external {
        collateral[user] += delta;
        totalCreditCapacity += delta;
    }
}
