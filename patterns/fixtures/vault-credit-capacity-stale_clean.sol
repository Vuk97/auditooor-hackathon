// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Clean variant: every branch entry point that mutates capacity-affecting
// state invokes updateCreditCapacity first so downstream reads are fresh.
contract VaultCreditCapacityStaleClean {
    mapping(address => uint256) public collateral;
    mapping(uint256 => uint256) public marketWeight;
    uint256 public totalCreditCapacity;
    uint256 public utilization;

    function updateCreditCapacity(uint256 /*marketId*/) public {
        totalCreditCapacity = utilization + 1;
    }

    // CLEAN: refreshes capacity before mutating - callers always see
    // a coherent totalCreditCapacity.
    function deposit(uint256 amount) external {
        updateCreditCapacity(0);
        collateral[msg.sender] += amount;
        totalCreditCapacity += amount;
    }

    function withdraw(uint256 amount) external {
        updateCreditCapacity(0);
        collateral[msg.sender] -= amount;
        utilization -= amount;
    }

    function rebalance(uint256 marketId, uint256 newWeight) external {
        updateCreditCapacity(marketId);
        marketWeight[marketId] = newWeight;
    }

    function setWeight(uint256 marketId, uint256 w) external {
        updateCreditCapacity(marketId);
        marketWeight[marketId] = w;
    }

    function _swapCollateral(address user, uint256 delta) external {
        updateCreditCapacity(0);
        collateral[user] += delta;
        totalCreditCapacity += delta;
    }
}
