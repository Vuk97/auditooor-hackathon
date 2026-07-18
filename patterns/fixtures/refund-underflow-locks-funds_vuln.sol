// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal escrow+refund contract. Users pay an up-front `paid` amount;
// the contract later reports `actualCost` (e.g., after a swap, oracle
// settle, or fee-on-transfer skim) and refunds the difference.
// VULN: raw `paid - actualCost` subtraction. When actualCost > paid
// (common on fee-on-transfer tokens or slippage), Solidity 0.8 panics
// and permanently locks user funds.
contract RefundUnderflowLocksFundsVuln {
    mapping(address => uint256) public paid;
    mapping(address => uint256) public actualCost;
    mapping(address => uint256) public locked;

    function deposit(uint256 amount) external {
        paid[msg.sender] += amount;
        locked[msg.sender] += amount;
    }

    function setActualCost(address user, uint256 cost) external {
        actualCost[user] = cost;
    }

    // VULN: raw subtraction; panics if actualCost > paid.
    function refund() external returns (uint256) {
        uint256 p = paid[msg.sender];
        uint256 c = actualCost[msg.sender];
        uint256 refundAmt = p - c;                 // raw, can underflow
        locked[msg.sender] = locked[msg.sender] - refundAmt; // raw, can underflow
        return refundAmt;
    }

    // VULN variant: redeem with compound -= underflow.
    function redeem(uint256 amount) external {
        locked[msg.sender] -= amount;              // raw, can underflow
    }

    // VULN variant: withdraw path with raw subtraction in name-matched fn.
    function withdraw(uint256 amount) external {
        uint256 balance = paid[msg.sender];
        paid[msg.sender] = balance - amount;       // raw
    }
}
