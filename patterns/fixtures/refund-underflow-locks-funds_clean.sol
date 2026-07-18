// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Clean variant: every refund subtraction is guarded by a saturating
// floor (ternary `? a - b : 0`) or an early-return short-circuit, so the
// refund path never panics.
contract RefundUnderflowLocksFundsClean {
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

    // CLEAN: saturating subtraction via ternary `? a - b : 0` floor.
    function refund() external returns (uint256) {
        uint256 p = paid[msg.sender];
        uint256 c = actualCost[msg.sender];
        uint256 refundAmt = p >= c ? p - c : 0;
        uint256 l = locked[msg.sender];
        locked[msg.sender] = l >= refundAmt ? l - refundAmt : 0;
        return refundAmt;
    }

    // CLEAN: uses min() floor to bound the redemption to available balance.
    function redeem(uint256 amount) external {
        uint256 bal = locked[msg.sender];
        uint256 take = min(amount, bal);
        locked[msg.sender] = bal - take;
    }

    // CLEAN: explicit early-return guard prevents any underflow.
    function withdraw(uint256 amount) external {
        uint256 balance = paid[msg.sender];
        if (balance < amount) return;
        paid[msg.sender] = balance - amount;
    }

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}
