// SPDX-License-Identifier: MIT
// Fixture: deposit-accepts-excess-native-eth — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

contract CleanVault {
    mapping(address => uint256) public balances;
    uint256 public constant FIXED_COST = 1 ether;

    // CLEAN fix #1: strict equality — msg.value must match expected cost.
    function depositExact() external payable {
        require(msg.value == FIXED_COST, "wrong value");
        balances[msg.sender] += FIXED_COST;
    }

    // CLEAN fix #2: accept overpayment, refund the excess atomically so no
    // ETH is retained beyond expected cost.
    function depositWithRefund() external payable {
        require(msg.value >= FIXED_COST, "insufficient");
        balances[msg.sender] += FIXED_COST;
        uint256 excess = msg.value - FIXED_COST;
        if (excess > 0) {
            (bool ok,) = msg.sender.call{value: excess}("");
            require(ok, "refund failed");
        }
    }
}
