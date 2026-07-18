// SPDX-License-Identifier: MIT
// Fixture: forced-eth-deposit-breaks-balance-invariant — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

contract CleanPool {
    uint256 public trackedEth;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    receive() external payable {
        trackedEth += msg.value;
    }

    // CLEAN fix #1: use >= not ==; contract tolerates forced donations.
    function swap() external {
        require(address(this).balance >= trackedEth, "balance shortfall");
        // ... swap logic ...
    }

    // CLEAN fix #2: rely ONLY on accounting state, never on
    // address(this).balance directly.
    function withdraw(uint256 amount) external {
        require(amount <= trackedEth, "insufficient tracked");
        trackedEth -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "xfer");
    }

    // CLEAN: admin skim path that realigns the tracker to actual balance,
    // explicitly pushing any forced donation to the owner.
    function skim() external {
        require(msg.sender == owner, "only owner");
        uint256 surplus = address(this).balance - trackedEth;
        if (surplus > 0) {
            (bool ok,) = owner.call{value: surplus}("");
            require(ok, "skim failed");
        }
    }
}
