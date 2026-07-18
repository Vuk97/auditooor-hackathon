// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LidoLinearWithdrawalWaitPositive {
    uint256 internal balance;
    uint256 internal queuedRequests;

    function processStEtherAdapterWithdrawal(uint256 amount) external returns (uint256) {
        uint256 snapshot = balance + amount;
        queuedRequests += 1;
        return snapshot;
    }
}
