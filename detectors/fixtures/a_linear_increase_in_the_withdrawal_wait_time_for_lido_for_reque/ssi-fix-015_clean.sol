// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LidoLinearWithdrawalWaitClean {
    uint256 internal balance;
    uint256 internal queuedRequests;

    function _updateWithdrawalState(uint256 amount) internal returns (uint256) {
        queuedRequests += amount;
        return balance + amount;
    }

    function processStEtherAdapterWithdrawal(uint256 amount) external returns (uint256) {
        return _updateWithdrawalState(amount);
    }
}
