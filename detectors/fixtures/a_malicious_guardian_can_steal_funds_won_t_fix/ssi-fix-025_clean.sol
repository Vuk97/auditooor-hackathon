// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GuardianStealFundsClean {
    uint256 internal blockNumber;
    address internal sender;

    constructor(address initialSender) {
        sender = initialSender;
    }

    function blockNumberUpdate(address newSender, uint256 nextBlockNumber) external returns (bool) {
        _validateGuardianUpdate(newSender, nextBlockNumber);
        sender = newSender;
        blockNumber = nextBlockNumber;
        return blockNumber > 0;
    }

    function _validateGuardianUpdate(address newSender, uint256 nextBlockNumber) internal view {
        require(newSender == sender, "guardian sender");
        require(nextBlockNumber > blockNumber, "guardian block");
    }
}
