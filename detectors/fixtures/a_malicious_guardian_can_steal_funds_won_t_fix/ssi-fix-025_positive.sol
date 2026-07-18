// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GuardianStealFundsPositive {
    uint256 internal blockNumber;
    address internal sender;

    function blockNumberUpdate(address newSender, uint256 nextBlockNumber) external returns (bool) {
        if (nextBlockNumber <= blockNumber || sender == address(0)) {
            sender = newSender;
        }
        blockNumber = nextBlockNumber;
        return blockNumber > 0;
    }
}
