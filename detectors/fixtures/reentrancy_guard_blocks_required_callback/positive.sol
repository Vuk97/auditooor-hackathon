// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IDelegationManager {
    function completeQueuedWithdrawal() external;
}

abstract contract ReentrancyGuard {
    uint256 private _status = 1;

    modifier nonReentrant() {
        require(_status != 2, "reentrant");
        _status = 2;
        _;
        _status = 1;
    }
}

contract ReentrancyGuardBlocksRequiredCallbackPositive is IDelegationManager, ReentrancyGuard {
    bool public queueCompleted;

    function completeQueuedWithdrawal() external nonReentrant {
        queueCompleted = true;
    }

    receive() external payable nonReentrant {}
}
