// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract ReentrancyGuard {
    uint256 private _status = 1;

    modifier nonReentrant() {
        require(_status != 2, "reentrant");
        _status = 2;
        _;
        _status = 1;
    }
}

contract ReentrancyGuardBlocksRequiredCallbackClean is ReentrancyGuard {
    bool public queueCompleted;

    function completeQueuedWithdrawal() external {
        queueCompleted = true;
    }

    receive() external payable {}
}
