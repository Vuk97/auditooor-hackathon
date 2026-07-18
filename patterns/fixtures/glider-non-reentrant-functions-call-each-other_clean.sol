// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

abstract contract ReentrancyGuard {
    uint256 private _status = 1;

    modifier nonReentrant() {
        require(_status == 1, "ReentrancyGuard: reentrant call");
        _status = 2;
        _;
        _status = 1;
    }
}

contract VaultClean is ReentrancyGuard {
    uint256 public pendingAmount;

    constructor() {
        pendingAmount = 100;
    }

    function redeem() external nonReentrant {
        uint256 amount = pendingAmount;
        pendingAmount = 0;
        _claimPendingInternal();
    }

    function claimPending() external nonReentrant {
        pendingAmount += 1;
    }

    function _claimPendingInternal() internal {
        pendingAmount += 1;
    }

    function deposit() external nonReentrant {
        pendingAmount += 10;
    }
}