// SPDX-License-Identifier: MIT
// Clean variant of the multi-contract fixture for burn-down item #5.
//
// The view is locked by the same reentrancy guard that protects
// mutating paths: any observer reading `getReserves()` during a hook
// callback reverts, so no stale snapshot can be quoted.
pragma solidity ^0.8.20;

interface ITokenReceiver {
    function tokensReceived(address from, uint256 amount) external;
}

abstract contract ReentrancyGuard {
    uint256 private _status = 1;

    modifier nonReentrant() {
        require(_status == 1, "REENTRANT");
        _status = 2;
        _;
        _status = 1;
    }

    modifier nonReentrantView() {
        require(_status == 1, "REENTRANT_VIEW");
        _;
    }
}

contract Pool is ReentrancyGuard {
    uint256 public reserves;

    function swap(address to, uint256 amount) external nonReentrant {
        // Same shape as the vulnerable variant, but the view that
        // exposes `reserves` cannot be observed mid-call because of
        // `nonReentrantView`.
        ITokenReceiver(to).tokensReceived(msg.sender, amount);
        reserves -= amount;
    }

    function getReserves() external view nonReentrantView returns (uint256) {
        return reserves;
    }

    function totalSupply() external view nonReentrantView returns (uint256) {
        return reserves;
    }
}
