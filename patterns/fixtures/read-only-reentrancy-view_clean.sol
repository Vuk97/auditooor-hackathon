// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IFlashLoanReceiver {
    function receiveFlashLoan(uint256 amount, bytes calldata data) external;
}

interface IERC20Like {
    function transfer(address, uint256) external returns (bool);
}

// Balancer-style read-side guard: a second lock slot that mutator paths
// acquire, and that the protected views require to be unset. This blocks
// quoting a mid-mutation snapshot from inside a callback.
abstract contract ReadGuard {
    uint256 private _s = 1;

    modifier nonReentrant() {
        require(_s != 2, "REENTRANT");
        _s = 2;
        _;
        _s = 1;
    }

    // Read-side guard: reverts if we are currently inside a mutator.
    modifier ensureNotInVaultContext() {
        require(_s != 2, "READ_REENTRANT");
        _;
    }
}

/// CLEAN: views that depend on live accounting state are guarded by
/// ensureNotInVaultContext (Balancer-style) and the mutator holds the
/// same lock while it is executing, so any callback-time quote reverts.
contract ReadOnlyReentrancyPoolClean is ReadGuard {
    mapping(address => uint256) public balance;
    uint256 public totalSupply;
    uint256 public reserve;
    IERC20Like public token;

    function flashLoan(address receiver, uint256 amount, bytes calldata data) external nonReentrant {
        reserve -= amount;
        token.transfer(receiver, amount);
        IFlashLoanReceiver(receiver).receiveFlashLoan(amount, data);
        reserve += amount;
    }

    // CLEAN: read-side guard blocks callback-time quoting.
    function getSharePrice() external view ensureNotInVaultContext returns (uint256) {
        if (totalSupply == 0) return 1e18;
        return (reserve * 1e18) / totalSupply;
    }

    // CLEAN: same read-side guard applied.
    function pricePerShare() public view ensureNotInVaultContext returns (uint256) {
        if (totalSupply == 0) return 1e18;
        return (reserve * 1e18) / totalSupply;
    }
}
