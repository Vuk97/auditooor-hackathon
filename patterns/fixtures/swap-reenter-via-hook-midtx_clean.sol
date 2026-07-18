// SPDX-License-Identifier: MIT
// Fixture: swap-reenter-via-hook-midtx — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

interface IHook {
    function beforeSwap(bytes calldata data) external;
    function afterSwap(bytes calldata data) external;
}

// Minimal reentrancy guard (same shape as OZ ReentrancyGuard).
abstract contract ReentrancyGuard {
    uint256 private _status = 1;
    modifier nonReentrant() {
        require(_status != 2, "REENTRANT");
        _status = 2;
        _;
        _status = 1;
    }
}

/// CLEAN fix: every payable hook-invoking swap entrypoint is wrapped in
/// `nonReentrant`. The reentry vector is closed because the guard reverts
/// on a second entry from within beforeSwap / afterSwap / onSwap.
contract SwapHookReenterClean is ReentrancyGuard {
    uint256 public totalOut;

    function swap(address hook, bytes calldata data) external payable nonReentrant {
        IHook(hook).beforeSwap(data);
        totalOut += msg.value;
        IHook(hook).afterSwap(data);
    }

    function _swap(address hook, bytes calldata data) external payable nonReentrant {
        (bool ok, ) = hook.call(abi.encodeWithSignature("onSwap(bytes)", data));
        require(ok, "hook failed");
        totalOut += msg.value;
    }

    function exchange(address hook, bytes calldata data) external payable nonReentrant {
        totalOut += msg.value;
        IHook(hook).afterSwap(data);
    }

    function trade(address hook, bytes calldata data) external payable nonReentrant {
        (bool ok, ) = hook.call(data);
        require(ok, "hook failed");
        totalOut += msg.value;
    }
}
