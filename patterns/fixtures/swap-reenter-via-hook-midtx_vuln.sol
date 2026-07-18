// SPDX-License-Identifier: MIT
// Fixture: swap-reenter-via-hook-midtx — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

/// Bug shape (Solodit cluster C0252, 144 findings):
///   A payable swap entrypoint invokes a beforeSwap/afterSwap/onSwap hook
///   before finalizing state. The hook is user-controllable (either the
///   `hook` address is a function arg, or the v4-style `poolKey.hooks`
///   resolves to attacker code). No nonReentrant / lock modifier is
///   present, so the hook can reenter `swap` mid-tx and double-spend
///   msg.value or rotate the receiving asset id.
interface IHook {
    function beforeSwap(bytes calldata data) external;
    function afterSwap(bytes calldata data) external;
}

contract SwapHookReenterVuln {
    // Contract-level precondition: IHook name + beforeSwap body match
    // the precondition `beforeSwap|afterSwap|onSwap|IHook|SwapHook`.

    uint256 public totalOut;

    // VULN #1: payable `swap`, no nonReentrant, invokes beforeSwap on a
    // user-supplied hook address.
    function swap(address hook, bytes calldata data) external payable {
        IHook(hook).beforeSwap(data);
        totalOut += msg.value;
        IHook(hook).afterSwap(data);
    }

    // VULN #2: payable `_swap`, no guard, onSwap variant.
    function _swap(address hook, bytes calldata data) external payable {
        (bool ok, ) = hook.call(abi.encodeWithSignature("onSwap(bytes)", data));
        require(ok, "hook failed");
        totalOut += msg.value;
    }

    // VULN #3: payable `exchange` (Bancor-shape), explicit .afterSwap( call.
    function exchange(address hook, bytes calldata data) external payable {
        totalOut += msg.value;
        IHook(hook).afterSwap(data);
    }

    // VULN #4: payable `trade`, hook.call dispatch.
    function trade(address hook, bytes calldata data) external payable {
        (bool ok, ) = hook.call(data);
        require(ok, "hook failed");
        totalOut += msg.value;
    }
}
