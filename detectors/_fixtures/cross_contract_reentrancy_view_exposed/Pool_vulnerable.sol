// SPDX-License-Identifier: MIT
// Multi-contract fixture for burn-down item #5 — pins
// `cross-contract-reentrancy-view-exposed` (a wave17 detector that DOES
// consult the callgraph via `function.has_high_level_call_named`).
//
// Vulnerable variant:
//   * `swap()` triggers an ERC777-style hook on `to` BEFORE updating
//     `reserves`. The hook can re-enter and read `getReserves()` —
//     the unguarded view exposes mid-mutation state.
//   * `getReserves()` has no reentrancy guard; an external observer
//     (Oracle.sol) reads it during the callback and quotes a stale
//     price.
pragma solidity ^0.8.20;

interface ITokenReceiver {
    function tokensReceived(address from, uint256 amount) external;
}

contract Pool {
    uint256 public reserves;

    // Mutating path — fires the hook BEFORE reserve write completes.
    function swap(address to, uint256 amount) external {
        // Hook fires on `to` while `reserves` is still pre-swap. A
        // read-only observer can read the old value and value
        // collateral against the stale snapshot.
        ITokenReceiver(to).tokensReceived(msg.sender, amount);
        reserves -= amount;
    }

    // Exposed view — UNGUARDED. The whole bug class hinges on this
    // being readable from inside the swap() callback.
    function getReserves() external view returns (uint256) {
        return reserves;
    }

    // Helper view some oracles call instead of getReserves().
    function totalSupply() external view returns (uint256) {
        return reserves;
    }
}
