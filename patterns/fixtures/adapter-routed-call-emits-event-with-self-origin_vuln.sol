// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally incorrect test input for the
/// adapter-routed-call-emits-event-with-self-origin detector. DO NOT DEPLOY.
///
/// Mirrors Polymarket CtfCollateralAdapter (Cantina #49 Low). The adapter
/// forwards `unwrap` to CollateralToken with `address(this)` as `_to`, so
/// the callee's `Unwrapped(msg.sender, to, amount)` event records the
/// adapter as both caller AND recipient. The originating `user` is absent
/// from every indexed topic — off-chain TVL/attribution indexers cannot
/// reconstruct who triggered the unwrap. Sibling functions
/// (`mergePositions` / `redeemPosition`) do this correctly, making the
/// bug asymmetric.
interface ICollateralToken {
    function unwrap(address to, uint256 amount) external;
    function wrap(address to, uint256 amount) external;
}

contract CtfCollateralAdapterVuln {
    ICollateralToken public immutable token;

    constructor(address _token) {
        token = ICollateralToken(_token);
    }

    /// VULN: passes `address(this)` to callee. Event becomes
    /// `Unwrapped(adapter, adapter, amount)`. Original `user` is lost.
    function splitPosition(address user, uint256 amount) external {
        // Bookkeeping omitted.
        token.unwrap(address(this), amount);
        // No adapter-side event mentioning `user` either.
    }

    /// CORRECT (sibling) — passes msg.sender to callee. Shown for asymmetry context.
    function mergePositions(uint256 amount) external {
        token.wrap(msg.sender, amount);
    }
}
