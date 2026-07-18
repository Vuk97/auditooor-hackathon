// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — counter-example for the
/// adapter-routed-call-emits-event-with-self-origin detector.
///
/// Either (a) forward `user` to the callee so the callee's event records
/// the real origin, or (b) emit a dedicated adapter-side event whose
/// indexed topic carries the originating user — both make off-chain
/// attribution sound.
interface ICollateralToken {
    function unwrap(address to, uint256 amount) external;
}

contract CtfCollateralAdapterClean {
    ICollateralToken public immutable token;

    /// Adapter-side event with `user` indexed — even if the callee's
    /// event records (adapter, adapter), off-chain joiners can recover
    /// the origin via this log.
    event RoutedSplit(address indexed user, uint256 amount);

    constructor(address _token) {
        token = ICollateralToken(_token);
    }

    /// CLEAN: forward `user` to the callee, AND emit our own attribution event.
    function splitPosition(address user, uint256 amount) external {
        token.unwrap(user, amount);
        emit RoutedSplit(user, amount);
    }
}
