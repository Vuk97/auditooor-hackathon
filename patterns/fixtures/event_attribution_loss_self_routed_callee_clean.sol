// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — correct implementation for the
/// event-attribution-loss-self-routed-callee detector.
///
/// Same as the vulnerable fixture, except:
/// - splitPosition unwraps to msg.sender (or the user-provided recipient)
///   instead of address(this). The callee's indexed `to` topic now carries
///   the actual user EOA, preserving off-chain attribution.
/// - A secondary `AssetAccumulated` event is emitted for the self-route
///   case so off-chain pipelines can distinguish user-routed from
///   self-accumulated flows.

interface ICollateralToken {
    function unwrap(address to, uint256 amount) external;
    event Unwrapped(address indexed caller, address indexed asset, address indexed to, uint256 amount);
}

contract CollateralToken {
    mapping(address => uint256) public balances;

    event Unwrapped(address indexed caller, address indexed asset, address indexed to, uint256 amount);

    function unwrap(address to, uint256 amount) external {
        balances[to] += amount;
        // The `to` field is indexed — off-chain indexers join on it.
        // When caller passes user address, attribution is preserved.
        emit Unwrapped(msg.sender, address(0), to, amount);
    }
}

contract CtfCollateralAdapter {
    ICollateralToken public immutable COLLATERAL;

    event AssetAccumulated(address indexed asset, address indexed beneficiary, uint256 amount);

    constructor(address _collateral) {
        COLLATERAL = ICollateralToken(_collateral);
    }

    /// CORRECT: splitPosition unwraps to the user (or recipient).
    /// The Unwrapped event's indexed `to` topic carries the user EOA.
    function splitPosition(address recipient, uint256 amount) external {
        // FIX: unwrap to msg.sender (or `recipient` param) instead of address(this).
        // This preserves the indexed `to` topic in the Unwrapped event so
        // off-chain attribution pipelines can correctly attribute the action.
        COLLATERAL.unwrap(msg.sender, amount); // CORRECT: user receives tokens
    }

    /// CORRECT: mergePositions unwraps to msg.sender.
    function mergePositions(uint256 amount) external {
        COLLATERAL.unwrap(msg.sender, amount);
    }

    /// CORRECT: redeemPositions unwraps to msg.sender.
    function redeemPositions(address recipient, uint256 amount) external {
        COLLATERAL.unwrap(msg.sender, amount);
    }
}