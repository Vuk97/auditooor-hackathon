// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally incorrect test input for the
/// event-attribution-loss-self-routed-callee detector. DO NOT DEPLOY.
///
/// Mimics the Polymarket CtfCollateralAdapter.splitPosition pattern:
/// calls CollateralToken.unwrap(_to: address(this)) instead of
/// CollateralToken.unwrap(_to: msg.sender). The callee's Unwrapped event
/// has the adapter's address as an indexed topic, destroying user-level
/// attribution. Sibling functions mergePositions / redeemPositions that
/// correctly use msg.sender are shown for contrast.

interface ICollateralToken {
    function unwrap(address to, uint256 amount) external;
    event Unwrapped(address indexed caller, address indexed asset, address indexed to, uint256 amount);
}

contract CollateralToken {
    mapping(address => uint256) public balances;

    event Unwrapped(address indexed caller, address indexed asset, address indexed to, uint256 amount);

    function unwrap(address to, uint256 amount) external {
        //BUG: `to` is indexed — when caller passes address(this) as `to`,
        //     the indexed `to` topic carries the proxy address, not the user.
        balances[to] += amount;
        emit Unwrapped(msg.sender, address(0), to, amount);
    }
}

contract CtfCollateralAdapter {
    ICollateralToken public immutable COLLATERAL;
    address public immutable PROXY_ADMIN; // for demonstration

    constructor(address _collateral) {
        COLLATERAL = ICollateralToken(_collateral);
        PROXY_ADMIN = address(this); // demonstration value
    }

    /// VULN: splitPosition calls COLLATERAL.unwrap(address(this)).
    /// The resulting Unwrapped event has `to = CtfCollateralAdapter`
    /// as an indexed topic, so off-chain dashboards attributing unwraps
    /// by `to` see the adapter's address, not the user's EOA.
    function splitPosition(address recipient, uint256 amount) external {
        // In real code: ConditionalTokens.splitPosition(...) first,
        // then unwrap to the adapter address (not the user).
        // Unwrap amount: minted conditional tokens as collateral backing.
        // BUG: unwrap to address(this), not msg.sender or recipient.
        COLLATERAL.unwrap(address(this), amount); // BUG: self-routed
    }

    /// CORRECT: mergePositions unwraps to msg.sender.
    /// The Unwrapped event's indexed `to` topic carries the user — correct.
    function mergePositions(uint256 amount) external {
        COLLATERAL.unwrap(msg.sender, amount); // CORRECT
    }

    /// CORRECT: redeemPositions unwraps to msg.sender.
    /// The Unwrapped event's indexed `to` topic carries the user — correct.
    function redeemPositions(address recipient, uint256 amount) external {
        COLLATERAL.unwrap(msg.sender, amount); // CORRECT
    }
}