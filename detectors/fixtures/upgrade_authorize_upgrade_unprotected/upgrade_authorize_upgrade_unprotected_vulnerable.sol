// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: UUPS `_authorizeUpgrade` override has an empty body - no
// access control. `upgradeToAndCall` is callable by anyone.
contract UUPSVaultVulnerable {
    address public implementation;

    function upgradeToAndCall(address newImpl, bytes calldata) external {
        _authorizeUpgrade(newImpl);
        implementation = newImpl;
    }

    function _authorizeUpgrade(address newImplementation) internal {
        // body intentionally empty: no caller gate of any kind
    }
}
