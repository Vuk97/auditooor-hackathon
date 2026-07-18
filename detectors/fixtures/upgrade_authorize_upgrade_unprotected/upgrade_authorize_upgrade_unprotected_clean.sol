// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: UUPS `_authorizeUpgrade` override gates the upgrade with an
// explicit owner check.
contract UUPSVaultClean {
    address public implementation;
    address public owner;

    function upgradeToAndCall(address newImpl, bytes calldata) external {
        _authorizeUpgrade(newImpl);
        implementation = newImpl;
    }

    function _authorizeUpgrade(address newImplementation) internal view {
        require(msg.sender == owner, "not owner");
    }
}
