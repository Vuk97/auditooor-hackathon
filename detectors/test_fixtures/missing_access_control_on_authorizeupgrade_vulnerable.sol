// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract UUPSUpgradeable {
    function _authorizeUpgrade(address newImplementation) internal virtual;

    function upgradeToAndCall(address newImplementation, bytes calldata data) external {
        _authorizeUpgrade(newImplementation);
        data;
    }
}

contract MissingAuthorizeUpgradeAccessControlPositive is UUPSUpgradeable {
    address public implementation;

    function _authorizeUpgrade(address newImplementation) internal override {
        implementation = newImplementation;
    }
}
