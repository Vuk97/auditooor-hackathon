// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract UUPSUpgradeable {
    function _authorizeUpgrade(address newImplementation) internal virtual;

    function upgradeToAndCall(address newImplementation, bytes calldata data) external {
        _authorizeUpgrade(newImplementation);
        data;
    }
}

contract MissingAuthorizeUpgradeAccessControlClean is UUPSUpgradeable {
    address public owner;
    address public implementation;

    constructor() {
        owner = msg.sender;
    }

    function _authorizeUpgrade(address newImplementation) internal override {
        require(msg.sender == owner, "not owner");
        implementation = newImplementation;
    }
}
