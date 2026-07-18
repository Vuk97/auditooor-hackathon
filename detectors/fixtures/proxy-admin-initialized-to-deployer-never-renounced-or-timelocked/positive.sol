// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract UpgradeableVaultPositive {
    address private _admin;
    address public implementation;
    bool private initialized;

    modifier onlyAdmin() {
        require(msg.sender == _admin, "not admin");
        _;
    }

    function initialize(address initialImplementation) public {
        require(!initialized, "initialized");
        initialized = true;
        implementation = initialImplementation;
        _admin = msg.sender;
    }

    function upgradeTo(address newImplementation) external onlyAdmin {
        implementation = newImplementation;
    }
}
