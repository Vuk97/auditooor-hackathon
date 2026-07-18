// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract UpgradeableVaultClean {
    address private _admin;
    address public implementation;
    address public timelockController;
    bool private initialized;

    modifier onlyAdmin() {
        require(msg.sender == _admin, "not admin");
        _;
    }

    function initialize(address initialImplementation, address timelock) public {
        require(!initialized, "initialized");
        require(timelock != address(0), "timelock required");
        initialized = true;
        implementation = initialImplementation;
        timelockController = timelock;
        _admin = timelock;
    }

    function upgradeTo(address newImplementation) external onlyAdmin {
        implementation = newImplementation;
    }
}
