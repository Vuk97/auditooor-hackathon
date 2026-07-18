// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: upgradeable implementation with an `initializer` function but
// a constructor that does NOT call `_disableInitializers()`. Anyone can call
// `initialize()` on the deployed implementation and seize ownership.
contract VaultImplVulnerable {
    address public owner;
    bool private _initializedFlag;

    modifier initializer() {
        require(!_initializedFlag, "already init");
        _initializedFlag = true;
        _;
    }

    constructor() {
        // implementation lock call is absent here
    }

    function initialize(address _owner) external initializer {
        owner = _owner;
    }
}
