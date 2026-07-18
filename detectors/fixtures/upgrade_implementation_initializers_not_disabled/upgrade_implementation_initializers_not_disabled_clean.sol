// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: the constructor calls `_disableInitializers()`, locking the
// implementation so `initialize()` can never be called on it directly.
contract VaultImplClean {
    address public owner;
    bool private _initializedFlag;

    modifier initializer() {
        require(!_initializedFlag, "already init");
        _initializedFlag = true;
        _;
    }

    function _disableInitializers() internal {
        _initializedFlag = true;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(address _owner) external initializer {
        owner = _owner;
    }
}
