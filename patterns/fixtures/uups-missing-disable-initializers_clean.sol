// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract Initializable {
    bool private _initialized;
    bool private _initializing;
    modifier initializer() {
        require(!_initialized, "already");
        _initialized = true;
        _;
    }
    function _disableInitializers() internal virtual {
        _initialized = true;
    }
}

abstract contract UUPSUpgradeable is Initializable {}

// CLEAN: constructor calls _disableInitializers() so the implementation
// itself cannot be initialized. Only the proxy (with its own storage) can.
contract CleanUUPS is UUPSUpgradeable {
    address public owner;

    constructor() {
        _disableInitializers();
    }

    function initialize(address _owner) external initializer {
        owner = _owner;
    }
}
