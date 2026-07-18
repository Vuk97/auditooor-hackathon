// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. Same upgradeable shape
/// as the vuln fixture, but (a) the `initializer` modifier guards
/// `initialize()`, and (b) the constructor calls `_disableInitializers()`
/// so the implementation itself cannot be initialized.
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

// CLEAN: constructor locks the implementation, and initialize() is
// protected by the `initializer` modifier. Either layer alone would be
// enough to suppress the detector; real-world code should keep both.
contract CleanUpgradeable is UUPSUpgradeable {
    address public owner;
    address public admin;

    constructor() {
        _disableInitializers();
    }

    function initialize(address _owner, address _admin) external initializer {
        owner = _owner;
        admin = _admin;
    }
}
