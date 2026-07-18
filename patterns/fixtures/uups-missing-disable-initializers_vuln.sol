// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal stand-ins for OZ upgradeable primitives so the fixture compiles
// under slither without pulling in node_modules.
abstract contract Initializable {
    bool private _initialized;
    modifier initializer() {
        require(!_initialized, "already");
        _initialized = true;
        _;
    }
    function _disableInitializers() internal virtual {}
}

abstract contract UUPSUpgradeable is Initializable {}

// VULN: inherits UUPSUpgradeable, exposes initialize(), but the constructor
// does NOT call _disableInitializers(). Implementation can be initialized
// by any EOA front-running the proxy deployment.
contract VulnUUPS is UUPSUpgradeable {
    address public owner;

    constructor() {
        // BUG: implementation constructor does not lock initializers.
    }

    function initialize(address _owner) external initializer {
        owner = _owner;
    }
}
