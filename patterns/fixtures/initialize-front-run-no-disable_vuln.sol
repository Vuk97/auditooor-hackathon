// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// initialize-front-run-no-disable detector. DO NOT DEPLOY.
///
/// Minimal stand-ins for the OZ upgradeable primitives so the fixture
/// compiles under slither without pulling in node_modules.
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

/// VULN: inherits UUPSUpgradeable, exposes `initialize(address _owner)`
/// with NO `initializer` / `reinitializer` / `onlyProxy` modifier, writes
/// the `owner` storage slot, and the constructor does not call
/// `_disableInitializers()`. Any attacker watching the mempool can call
/// `initialize(attacker)` on the implementation at block N+1 and become
/// owner, then `upgradeTo(malicious)` on a UUPS proxy.
contract VulnUpgradeable is UUPSUpgradeable {
    address public owner;
    address public admin;

    constructor() {
        // BUG: missing _disableInitializers();
    }

    // BUG: no `initializer` modifier, and writes a privileged role.
    function initialize(address _owner, address _admin) external {
        owner = _owner;
        admin = _admin;
    }
}
