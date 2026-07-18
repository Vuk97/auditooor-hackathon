// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Minimal OZ v5 stand-ins so the fixture compiles under Slither.
abstract contract Initializable {
    uint64 private _initializedVersion;
    bool private _initializing;

    modifier reinitializer(uint64 version) {
        require(!_initializing && _initializedVersion < version, "already");
        _initializing = true;
        _initializedVersion = version;
        _;
        _initializing = false;
    }

    function _getInitializedVersion() internal view returns (uint64) {
        return _initializedVersion;
    }
}

abstract contract UUPSUpgradeable is Initializable {}

// VULN: reinitializer-gated migration runs without verifying the current
// initialized-version matches the expected pre-upgrade value. If this
// function is invoked against an instance whose version is already >= 2,
// the modifier no-ops the body and `criticalConfig` stays uninitialized.
contract VulnReinit is UUPSUpgradeable {
    address public criticalConfig;

    function reinitV2(address newConfig) external reinitializer(2) {
        // BUG: no check against _getInitializedVersion() / expected prev version.
        criticalConfig = newConfig;
    }
}
