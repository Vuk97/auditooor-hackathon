// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

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

// CLEAN: explicit version check before touching storage. A stale-version
// call reverts loudly instead of silently no-op'ing the migration.
contract CleanReinit is UUPSUpgradeable {
    address public criticalConfig;

    function reinitV2(address newConfig) external reinitializer(2) {
        require(_getInitializedVersion() == 2, "wrong version");
        criticalConfig = newConfig;
    }
}
