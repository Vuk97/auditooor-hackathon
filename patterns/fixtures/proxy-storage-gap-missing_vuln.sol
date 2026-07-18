// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal OZ-upgradeable stand-ins so this fixture compiles without node_modules.
abstract contract Initializable {
    bool private _initialized;
    modifier initializer() {
        require(!_initialized, "already");
        _initialized = true;
        _;
    }
}

abstract contract OwnableUpgradeable is Initializable {
    address internal _owner;
}

// VULN: inherits OwnableUpgradeable, declares new state (`users`, `rates`),
// but provides NO `__gap` / `_gap` / `storage_slotN` array. A future version
// of OwnableUpgradeable that adds a new state variable will shift these
// slots and corrupt live user data on upgrade.
contract VaultNoGap is OwnableUpgradeable {
    mapping(address => uint256) public users;
    uint256 public rates;

    constructor() {
        _owner = msg.sender;
    }

    function initialize() external initializer {
        _owner = msg.sender;
    }
}
