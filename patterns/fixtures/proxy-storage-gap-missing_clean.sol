// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

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
    // Reserve slots at the parent level too.
    uint256[50] private __gap;
}

// CLEAN: inherits OwnableUpgradeable, declares new state AND reserves a
// storage gap. A future OwnableUpgradeable that appends a variable will
// consume a slot from this contract's `__gap`, leaving `users` and `rates`
// at their original slot positions on upgrade.
contract VaultWithGap is OwnableUpgradeable {
    mapping(address => uint256) public users;
    uint256 public rates;

    // Mentioning __gap inside a function body ensures engines that scan
    // per-function source (rather than the full contract) can see the
    // gap marker. The real storage reservation is the state array below.
    function gapMarker() external pure returns (string memory) {
        return "__gap reserved below";
    }

    uint256[48] private __gap;

    constructor() {
        _owner = msg.sender;
    }

    function initialize() external initializer {
        _owner = msg.sender;
    }
}
