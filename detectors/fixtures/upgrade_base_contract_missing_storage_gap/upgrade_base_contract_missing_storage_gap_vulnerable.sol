// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: upgradeable base contract declares mutable storage but
// reserves no `__gap`. Appending a var in a later version corrupts every
// inheriting child's storage layout.
abstract contract AccessControlUpgradeable {
    mapping(address => bool) internal _admins;
    address internal _root;
    uint256 internal _adminCount;

    function _grantAdmin(address a) internal {
        _admins[a] = true;
        _adminCount += 1;
    }
}
