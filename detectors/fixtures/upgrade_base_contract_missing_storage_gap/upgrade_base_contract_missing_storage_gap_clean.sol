// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: upgradeable base contract reserves a `uint256[N] __gap;` slot range
// so future variables can be appended without shifting child storage.
abstract contract AccessControlUpgradeable {
    mapping(address => bool) internal _admins;
    address internal _root;
    uint256 internal _adminCount;

    uint256[47] private __gap;

    function _grantAdmin(address a) internal {
        _admins[a] = true;
        _adminCount += 1;
    }
}
