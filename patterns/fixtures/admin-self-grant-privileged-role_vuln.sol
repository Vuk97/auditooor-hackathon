// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AccessControlLike {
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    mapping(bytes32 => mapping(address => bool)) internal _roles;
    function _grantRole(bytes32 r, address a) internal { _roles[r][a] = true; }
}

contract PayoutVaultVuln is AccessControlLike {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    function initialize(address owner, address operator) external {
        // VULN: owner gets DEFAULT_ADMIN_ROLE + separate OPERATOR_ROLE granted,
        // but OPERATOR_ROLE admin is still DEFAULT_ADMIN_ROLE, so owner can
        // self-grant OPERATOR_ROLE later.
        _grantRole(DEFAULT_ADMIN_ROLE, owner);
        _grantRole(OPERATOR_ROLE, operator);
    }
}
