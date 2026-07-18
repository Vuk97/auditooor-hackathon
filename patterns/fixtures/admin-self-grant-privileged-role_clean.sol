// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AccessControlLike {
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    mapping(bytes32 => mapping(address => bool)) internal _roles;
    mapping(bytes32 => bytes32) internal _roleAdmin;
    function _grantRole(bytes32 r, address a) internal { _roles[r][a] = true; }
    function setRoleAdmin(bytes32 r, bytes32 admin) internal { _roleAdmin[r] = admin; }
}

contract PayoutVaultClean is AccessControlLike {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant OWNER_ROLE = keccak256("OWNER_ROLE");

    function initialize(address owner, address operator) external {
        _grantRole(DEFAULT_ADMIN_ROLE, owner);
        _grantRole(OWNER_ROLE, owner);
        _grantRole(OPERATOR_ROLE, operator);
        // CLEAN: separates OPERATOR_ROLE's admin from DEFAULT_ADMIN_ROLE
        setRoleAdmin(OPERATOR_ROLE, OWNER_ROLE);
    }
}
