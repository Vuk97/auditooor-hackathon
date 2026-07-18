// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RoleGatedFunctionRoleNeverGrantedPositiveWrongRole {
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 public constant WRAPPER_ROLE = keccak256("WRAPPER_ROLE");

    mapping(bytes32 => mapping(address => bool)) private _roles;
    address public lastRecipient;

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function withdraw(address recipient) external {
        _checkRole(WRAPPER_ROLE);
        lastRecipient = recipient;
    }

    function _checkRole(bytes32 role) internal view {
        require(_roles[role][msg.sender], "missing role");
    }

    function _grantRole(bytes32 role, address account) internal {
        _roles[role][account] = true;
    }
}
