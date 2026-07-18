// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RoleGatedFunctionRoleNeverGrantedPositive {
    bytes32 public constant WRAPPER_ROLE = keccak256("WRAPPER_ROLE");

    mapping(bytes32 => mapping(address => bool)) private _roles;
    address public lastRecipient;

    function withdraw(address recipient) external {
        _checkRole(WRAPPER_ROLE);
        lastRecipient = recipient;
    }

    function _checkRole(bytes32 role) internal view {
        require(_roles[role][msg.sender], "missing role");
    }
}
