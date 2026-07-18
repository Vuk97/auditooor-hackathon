// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RoleGatedFunctionRoleNeverGrantedCleanInitHelper {
    bytes32 public constant WRAPPER_ROLE = keccak256("WRAPPER_ROLE");

    mapping(bytes32 => mapping(address => bool)) private _roles;
    address public wrapper;
    address public lastRecipient;

    function initialize(address wrapper_) external {
        wrapper = wrapper_;
        _grantWrapperRole(wrapper_);
    }

    function withdraw(address recipient) external {
        _checkRole(WRAPPER_ROLE);
        lastRecipient = recipient;
    }

    function _grantWrapperRole(address account) internal {
        _grantRole(WRAPPER_ROLE, account);
    }

    function _checkRole(bytes32 role) internal view {
        require(_roles[role][msg.sender], "missing role");
    }

    function _grantRole(bytes32 role, address account) internal {
        _roles[role][account] = true;
    }
}
