// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract Ownable {
    address internal _owner;
    constructor() { _owner = msg.sender; }
    function owner() public view returns (address) { return _owner; }
    function _transferOwnership(address n) internal virtual { _owner = n; }
    function transferOwnership(address n) external virtual { _transferOwnership(n); }
}

abstract contract AccessControl {
    mapping(bytes32 => mapping(address => bool)) internal _roles;
    function hasRole(bytes32 role, address u) public view returns (bool) { return _roles[role][u]; }
    function _grantRole(bytes32 role, address u) internal { _roles[role][u] = true; }
    function _revokeRole(bytes32 role, address u) internal { _roles[role][u] = false; }
}

contract OwnableOverrideRoleCheckMismatchClean is Ownable, AccessControl {
    bytes32 constant OWNER_ROLE = keccak256("OWNER_ROLE");
    constructor() { _grantRole(OWNER_ROLE, msg.sender); }

    modifier onlyOwnerRole() { require(hasRole(OWNER_ROLE, msg.sender), "not owner role"); _; }

    function sensitive() external onlyOwnerRole {}

    function _transferOwnership(address n) internal override {
        _revokeRole(OWNER_ROLE, _owner);
        _grantRole(OWNER_ROLE, n);
        _owner = n;
    }
}
