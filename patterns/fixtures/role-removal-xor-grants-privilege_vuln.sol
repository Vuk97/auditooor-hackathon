// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RoleBitmapVuln {
    mapping(address => uint256) public roles;
    uint256 public constant ADMIN_FLAG = 1 << 0;

    // VULN: XOR toggles; if flag absent, this grants it
    function removeRole(address user, uint256 flag) external {
        roles[user] ^= flag;
    }

    function hasRole(address user, uint256 flag) external view returns (bool) {
        return (roles[user] & flag) != 0;
    }
}
