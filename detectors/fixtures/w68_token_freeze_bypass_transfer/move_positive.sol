// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: move path does not consult the blocked registry, so a
// restricted holder can still move tokens.
contract TokenFreezeBypassMoveVulnerable {
    mapping(address => bool) public blocked;
    mapping(address => uint256) public balanceOf;

    function move(address to, uint256 amount) external {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }

    function setBlocked(address a, bool v) external { blocked[a] = v; }
}
