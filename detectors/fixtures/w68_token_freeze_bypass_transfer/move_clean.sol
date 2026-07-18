// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: move path enforces the blocked registry.
contract TokenFreezeBypassMoveSafe {
    mapping(address => bool) public blocked;
    mapping(address => uint256) public balanceOf;

    function move(address to, uint256 amount) external {
        require(!blocked[msg.sender], "sender blocked");
        require(!blocked[to], "recipient blocked");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }

    function setBlocked(address a, bool v) external { blocked[a] = v; }
}
