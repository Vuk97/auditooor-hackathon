// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: execute/join path does not consult the freeze registry, so a
// restricted holder can still execute the fork flow.
contract TokenFreezeBypassExecuteJoinVulnerable {
    mapping(address => bool) public frozen;
    mapping(address => uint256) public balanceOf;

    function executeJoin(address to, uint256 amount) external {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }

    function setFrozen(address a, bool v) external { frozen[a] = v; }
}
