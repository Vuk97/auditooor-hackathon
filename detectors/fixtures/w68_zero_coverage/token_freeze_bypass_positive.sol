// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: transfer path does not consult the freeze registry, so a
// frozen account can still move tokens (token freeze bypassed).
contract TokenFreezeBypassVulnerable {
    mapping(address => bool) public frozen;
    mapping(address => uint256) public balanceOf;

    function transfer(address to, uint256 amount) external {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }

    function setFrozen(address a, bool v) external { frozen[a] = v; }
}
