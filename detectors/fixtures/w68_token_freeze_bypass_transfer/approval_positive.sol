// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: approve path does not consult the blocked registry, so a
// restricted holder can still grant spending power.
contract TokenFreezeBypassApprovalVulnerable {
    mapping(address => bool) public blocked;
    mapping(address => mapping(address => uint256)) public allowance;

    function approve(address spender, uint256 amount) external {
        allowance[msg.sender][spender] = amount;
    }

    function setBlocked(address a, bool v) external { blocked[a] = v; }
}
