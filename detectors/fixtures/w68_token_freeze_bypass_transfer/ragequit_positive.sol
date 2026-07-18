// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: ragequit path does not consult the veto registry, so a
// restricted holder can still exit with tokens.
contract TokenFreezeBypassRagequitVulnerable {
    mapping(address => bool) public vetoed;
    mapping(address => uint256) public shares;

    function ragequit(uint256 amount) external {
        shares[msg.sender] -= amount;
    }

    function setVetoed(address a, bool v) external { vetoed[a] = v; }
}
