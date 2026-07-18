// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: ragequit path enforces the veto registry.
contract TokenFreezeBypassRagequitSafe {
    mapping(address => bool) public vetoed;
    mapping(address => uint256) public shares;

    function ragequit(uint256 amount) external {
        require(!vetoed[msg.sender], "sender vetoed");
        shares[msg.sender] -= amount;
    }

    function setVetoed(address a, bool v) external { vetoed[a] = v; }
}
