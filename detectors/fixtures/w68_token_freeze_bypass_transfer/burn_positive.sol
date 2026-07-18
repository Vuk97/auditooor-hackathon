// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: burn path does not consult the veto registry, so a
// restricted holder can still burn tokens.
contract TokenFreezeBypassBurnVulnerable {
    mapping(address => bool) public vetoed;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply = 1_000_000;

    function burn(uint256 amount) external {
        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;
    }

    function setVetoed(address a, bool v) external { vetoed[a] = v; }
}
