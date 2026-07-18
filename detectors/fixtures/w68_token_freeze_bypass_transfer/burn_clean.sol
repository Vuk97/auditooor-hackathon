// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: burn path enforces the veto registry.
contract TokenFreezeBypassBurnSafe {
    mapping(address => bool) public vetoed;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply = 1_000_000;

    function burn(uint256 amount) external {
        require(!vetoed[msg.sender], "sender vetoed");
        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;
    }

    function setVetoed(address a, bool v) external { vetoed[a] = v; }
}
