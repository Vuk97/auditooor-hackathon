// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: burn symmetrically decrements totalSupply.
contract MintBurnAsymmetrySafe {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
    }

    function burn(address from, uint256 amount) external {
        balanceOf[from] -= amount;
        totalSupply -= amount;
    }
}
