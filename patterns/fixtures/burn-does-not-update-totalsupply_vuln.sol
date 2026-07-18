// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BurnSupplyVuln {
    mapping(address => uint256) public balance;
    uint256 public totalSupply;

    function mint(address to, uint256 amount) external {
        balance[to] += amount;
        totalSupply += amount;
    }

    // Detector MUST fire: totalSupply is not decremented on burn.
    function burn(uint256 amount) external {
        balance[msg.sender] -= amount;
    }
}
