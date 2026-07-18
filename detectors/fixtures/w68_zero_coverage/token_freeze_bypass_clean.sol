// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: transfer path enforces the freeze registry.
contract TokenFreezeBypassSafe {
    mapping(address => bool) public frozen;
    mapping(address => uint256) public balanceOf;

    function transfer(address to, uint256 amount) external {
        require(!frozen[msg.sender], "sender frozen");
        require(!frozen[to], "recipient frozen");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }

    function setFrozen(address a, bool v) external { frozen[a] = v; }
}
