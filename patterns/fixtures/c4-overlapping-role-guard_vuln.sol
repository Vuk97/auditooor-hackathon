// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UStbVuln {
    mapping(address => bool) public whitelist;
    mapping(address => bool) public blacklist;
    mapping(address => uint256) public balances;

    // VULN: checks whitelist but forgets blacklist
    function burn(uint256 amount) external {
        require(whitelist[msg.sender], "not whitelisted");
        balances[msg.sender] -= amount;
    }
}
