// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UStbClean {
    mapping(address => bool) public whitelist;
    mapping(address => bool) public blacklist;
    mapping(address => uint256) public balances;

    function burn(uint256 amount) external {
        require(whitelist[msg.sender], "not whitelisted");
        require(!blacklist[msg.sender], "blacklisted");
        balances[msg.sender] -= amount;
    }
}
