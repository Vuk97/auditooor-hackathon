// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract MintUnrestrictedClean {
    address public owner;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}
