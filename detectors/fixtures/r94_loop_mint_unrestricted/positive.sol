// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract MintUnrestrictedPositive {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}
