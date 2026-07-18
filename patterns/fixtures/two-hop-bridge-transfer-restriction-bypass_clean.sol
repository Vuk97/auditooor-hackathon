// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OFTClean {
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public lockUntil;

    function _update(address from, address to) internal view {
        if (from != address(0)) require(block.timestamp >= lockUntil[from], "locked");
        if (to != address(0)) require(block.timestamp >= lockUntil[to], "locked");
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _update(msg.sender, to);
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function send(uint32, address, uint256 amount) external {
        _update(msg.sender, address(0));
        balanceOf[msg.sender] -= amount;
    }

    function _credit(address to, uint256 amount) external {
        _update(address(0), to);
        balanceOf[to] += amount;
    }
}
