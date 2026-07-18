// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RestrictedTokenActionClean {
    mapping(address => bool) public frozen;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function transfer(address to, uint256 amount) external {
        require(!frozen[msg.sender], "sender frozen");
        require(!frozen[to], "recipient frozen");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external {
        require(!frozen[msg.sender], "owner frozen");
        require(!frozen[spender], "spender frozen");
        allowance[msg.sender][spender] = amount;
    }
}
