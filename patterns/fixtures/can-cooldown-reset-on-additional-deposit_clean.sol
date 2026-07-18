// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract StakingClean {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public cooldownEnd;
    uint256 public constant COOLDOWN = 7 days;

    // Clean: require positive amount + caller identity, use weighted max.
    function deposit(address user, uint256 amount) external {
        require(amount > 0, "zero amount");
        require(msg.sender == user, "not owner");
        uint256 proposed = block.timestamp + COOLDOWN;
        if (proposed > cooldownEnd[user]) cooldownEnd[user] = proposed;
        balances[user] += amount;
    }

    function withdraw(uint256 amount) external {
        require(block.timestamp >= cooldownEnd[msg.sender], "cooldown");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
