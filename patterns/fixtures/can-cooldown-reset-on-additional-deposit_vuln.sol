// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract StakingVuln {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public cooldownEnd;
    uint256 public constant COOLDOWN = 7 days;

    // BUG: any third party can call with amount=0 to reset victim's cooldown.
    function deposit(address user, uint256 amount) external {
        balances[user] += amount;
        cooldownEnd[user] = block.timestamp + COOLDOWN; // unconditional reset
    }

    function withdraw(uint256 amount) external {
        require(block.timestamp >= cooldownEnd[msg.sender], "cooldown");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
