// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// Companion fixed version of ToyVulnerable. The withdraw path now
// subtracts the full amount, which means the campaign-generated Forge
// replay should change behavior between this version and the
// vulnerable one — the operator-driven verified|rejected promotion
// gate. (No trigger-word comments per foot-gun #2 hygiene.)

contract ToyVulnerable {
    mapping(address => uint256) public deposits;
    uint256 public sumDeposits;
    uint256 public sumWithdraws;

    function deposit(uint256 amount) external {
        deposits[msg.sender] += amount;
        sumDeposits += amount;
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "insufficient");
        deposits[msg.sender] -= amount;
        sumWithdraws += amount;
    }
}
