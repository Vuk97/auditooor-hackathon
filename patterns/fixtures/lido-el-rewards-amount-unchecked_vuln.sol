// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IELVault { function withdrawRewards(uint256 amount) external returns (uint256); }

contract ELRewardsVuln {
    IELVault public elVault;
    uint256 public totalRewards;

    // VULN: credits the reported amount with no balance-delta cross-check
    function receiveELRewards(uint256 amount) external {
        uint256 received = elVault.withdrawRewards(amount);
        totalRewards += received;
    }
}
