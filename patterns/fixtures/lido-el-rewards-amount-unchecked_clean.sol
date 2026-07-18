// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IELVault { function withdrawRewards(uint256 amount) external returns (uint256); }

contract ELRewardsClean {
    IELVault public elVault;
    uint256 public totalRewards;

    // CLEAN: measures actual balance delta to validate reported amount
    function receiveELRewards(uint256 amount) external {
        uint256 balanceBefore = address(this).balance;
        uint256 received = elVault.withdrawRewards(amount);
        uint256 balanceAfter = address(this).balance;
        require(balanceAfter - balanceBefore == received, "EL amount mismatch");
        totalRewards += received;
    }
}
