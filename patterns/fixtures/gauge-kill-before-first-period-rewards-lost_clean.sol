// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRewardToken { function transfer(address to, uint256 amount) external returns (bool); }

contract GaugeKillClean {
    bool public isAlive = true;
    uint256 public pendingRewards;
    address public admin;
    address public treasury;
    IRewardToken public reward;

    // CLEAN: flushes reward balance before flipping isAlive.
    function killGauge() external {
        require(msg.sender == admin, "not admin");
        uint256 bal = pendingRewards;
        pendingRewards = 0;
        if (bal > 0) {
            reward.transfer(treasury, bal);
        }
        isAlive = false;
    }
}
