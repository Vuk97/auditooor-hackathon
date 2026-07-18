// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RebalanceVuln {
    uint256 public totalSupply;
    uint256 public rewardPerToken;
    uint256 public lastUpdateTime;
    mapping(address => uint256) public balance;

    function _accrue() internal {
        // would compute rewardPerToken += dt * rate / totalSupply
        lastUpdateTime = block.timestamp;
    }

    function stake(uint256 amount) external {
        _accrue();
        balance[msg.sender] += amount;
        totalSupply += amount;
    }

    // Detector MUST fire: rebalance mutates totalSupply without calling _accrue / updateReward first.
    function rebalance(uint256 delta) external {
        totalSupply += delta;
    }
}
