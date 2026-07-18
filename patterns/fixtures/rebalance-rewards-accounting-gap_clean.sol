// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RebalanceClean {
    uint256 public totalSupply;
    uint256 public rewardPerToken;
    uint256 public lastUpdateTime;
    mapping(address => uint256) public balance;

    function _updateReward() internal {
        lastUpdateTime = block.timestamp;
    }

    function stake(uint256 amount) external {
        _updateReward();
        balance[msg.sender] += amount;
        totalSupply += amount;
    }

    // Detector MUST NOT fire: _updateReward is called before mutating totals.
    function rebalance(uint256 delta) external {
        _updateReward();
        totalSupply += delta;
    }
}
