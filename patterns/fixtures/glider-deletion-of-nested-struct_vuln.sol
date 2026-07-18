// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PositionsVuln {
    struct Position {
        uint256 amount;
        mapping(address => uint256) rewardsOwed;
    }
    mapping(uint256 => Position) public positions;

    function openPosition(uint256 id, uint256 amount) external {
        positions[id].amount = amount;
    }

    function accrueReward(uint256 id, address user, uint256 r) external {
        positions[id].rewardsOwed[user] += r;
    }

    // VULN: delete leaves rewardsOwed stale
    function closePosition(uint256 id) external {
        delete positions[id];
    }
}
