// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PositionsClean {
    // CLEAN: flat top-level mapping; no nested mapping inside struct
    mapping(uint256 => uint256) public positionAmount;
    mapping(uint256 => mapping(address => uint256)) public rewardsOwed;
    mapping(uint256 => address[]) public accruedUsers;

    function openPosition(uint256 id, uint256 amount) external {
        positionAmount[id] = amount;
    }

    function accrueReward(uint256 id, address user, uint256 r) external {
        if (rewardsOwed[id][user] == 0) accruedUsers[id].push(user);
        rewardsOwed[id][user] += r;
    }

    function closePosition(uint256 id) external {
        address[] storage users = accruedUsers[id];
        for (uint256 i = 0; i < users.length; i++) {
            delete rewardsOwed[id][users[i]];
        }
        delete accruedUsers[id];
        delete positionAmount[id];
    }
}
