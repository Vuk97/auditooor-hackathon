// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VoterPokeVuln {
    mapping(address => uint256) public snapshot;
    mapping(address => uint256) public rewardPerVote;
    function poke(address user) external {
        snapshot[user] = block.number;
        rewardPerVote[user] = 0;
    }
}
